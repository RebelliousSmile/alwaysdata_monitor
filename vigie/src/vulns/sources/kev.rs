//! CISA KEV (issue #18) : catalogue JSON des failles exploitées, lu depuis
//! le miroir officiel `cisagov/kev-data` puis, en secours, depuis
//! cisa.gov (cisa.gov d'abord avec `--accept-shrink`). Mesures, schéma et
//! licence : `docs/failles.md`, « CISA KEV ».
//!
//! Le catalogue (1,8 Mo) est lu et contrôlé **en mémoire avant toute
//! poussée**, hôte par hôte, dans cet ordre : seuil d'écart
//! (`Limits::max_dropped_ratio`), régression de `dateReleased` par rapport
//! au jeu actif (comparée à la seconde), garde contre le rétrécissement de
//! F2 ([`shrink_refused`]). Le premier jeu accepté est poussé ; sinon
//! l'issue la plus sévère : échec (dernière erreur), puis rétrécissement
//! refusé, puis inchangé (périmé). Un 304 ou une même empreinte sur l'un
//! des hôtes : inchangé.

use std::collections::HashSet;
use std::time::Duration;

use jiff::Timestamp;
use jiff::civil::Date;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::api::log_text::LogText;
use crate::vulns::advisory::{Reason, Tally};
use crate::vulns::enrich_store::{DatasetHeader, KevRow};
use crate::vulns::exploit::{Cve, KevFact};
use crate::vulns::sources::Redistribution;
use crate::vulns::sync::download::{Download, Fetched, Received, Request};
use crate::vulns::sync::engine::{shrink_message, shrink_refused};
use crate::vulns::sync::enrichment::{EnrichSink, EnrichmentSource};
use crate::vulns::sync::{Dumped, FetchOutcome, Limits, SourceMeta, SyncError};

/// Miroir officiel de CISA, essayé d'abord.
pub const MIRROR_URL: &str =
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
/// URL canonique, en secours.
pub const CISA_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// Origines admises, redirections comprises.
pub const KEV_ORIGINS: &[(&str, u16)] =
    &[("raw.githubusercontent.com", 443), ("www.cisa.gov", 443)];
/// Version du lecteur KEV : à incrémenter à chaque changement de lecture ou
/// de validation qui change ce qui est stocké.
pub const LOADER_VERSION: u32 = 1;
/// Document de 16 Mio au plus (mesure : 1 792 713 o).
pub const MAX_DOCUMENT: u64 = 16 * 1024 * 1024;
/// Entrées au plus (mesure : 1 748).
pub const MAX_ENTRIES: u64 = 20_000;
/// Âge du catalogue (maintenant − `dateReleased`) au-delà duquel `vigie
/// vulns sources` avertit : CISA publie les jours ouvrés.
pub const MAX_CATALOG_AGE: i64 = 14 * 86_400;
/// `catalogVersion` : 32 caractères au plus.
const MAX_VERSION_CHARS: usize = 32;
/// `vulnerabilityName` gardé : 200 caractères au plus.
const MAX_NAME_CHARS: usize = 200;

/// Plafonds de KEV : document entier en mémoire.
pub fn limits() -> Limits {
    Limits {
        compressed: MAX_DOCUMENT,
        unpacked: MAX_DOCUMENT,
        entries: MAX_ENTRIES,
        entry: MAX_DOCUMENT,
        central_directory: 0,
        duration: Duration::from_secs(10 * 60),
        max_dropped_ratio: 0.01,
    }
}

/// La source KEV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KevSource;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCatalog {
    catalog_version: Option<String>,
    date_released: Option<String>,
    count: Option<serde_json::Value>,
    vulnerabilities: Option<Vec<RawEntry>>,
}

/// Champs de la liste de l'issue, lus en texte puis validés ; les autres
/// champs requis du schéma ne sont que vérifiés présents, les champs
/// inconnus ignorés.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve_id: Option<String>,
    date_added: Option<String>,
    due_date: Option<String>,
    known_ransomware_campaign_use: Option<String>,
    vulnerability_name: Option<String>,
    vendor_project: Option<IgnoredAny>,
    product: Option<IgnoredAny>,
    short_description: Option<IgnoredAny>,
    required_action: Option<IgnoredAny>,
}

/// Catalogue lu et validé, pas encore poussé.
#[derive(Debug)]
pub struct Catalog {
    pub header: DatasetHeader,
    pub rows: Vec<KevRow>,
    /// Entrées lues (dénominateur du taux d'écart).
    pub entries: u64,
    pub tally: Tally,
}

/// Date `format: date` du schéma : AAAA-MM-JJ exactement.
fn date(raw: &str) -> Option<Date> {
    (raw.len() == 10)
        .then(|| raw.parse::<Date>().ok())
        .flatten()
}

/// Lit un catalogue KEV ; erreur si l'en-tête est illisible ou si le
/// format a changé (JSON, entrées absentes ou trop nombreuses).
pub fn parse(bytes: &[u8]) -> Result<Catalog, SyncError> {
    let raw: RawCatalog = serde_json::from_slice(bytes)
        .map_err(|e| SyncError::Format(format!("JSON KEV illisible ({:?})", e.classify())))?;
    let version = raw
        .catalog_version
        .filter(|v| {
            (1..=MAX_VERSION_CHARS).contains(&v.chars().count())
                && v.chars().all(|c| c.is_ascii_graphic())
        })
        .ok_or_else(|| SyncError::Format("catalogVersion absent ou invalide".into()))?;
    let released: Timestamp = raw
        .date_released
        .as_deref()
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| SyncError::Format("dateReleased absent ou invalide".into()))?;
    let entries = raw
        .vulnerabilities
        .ok_or_else(|| SyncError::Format("vulnerabilities absent".into()))?;
    if entries.len() as u64 > MAX_ENTRIES {
        return Err(SyncError::TooLarge {
            what: "entrées KEV",
        });
    }
    let mut tally = Tally::default();
    if raw.count.as_ref().and_then(serde_json::Value::as_u64) != Some(entries.len() as u64) {
        tally.add(Reason::CountMismatch);
    }
    let mut seen = HashSet::new();
    let mut rows = Vec::with_capacity(entries.len());
    for e in &entries {
        let Some(cve) = e.cve_id.as_deref() else {
            tally.add(Reason::MissingField);
            continue;
        };
        let Some(cve) = Cve::parse(cve) else {
            tally.add(Reason::BadCve);
            continue;
        };
        let (Some(added), Some(due), Some(name)) = (
            e.date_added.as_deref(),
            e.due_date.as_deref(),
            e.vulnerability_name.as_deref(),
        ) else {
            tally.add(Reason::MissingField);
            continue;
        };
        if e.vendor_project.is_none()
            || e.product.is_none()
            || e.short_description.is_none()
            || e.required_action.is_none()
        {
            tally.add(Reason::MissingField);
            continue;
        }
        let (Some(added), Some(due)) = (date(added), date(due)) else {
            tally.add(Reason::BadDate);
            continue;
        };
        let known_ransomware = match e.known_ransomware_campaign_use.as_deref() {
            Some("Known") => true,
            None | Some("Unknown") => false,
            Some(_) => {
                tally.add(Reason::UnknownRansomware);
                false
            }
        };
        if !seen.insert(cve.clone()) {
            tally.add(Reason::Duplicate);
            continue;
        }
        rows.push(KevRow {
            cve,
            fact: KevFact {
                date_added: added,
                due_date: due,
                known_ransomware,
                name: LogText::new(name, MAX_NAME_CHARS).into(),
            },
        });
    }
    Ok(Catalog {
        header: DatasetHeader { version, released },
        rows,
        entries: entries.len() as u64,
        tally,
    })
}

/// Issue d'un hôte.
enum Attempt {
    /// 304 ou même empreinte que l'actif.
    Unchanged {
        not_modified: bool,
        validators: Option<Received>,
    },
    /// Jeu accepté, prêt à pousser.
    Accepted {
        catalog: Catalog,
        sha256: String,
        validators: Received,
        bytes: u64,
    },
    /// `dateReleased` antérieur à l'actif.
    Stale,
    /// Garde contre le rétrécissement.
    Shrunk(String),
}

impl KevSource {
    fn attempt(
        &self,
        dl: &mut Download,
        url: &url::Url,
        sink: &dyn EnrichSink,
    ) -> Result<Attempt, SyncError> {
        let dump = match dl.get_to_file(&Request::get(url.clone()))? {
            Fetched::NotModified => {
                return Ok(Attempt::Unchanged {
                    not_modified: true,
                    validators: None,
                });
            }
            Fetched::SameDigest { validators, .. } => {
                return Ok(Attempt::Unchanged {
                    not_modified: false,
                    validators: Some(validators),
                });
            }
            Fetched::Dump(dump) => dump,
        };
        let bytes = std::fs::read(&dump.path).map_err(|e| SyncError::io("lecture de KEV", &e))?;
        let _ = std::fs::remove_file(&dump.path);
        let catalog = parse(&bytes)?;
        // 1. Seuil d'écart de F2.
        let dropped = catalog.tally.dropped();
        let max = dl.limits().max_dropped_ratio;
        if catalog.entries > 0 && dropped as f64 / catalog.entries as f64 > max {
            return Err(SyncError::Format(format!(
                "{dropped} entrées KEV écartées sur {}, au-delà de {:.2} %",
                catalog.entries,
                max * 100.0
            )));
        }
        let accept = sink.accept_shrink();
        // 2. Régression de dateReleased, à la seconde.
        if !accept
            && let Some(active) = sink.active()
            && catalog.header.released.as_second() < active.released.as_second()
        {
            return Ok(Attempt::Stale);
        }
        // 3. Garde contre le rétrécissement de F2.
        let retained = catalog.rows.len() as u64;
        if shrink_refused(retained, sink.recent_entries(), accept) {
            return Ok(Attempt::Shrunk(shrink_message(
                self.id(),
                retained,
                sink.recent_entries(),
            )));
        }
        Ok(Attempt::Accepted {
            catalog,
            sha256: dump.sha256,
            validators: dump.validators,
            bytes: dump.bytes,
        })
    }
}

impl EnrichmentSource for KevSource {
    fn id(&self) -> &'static str {
        "kev"
    }

    fn meta(&self) -> SourceMeta {
        SourceMeta {
            url: MIRROR_URL,
            origins: KEV_ORIGINS,
            license: "CC0-1.0",
            attribution: "CISA KEV (Known Exploited Vulnerabilities Catalog), CC0 1.0",
            limits: limits(),
            min_interval: Duration::ZERO,
            loader_version: LOADER_VERSION,
            redistribution: Redistribution::Free,
            raw_content_encodings: &[],
        }
    }

    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn EnrichSink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        // Geste explicite de l'exploitant : la source canonique d'abord.
        let order = if sink.accept_shrink() {
            [CISA_URL, MIRROR_URL]
        } else {
            [MIRROR_URL, CISA_URL]
        };
        if sink.accept_shrink() {
            log::warn!("kev : --accept-shrink : cisa.gov demandé en premier");
        }
        let mut error: Option<SyncError> = None;
        let mut shrunk: Option<String> = None;
        let mut stale = false;
        for raw in order {
            let url = dl.endpoint(raw)?;
            match self.attempt(dl, &url, sink) {
                Ok(Attempt::Unchanged {
                    not_modified,
                    validators,
                }) => {
                    return Ok(FetchOutcome::Unchanged {
                        not_modified,
                        validators,
                        stale: false,
                        served: Some(url.to_string()),
                    });
                }
                Ok(Attempt::Accepted {
                    catalog,
                    sha256,
                    validators,
                    bytes,
                }) => {
                    tally.merge(&catalog.tally);
                    sink.set_header(catalog.header);
                    for row in catalog.rows {
                        sink.push_kev(row)?;
                    }
                    return Ok(FetchOutcome::Loaded(Dumped {
                        sha256,
                        validators,
                        bytes,
                        unpacked_bytes: bytes,
                        entries: catalog.entries,
                        revision: None,
                        served: Some(url.to_string()),
                    }));
                }
                Ok(Attempt::Stale) => {
                    log::warn!("kev : {url} sert un catalogue plus ancien que l'actif");
                    stale = true;
                }
                Ok(Attempt::Shrunk(msg)) => {
                    log::warn!("kev : {url} : {msg}");
                    shrunk = Some(msg);
                }
                // Base injoignable ou bail perdu : inutile d'essayer l'autre
                // hôte.
                Err(e @ (SyncError::LeaseLost | SyncError::Store(_))) => return Err(e),
                Err(e) => {
                    log::warn!("kev : {url} : {e}");
                    error = Some(e);
                }
            }
        }
        if let Some(e) = error {
            return Err(e);
        }
        if let Some(msg) = shrunk {
            return Ok(FetchOutcome::RefusedShrink(msg));
        }
        debug_assert!(stale);
        Ok(FetchOutcome::Unchanged {
            not_modified: false,
            validators: None,
            stale: true,
            served: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cve: &str) -> String {
        format!(
            r#"{{"cveID":"{cve}","vendorProject":"Exemple","product":"Produit","vulnerabilityName":"Faille fictive","dateAdded":"2099-01-10","shortDescription":"Texte fictif.","requiredAction":"Action fictive.","dueDate":"2099-01-31","knownRansomwareCampaignUse":"Unknown","notes":""}}"#
        )
    }

    #[test]
    fn a_minimal_catalog_is_read() {
        let doc = format!(
            r#"{{"title":"t","catalogVersion":"2099.01.15","dateReleased":"2099-01-15T17:15:48.8752Z","count":1,"vulnerabilities":[{}]}}"#,
            entry("CVE-2099-90001")
        );
        let c = parse(doc.as_bytes()).unwrap();
        assert_eq!(c.rows.len(), 1);
        assert_eq!(c.header.version, "2099.01.15");
        assert_eq!(c.tally, Tally::default());
    }

    #[test]
    fn a_broken_header_fails() {
        for doc in [
            r#"{"dateReleased":"2099-01-15T00:00:00Z","count":0,"vulnerabilities":[]}"#,
            r#"{"catalogVersion":"v","dateReleased":"hier","count":0,"vulnerabilities":[]}"#,
            r#"{"catalogVersion":"v","dateReleased":"2099-01-15T00:00:00Z","count":0}"#,
            r#"{"catalogVersion":"v","#,
        ] {
            assert!(
                matches!(parse(doc.as_bytes()), Err(SyncError::Format(_))),
                "{doc}"
            );
        }
    }
}
