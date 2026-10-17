//! Construction de l'inventaire de `vigie-inventory` (issue #20) : entrées des
//! lockfiles → composants de la liste blanche de F5, enveloppe `source: ci`,
//! puis revalidation par [`bom::parse`] ([`validate_own`]) : l'outil ne peut
//! pas émettre un document que le veilleur refuserait.
//!
//! - purl par [`Purl::new`] de F1 ; version passée par la grammaire commune
//!   (hors grammaire ou plus de 128 caractères : version vide, purl sans `@`,
//!   jamais tronquée) ; nom refusé : composant écarté et compté (`skipped`) ;
//! - `--cms wordpress` : `wpackagist-plugin|theme/<slug>` →
//!   `pkg:wordpress/plugin|theme/<slug>` ; sans l'option, ils restent
//!   `pkg:composer`, comme `prestashop-module` toujours ;
//! - doublons : `pkg:wordpress` un par purl sans version, sinon un par
//!   (purl complet, `vigie:path`) ;
//! - ordre global : tous les `required` de tous les lockfiles (dans l'ordre
//!   reçu, et l'ordre du fichier dans chacun), puis tous les `dev` ; la
//!   troncature (2 000 composants, puis 524 288 octets d'enveloppe) retire
//!   depuis la fin : tout le développement avant le moindre `required` ;
//! - `complete` faux dès qu'un composant est écarté, hors registre, omis
//!   (`--omit-dev`) ou tronqué.

use std::collections::BTreeSet;
use std::fmt;

use super::bom::{
    self, Bom, Envelope, MetaComponent, Metadata, PROPERTY_PATH, PROPERTY_SCOPE, Property,
    RawComponent,
};
use super::lockfile::{Entry, Parsed};
use super::{MAX_COMPONENTS, MAX_INVENTORY_BYTES, MAX_SKIPPED, Scope, Source, TOOL_VERSION};
use crate::config::SiteKind;
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::version::in_grammar;

/// Version de CycloneDX émise.
pub const SPEC_VERSION: &str = "1.7";
/// `metadata.component.name` d'un `sbom` sans `--site`.
pub const DEFAULT_NAME: &str = "projet";

/// CMS explicite du projet (`--cms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cms {
    Wordpress,
}

impl Cms {
    /// CMS du site dont le veilleur appliquera la matrice des écosystèmes.
    pub fn site_kind(cms: Option<Self>) -> SiteKind {
        match cms {
            Some(Self::Wordpress) => SiteKind::Wordpress,
            None => SiteKind::Generic,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    pub cms: Option<Cms>,
    pub omit_dev: bool,
}

/// Lockfile lu, et son `vigie:path` (relatif au projet, séparateur `/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    pub path: String,
    pub parsed: Parsed,
}

/// Ce que la construction a fait, en nombres : pour les messages de l'outil,
/// jamais un nom de composant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    pub lockfiles: usize,
    pub components: usize,
    /// Membres du projet : ni émis, ni comptés.
    pub ignored: usize,
    /// Dépendances hors registre, comptées dans `skipped`.
    pub offregistry: usize,
    /// Noms hors grammaire, comptés dans `skipped`.
    pub invalid: usize,
    /// Doublons retirés.
    pub duplicates: usize,
    /// Composants de développement retirés par `--omit-dev`.
    pub omitted: usize,
    /// Composants retirés par les bornes de F5.
    pub truncated: usize,
}

/// Horodatage et identité d'un document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// `seq` de l'enveloppe (heure Unix en millisecondes au moment de signer).
    pub seq: i64,
    /// Heure Unix, aussi `metadata.timestamp`.
    pub sent_at: i64,
    /// Aléa du `serialNumber` (UUID v4).
    pub serial: [u8; 16],
}

/// Document construit : enveloppe prête à signer, et ce qui a été fait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub envelope: Envelope,
    pub report: Report,
}

/// Erreur de construction : un `vigie:path` hors règle, ou un document que
/// la liste blanche refuserait (erreur interne, jamais envoyé).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    Path,
    Internal(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path => f.write_str(
                "chemin de lockfile hors règle (segments [A-Za-z0-9._@+-], 200 caractères)",
            ),
            Self::Internal(why) => write!(f, "erreur interne : document refusé ({why})"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Composant retenu, avant ordre et troncature.
struct Kept {
    component: RawComponent,
    dev: bool,
}

/// Purl d'une entrée (version hors grammaire : sans version), ou `None` si
/// son nom est hors grammaire.
pub fn entry_purl(entry: &Entry, cms: Option<Cms>) -> Option<Purl> {
    let version = entry.version.trim();
    let version = in_grammar(version).then_some(version);
    let wordpress = match (cms, entry.ecosystem, entry.namespace.as_deref()) {
        (Some(Cms::Wordpress), PurlType::Composer, Some("wpackagist-plugin")) => Some("plugin"),
        (Some(Cms::Wordpress), PurlType::Composer, Some("wpackagist-theme")) => Some("theme"),
        _ => None,
    };
    match wordpress {
        Some(category) => Purl::new(PurlType::Wordpress, Some(category), &entry.name, version).ok(),
        None => Purl::new(
            entry.ecosystem,
            entry.namespace.as_deref(),
            &entry.name,
            version,
        )
        .ok(),
    }
}

/// Composant de la liste blanche pour un purl validé.
fn component(purl: &Purl, path: &str, dev: bool) -> RawComponent {
    let name = match (purl.ty(), purl.namespace()) {
        (PurlType::Wordpress, _) | (_, None) => purl.name().to_owned(),
        (_, Some(namespace)) => format!("{namespace}/{}", purl.name()),
    };
    let scope = if dev { Scope::Dev } else { Scope::Required };
    RawComponent {
        kind: "library".to_owned(),
        name,
        version: purl.version().unwrap_or("").to_owned(),
        purl: purl.canonical(),
        scope: if dev { "excluded" } else { "required" }.to_owned(),
        properties: vec![
            Property {
                name: PROPERTY_PATH.to_owned(),
                value: path.to_owned(),
            },
            Property {
                name: PROPERTY_SCOPE.to_owned(),
                value: scope.as_str().to_owned(),
            },
        ],
    }
}

/// UUID v4 en minuscules, `urn:uuid:…`.
fn serial_number(mut bytes: [u8; 16]) -> String {
    bytes[6] = bytes[6] & 0x0F | 0x40;
    bytes[8] = bytes[8] & 0x3F | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// BOM CycloneDX seul (sortie de `sbom`).
pub fn build_bom(name: &str, components: Vec<RawComponent>, now: i64, serial: [u8; 16]) -> Bom {
    Bom {
        bom_format: "CycloneDX".to_owned(),
        spec_version: SPEC_VERSION.to_owned(),
        serial_number: serial_number(serial),
        metadata: Metadata {
            timestamp: crate::iso_utc(now),
            component: MetaComponent {
                kind: "application".to_owned(),
                name: name.to_owned(),
            },
        },
        components,
    }
}

/// Enveloppe de F5, `source: ci`, `agent: vigie-inventory/<version>`.
pub fn build_envelope(
    site: &str,
    seq: i64,
    sent_at: i64,
    bom: Bom,
    complete: bool,
    skipped: i64,
) -> Envelope {
    Envelope {
        v: 1,
        kind: "inventory".to_owned(),
        site: site.to_owned(),
        source: Some(Source::Ci),
        seq,
        sent_at,
        agent: format!("vigie-inventory/{TOOL_VERSION}"),
        complete,
        skipped,
        bom,
    }
}

/// Construit l'inventaire de `site` (ou [`DEFAULT_NAME`]) depuis les
/// lockfiles lus, dans l'ordre reçu.
pub fn document(
    site: &str,
    lockfiles: &[Lockfile],
    options: Options,
    stamp: Stamp,
) -> Result<Document, BuildError> {
    let mut report = Report {
        lockfiles: lockfiles.len(),
        ..Report::default()
    };
    let mut seen_wordpress: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut kept: Vec<Kept> = Vec::new();
    for lockfile in lockfiles {
        if !bom::valid_path(&lockfile.path) {
            return Err(BuildError::Path);
        }
        report.ignored += lockfile.parsed.ignored;
        report.offregistry += lockfile.parsed.offregistry;
        for entry in &lockfile.parsed.entries {
            let Some(purl) = entry_purl(entry, options.cms) else {
                report.invalid += 1;
                continue;
            };
            let fresh = if purl.ty() == PurlType::Wordpress {
                seen_wordpress.insert(purl.without_version().canonical())
            } else {
                seen.insert((purl.canonical(), lockfile.path.clone()))
            };
            if !fresh {
                report.duplicates += 1;
                continue;
            }
            if options.omit_dev && entry.dev {
                report.omitted += 1;
                continue;
            }
            kept.push(Kept {
                component: component(&purl, &lockfile.path, entry.dev),
                dev: entry.dev,
            });
        }
    }
    // Ordre global : tous les `required`, puis tous les `dev`.
    let (mut ordered, dev): (Vec<Kept>, Vec<Kept>) = kept.into_iter().partition(|k| !k.dev);
    ordered.extend(dev);
    let mut components: Vec<RawComponent> = ordered.into_iter().map(|k| k.component).collect();
    if components.len() > MAX_COMPONENTS {
        report.truncated += components.len() - MAX_COMPONENTS;
        components.truncate(MAX_COMPONENTS);
    }
    let skipped = i64::try_from(report.offregistry + report.invalid)
        .unwrap_or(MAX_SKIPPED)
        .min(MAX_SKIPPED);
    let bom = build_bom(site, Vec::new(), stamp.sent_at, stamp.serial);
    // Taille de l'enveloppe : celle d'un document vide (avec `complete` à
    // faux, le plus long), plus chaque composant encodé et sa virgule.
    let empty = build_envelope(site, stamp.seq, stamp.sent_at, bom.clone(), false, skipped);
    let base = serde_json::to_vec(&empty)
        .map_err(|_| BuildError::Internal("sérialisation"))?
        .len();
    let sizes: Vec<usize> = components
        .iter()
        .map(|c| serde_json::to_vec(c).map_or(usize::MAX / 4, |v| v.len()) + 1)
        .collect();
    let mut total = base + sizes.iter().sum::<usize>();
    while total > MAX_INVENTORY_BYTES && !components.is_empty() {
        components.pop();
        total -= sizes[components.len()];
        report.truncated += 1;
    }
    report.components = components.len();
    let complete = skipped == 0 && report.omitted == 0 && report.truncated == 0;
    let bom = Bom { components, ..bom };
    let envelope = build_envelope(site, stamp.seq, stamp.sent_at, bom, complete, skipped);
    validate_own(&envelope, options.cms)?;
    Ok(Document { envelope, report })
}

/// Revalide le document par la validation de F5, avec la matrice
/// d'écosystèmes du CMS déclaré (`Wordpress` avec `--cms wordpress`, sinon
/// `Generic`) : tout composant écarté, document refusé ou trop gros est une
/// erreur interne.
pub fn validate_own(envelope: &Envelope, cms: Option<Cms>) -> Result<(), BuildError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| BuildError::Internal("sérialisation"))?;
    if bytes.len() > MAX_INVENTORY_BYTES {
        return Err(BuildError::Internal("plus de 512 Kio"));
    }
    let inventory = bom::parse(&bytes, &envelope.site, Cms::site_kind(cms))
        .map_err(|e| BuildError::Internal(e.0))?;
    if inventory.dropped_total() > 0 || inventory.components.len() != envelope.bom.components.len()
    {
        return Err(BuildError::Internal(
            "composant écarté par la liste blanche",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_numbers_are_v4_uuids() {
        assert_eq!(
            serial_number([0xff; 16]),
            "urn:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
        assert_eq!(
            serial_number([0; 16]),
            "urn:uuid:00000000-0000-4000-8000-000000000000"
        );
    }
}
