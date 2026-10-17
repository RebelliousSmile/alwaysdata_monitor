//! FIRST EPSS (issue #18) : CSV gzip quotidien des scores d'exploitation,
//! lu **en flux** (≈ 300 000 à 383 000 lignes, jamais entier en mémoire).
//! Format, plafonds provisoires et hôtes : `docs/failles.md`, « FIRST
//! EPSS ». L'API `api.first.org` n'est jamais appelée.
//!
//! Lecture stricte : `MultiGzDecoder` (plusieurs membres admis) derrière un
//! compteur coupé au plafond décompressé ; lignes lues par `read_until`,
//! 128 octets au plus, `\r` final et dernière ligne vide tolérés ;
//! commentaire `#model_version:<v>,score_date:<date>` exigé (date lue par
//! son préfixe `AAAA-MM-JJ`), en-tête exactement `cve,epss,percentile`,
//! puis lignes `CVE,score,percentile` (nombres de `[0, 1]` lus en
//! millionièmes tronqués, `parse_ppm`). Une ligne fautive est écartée et
//! comptée ; le seuil d'écart et la garde contre le rétrécissement sont
//! appliqués par le moteur à la fin.

use std::cell::Cell;
use std::io::{BufRead, BufReader, Read};
use std::rc::Rc;
use std::time::{Duration, Instant};

use flate2::read::MultiGzDecoder;
use jiff::Timestamp;
use jiff::civil::Date;

use crate::vulns::advisory::{Reason, Tally};
use crate::vulns::enrich_store::{DatasetHeader, EpssRow};
use crate::vulns::exploit::{Cve, parse_ppm};
use crate::vulns::sources::Redistribution;
use crate::vulns::sync::download::{Download, Fetched, Request};
use crate::vulns::sync::enrichment::{EnrichSink, EnrichmentSource};
use crate::vulns::sync::{Dumped, FetchOutcome, Limits, SourceMeta, SyncError};

/// URL du CSV courant ; redirection admise vers l'ancien hôte.
pub const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
/// Origines admises, redirections comprises.
pub const EPSS_ORIGINS: &[(&str, u16)] = &[
    ("epss.empiricalsecurity.com", 443),
    ("epss.cyentia.com", 443),
];
/// Version du lecteur EPSS : à incrémenter à chaque changement de lecture
/// ou de conversion qui change ce qui est stocké.
pub const LOADER_VERSION: u32 = 1;
/// Longueur maximale d'une ligne, fin de ligne exclue.
pub const MAX_LINE: usize = 128;
/// En-tête exact des colonnes.
pub const COLUMNS: &str = "cve,epss,percentile";
/// `model_version` : 32 caractères au plus.
const MAX_VERSION_CHARS: usize = 32;
const MIB: u64 = 1024 * 1024;

/// Plafonds provisoires, à confirmer par le relevé du VPS.
pub fn limits() -> Limits {
    Limits {
        compressed: 32 * MIB,
        unpacked: 64 * MIB,
        entries: 2_000_000,
        entry: MAX_LINE as u64,
        central_directory: 0,
        duration: Duration::from_secs(15 * 60),
        max_dropped_ratio: 0.01,
    }
}

/// La source EPSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpssSource;

/// Coupe la lecture au plafond décompressé ; `over` dit pourquoi elle a
/// échoué.
struct Capped<R> {
    inner: R,
    read: u64,
    cap: u64,
    over: Rc<Cell<bool>>,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        if self.read > self.cap {
            self.over.set(true);
            return Err(std::io::Error::other("plafond décompressé"));
        }
        Ok(n)
    }
}

/// Commentaire de tête : version du modèle et date des scores (minuit
/// UTC).
pub fn parse_comment(line: &str) -> Option<DatasetHeader> {
    let rest = line.strip_prefix("#model_version:")?;
    let (version, date) = rest.split_once(",score_date:")?;
    if !(1..=MAX_VERSION_CHARS).contains(&version.chars().count())
        || !version.chars().all(|c| c.is_ascii_graphic())
    {
        return None;
    }
    let day: Date = date.get(..10)?.parse().ok()?;
    let released: Timestamp = day.to_zoned(jiff::tz::TimeZone::UTC).ok()?.timestamp();
    Some(DatasetHeader {
        version: version.to_owned(),
        released,
    })
}

/// Une ligne de scores ; `Err` : raison de l'écart.
pub fn parse_row(line: &str) -> Result<(Cve, EpssRow), Reason> {
    let mut fields = line.split(',');
    let (Some(cve), Some(epss), Some(percentile)) = (fields.next(), fields.next(), fields.next())
    else {
        return Err(Reason::MissingField);
    };
    if fields.next().is_some() {
        return Err(Reason::BadValue);
    }
    let cve = Cve::parse(cve).ok_or(Reason::BadCve)?;
    let epss_ppm = parse_ppm(epss).ok_or(Reason::BadValue)?;
    let percentile_ppm = parse_ppm(percentile).ok_or(Reason::BadValue)?;
    Ok((
        cve,
        EpssRow {
            epss_ppm,
            percentile_ppm,
        },
    ))
}

/// Lit une ligne de [`MAX_LINE`] octets au plus ; `None` en fin de flux.
fn next_line(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> Result<Option<()>, std::io::Error> {
    buf.clear();
    let n = reader
        .by_ref()
        .take(MAX_LINE as u64 + 2)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(()))
}

impl EnrichmentSource for EpssSource {
    fn id(&self) -> &'static str {
        "epss"
    }

    fn meta(&self) -> SourceMeta {
        SourceMeta {
            url: EPSS_URL,
            origins: EPSS_ORIGINS,
            license: "FIRST EPSS Usage Agreement",
            attribution: "FIRST EPSS, See EPSS at https://www.first.org/epss",
            limits: limits(),
            min_interval: Duration::ZERO,
            loader_version: LOADER_VERSION,
            redistribution: Redistribution::Free,
            // Un .csv.gz peut être servi avec Content-Encoding: gzip : il est
            // gardé tel quel et décompressé ici (à vérifier au relevé VPS).
            raw_content_encodings: &["gzip"],
        }
    }

    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn EnrichSink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        let url = dl.url().cloned().ok_or(SyncError::OriginRefused)?;
        let served = Some(url.to_string());
        let dump = match dl.get_to_file(&Request::get(url))? {
            Fetched::NotModified => {
                return Ok(FetchOutcome::Unchanged {
                    not_modified: true,
                    validators: None,
                    stale: false,
                    served,
                });
            }
            Fetched::SameDigest { validators, .. } => {
                return Ok(FetchOutcome::Unchanged {
                    not_modified: false,
                    validators: Some(validators),
                    stale: false,
                    served,
                });
            }
            Fetched::Dump(dump) => dump,
        };
        let file =
            std::fs::File::open(&dump.path).map_err(|e| SyncError::io("lecture d'EPSS", &e))?;
        let limits = dl.limits().clone();
        let over = Rc::new(Cell::new(false));
        let capped = Capped {
            inner: MultiGzDecoder::new(file),
            read: 0,
            cap: limits.unpacked,
            over: Rc::clone(&over),
        };
        let mut reader = BufReader::new(capped);
        let io = |e: std::io::Error| {
            if over.get() {
                SyncError::TooLarge {
                    what: "EPSS décompressé",
                }
            } else {
                SyncError::Format(format!("gzip EPSS illisible ({})", e.kind()))
            }
        };
        let mut buf = Vec::with_capacity(MAX_LINE + 2);
        let line =
            |reader: &mut BufReader<_>, buf: &mut Vec<u8>| -> Result<Option<String>, SyncError> {
                if next_line(reader, buf).map_err(io)?.is_none() {
                    return Ok(None);
                }
                if buf.len() > MAX_LINE {
                    return Err(SyncError::Format(format!(
                        "ligne EPSS de plus de {MAX_LINE} octets"
                    )));
                }
                // Ligne non UTF-8 : rendue vide, donc fautive.
                Ok(Some(String::from_utf8(buf.clone()).unwrap_or_default()))
            };
        let header = line(&mut reader, &mut buf)?
            .as_deref()
            .and_then(parse_comment)
            .ok_or_else(|| SyncError::Format("commentaire #model_version absent".into()))?;
        if line(&mut reader, &mut buf)?.as_deref() != Some(COLUMNS) {
            return Err(SyncError::Format(format!("en-tête {COLUMNS} attendu")));
        }
        let deadline = dl.deadline();
        let mut entries = 0u64;
        // Ligne vide : tolérée seulement en dernier.
        let mut blank = false;
        while let Some(text) = line(&mut reader, &mut buf)? {
            if text.is_empty() {
                blank = true;
                continue;
            }
            if blank {
                // Ligne vide au milieu : comptée comme une ligne fautive.
                entries += 1;
                tally.add(Reason::MissingField);
                blank = false;
            }
            entries += 1;
            if entries > limits.entries {
                return Err(SyncError::TooLarge {
                    what: "lignes EPSS",
                });
            }
            if entries.is_multiple_of(10_000) && Instant::now() >= deadline {
                return Err(SyncError::Deadline);
            }
            match parse_row(&text) {
                Ok((cve, row)) => sink.push_epss(cve, row)?,
                Err(reason) => tally.add(reason),
            }
        }
        sink.set_header(header);
        let unpacked = reader.get_ref().read;
        drop(reader);
        let _ = std::fs::remove_file(&dump.path);
        Ok(FetchOutcome::Loaded(Dumped {
            sha256: dump.sha256,
            validators: dump.validators,
            bytes: dump.bytes,
            unpacked_bytes: unpacked,
            entries,
            revision: None,
            served,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_comment_gives_version_and_midnight() {
        let h = parse_comment("#model_version:v2099.01.01,score_date:2099-01-15T00:00:00+0000")
            .unwrap();
        assert_eq!(h.version, "v2099.01.01");
        assert_eq!(h.released.to_string(), "2099-01-15T00:00:00Z");
        let h = parse_comment("#model_version:v2099.01.01,score_date:2099-01-15").unwrap();
        assert_eq!(h.released.to_string(), "2099-01-15T00:00:00Z");
        for bad in [
            "model_version:v,score_date:2099-01-15",
            "#model_version:,score_date:2099-01-15",
            "#model_version:v,score_date:15/01/2099",
            "#model_version:v",
        ] {
            assert!(parse_comment(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn rows_are_strict() {
        let (cve, row) = parse_row("CVE-2099-90001,1.23e-05,0.5").unwrap();
        assert_eq!(
            (cve.as_str(), row.epss_ppm, row.percentile_ppm),
            ("CVE-2099-90001", 12, 500_000)
        );
        assert_eq!(parse_row("CVE-2099-90001,1.5,0.5"), Err(Reason::BadValue));
        assert_eq!(parse_row("CVE-2099-90001,-0.1,0.5"), Err(Reason::BadValue));
        assert_eq!(parse_row("CVE-99-1,0.1,0.5"), Err(Reason::BadCve));
        assert_eq!(parse_row("CVE-2099-90001,0.1"), Err(Reason::MissingField));
        assert_eq!(parse_row("CVE-2099-90001,0.1,0.2,x"), Err(Reason::BadValue));
    }
}
