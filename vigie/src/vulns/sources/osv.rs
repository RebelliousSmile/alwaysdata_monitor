//! Exports OSV.dev par écosystème (`Packagist`, `npm`, `crates.io`) : un zip
//! d'un JSON OSV par faille, lu par le lecteur strict, chaque entrée
//! convertie par `from_osv` (F1) puis poussée en flux. Licence et
//! attribution par enregistrement, d'après le préfixe de l'identifiant
//! (`docs/failles.md`, « OSV.dev : exports par écosystème »).

use std::time::{Duration, Instant};

use crate::vulns::advisory::{Tally, from_osv};
use crate::vulns::sources::Redistribution;
use crate::vulns::sync::download::{Download, Fetched, Request};
use crate::vulns::sync::zip::{Body, ZipReader};
use crate::vulns::sync::{Dumped, FetchOutcome, Limits, Sink, SourceMeta, SyncError, VulnSource};
use crate::vulns::version::SourceEcosystem;

/// Seule origine des exports OSV.
pub const OSV_ORIGIN: (&str, u16) = ("osv-vulnerabilities.storage.googleapis.com", 443);
/// Version du lecteur OSV : à incrémenter à chaque changement du lecteur
/// zip, de `from_osv` ou des bornes F1 qui change ce qui est stocké (le
/// dump est alors rechargé sans requête conditionnelle).
pub const LOADER_VERSION: u32 = 1;

/// Un export OSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsvSource {
    pub ecosystem: SourceEcosystem,
}

impl VulnSource for OsvSource {
    fn id(&self) -> &'static str {
        match self.ecosystem {
            SourceEcosystem::Packagist => "osv-packagist",
            SourceEcosystem::Npm => "osv-npm",
            SourceEcosystem::CratesIo => "osv-crates-io",
            SourceEcosystem::Wordfence | SourceEcosystem::FriendsOfPresta => "osv-hors-export",
        }
    }

    fn meta(&self) -> SourceMeta {
        let url = match self.ecosystem {
            SourceEcosystem::Packagist => {
                "https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip"
            }
            SourceEcosystem::Npm => {
                "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
            }
            SourceEcosystem::CratesIo
            | SourceEcosystem::Wordfence
            | SourceEcosystem::FriendsOfPresta => {
                "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"
            }
        };
        SourceMeta {
            url,
            origins: &[OSV_ORIGIN],
            license: "",
            attribution: "OSV.dev, licence de chaque enregistrement selon son préfixe",
            limits: Limits::osv(self.ecosystem),
            min_interval: Duration::ZERO,
            loader_version: LOADER_VERSION,
            redistribution: Redistribution::Free,
        }
    }

    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        let url = dl.url().cloned().ok_or(SyncError::OriginRefused)?;
        let dump = match dl.get_to_file(&Request::get(url))? {
            Fetched::NotModified => {
                return Ok(FetchOutcome::Unchanged {
                    not_modified: true,
                    validators: None,
                });
            }
            Fetched::SameDigest { validators, .. } => {
                return Ok(FetchOutcome::Unchanged {
                    not_modified: false,
                    validators: Some(validators),
                });
            }
            Fetched::Dump(dump) => dump,
        };
        let mut zip = ZipReader::open(&dump.path, dl.limits())?;
        // Second contrôle disque : borne haute de ce que le chargement
        // écrira en base.
        dl.workdir().ensure_space(zip.declared_unpacked())?;
        let deadline: Instant = dl.deadline();
        let mut entries = 0u64;
        for entry in zip.entries() {
            if Instant::now() >= deadline {
                return Err(SyncError::Deadline);
            }
            let entry = entry?;
            entries += 1;
            match entry.body {
                Body::Skipped(reason) => tally.add(reason),
                Body::Data(bytes) => {
                    if let Ok(advisory) = from_osv(&bytes, self.ecosystem, tally) {
                        sink.push(advisory)?;
                    }
                }
            }
        }
        Ok(FetchOutcome::Loaded(Dumped {
            sha256: dump.sha256,
            validators: dump.validators,
            bytes: dump.bytes,
            unpacked_bytes: zip.declared_unpacked(),
            entries,
            revision: None,
        }))
    }
}
