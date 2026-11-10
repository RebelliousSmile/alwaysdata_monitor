//! Lecteur zip strict des dumps de failles : le sous-ensemble mesuré des
//! exports OSV (`docs/failles.md`), tout le reste refusé.
//!
//! - fin de fichier classique, ou ZIP64 (enregistrement, localisateur, fin
//!   classique, chacun exactement à sa place, un seul disque) ;
//! - répertoire central contigu, juste avant la fin de fichier, **consommé
//!   exactement** : autant d'entrées que déclaré, aucun octet restant ;
//! - méthodes 0 (stocké, tailles égales) et 8 (deflate) ; chiffrement,
//!   données « patchées », ZIP64 par entrée et descripteur de données
//!   refusés ;
//! - en-tête local identique au répertoire central (nom, méthode, drapeaux,
//!   CRC, tailles), enregistrements locaux sans recouvrement et sous le
//!   répertoire central ;
//! - toute arithmétique d'offset et de taille en `u64` vérifiée.
//!
//! Rien n'est extrait sur le disque : chaque entrée est décompressée en
//! mémoire (taille déclarée + 1 octet lus au plus), longueur et CRC
//! vérifiés. Le nom d'une entrée n'est **jamais** un chemin. Une entrée trop
//! grosse ou mal nommée est sautée et comptée ; toute autre anomalie fait
//! refuser le dump entier.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use flate2::Crc;
use flate2::bufread::DeflateDecoder;

use super::{Limits, SyncError};
use crate::vulns::advisory::Reason;

const EOCD_SIG: u32 = 0x0605_4b50;
const EOCD_LEN: u64 = 22;
const LOCATOR_SIG: u32 = 0x0706_4b50;
const LOCATOR_LEN: u64 = 20;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_EOCD_MIN: u64 = 44;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const CENTRAL_LEN: usize = 46;
const LOCAL_SIG: u32 = 0x0403_4b50;
const LOCAL_LEN: u64 = 30;
const MAX_COMMENT: u64 = 0xFFFF;

/// Bit 0 : chiffré.
const FLAG_ENCRYPTED: u16 = 1;
/// Bits 1 et 2 : options de deflate, sans effet sur la lecture.
const FLAG_DEFLATE_OPTIONS: u16 = 0b110;
/// Bit 3 : tailles et CRC dans un descripteur après les données.
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
/// Bit 11 : nom en UTF-8.
const FLAG_UTF8: u16 = 1 << 11;

const DATA_DESCRIPTOR: &str =
    "descripteurs de données non pris en charge : format de l'export changé ?";

/// Une entrée du répertoire central.
#[derive(Debug, Clone)]
struct Central {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u64,
    unpacked: u64,
    offset: u64,
}

/// Contenu d'une entrée lue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Entrée sautée sans décompression : `too_large` ou `bad_entry_name`.
    Skipped(Reason),
    /// Contenu décompressé, longueur et CRC vérifiés.
    Data(Vec<u8>),
}

/// Entrée lue, dans l'ordre des offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Nom tel quel (UTF-8 avec remplacement), jamais employé comme chemin.
    pub name: String,
    pub body: Body,
}

/// Zip ouvert, répertoire central lu et validé. Lu depuis le fichier du
/// dump ; tout lecteur positionnable convient (fuzz des tests en mémoire).
pub struct ZipReader<R = File> {
    file: R,
    limits: Limits,
    /// Entrées triées par offset.
    entries: Vec<Central>,
    cd_offset: u64,
    declared_unpacked: u64,
}

fn zip(reason: &'static str) -> SyncError {
    SyncError::Zip(reason)
}

fn overflow() -> SyncError {
    zip("débordement d'offset ou de taille")
}

fn read_err(err: std::io::Error) -> SyncError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        zip("fichier tronqué")
    } else {
        SyncError::io("lecture du zip", &err)
    }
}

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn u64_at(buf: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[at..at + 8]);
    u64::from_le_bytes(b)
}

fn read_exact_at<R: Read + Seek>(
    file: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, SyncError> {
    file.seek(SeekFrom::Start(offset)).map_err(read_err)?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).map_err(read_err)?;
    Ok(buf)
}

/// Nom admis : `[A-Za-z0-9._-]{1,64}\.json`.
pub fn valid_entry_name(name: &[u8]) -> bool {
    let Some(stem) = name.strip_suffix(b".json") else {
        return false;
    };
    (1..=64).contains(&stem.len())
        && stem
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl ZipReader<File> {
    /// Ouvre le zip et valide sa fin de fichier et son répertoire central,
    /// sans rien décompresser.
    pub fn open(path: &Path, limits: &Limits) -> Result<Self, SyncError> {
        let file = File::open(path).map_err(|e| SyncError::io("ouverture du zip", &e))?;
        let size = file
            .metadata()
            .map_err(|e| SyncError::io("ouverture du zip", &e))?
            .len();
        Self::from_reader(file, size, limits)
    }
}

impl<R: Read + Seek> ZipReader<R> {
    /// Comme [`ZipReader::open`], sur un lecteur de `size` octets.
    pub fn from_reader(mut file: R, size: u64, limits: &Limits) -> Result<Self, SyncError> {
        if size > limits.compressed {
            return Err(SyncError::TooLarge {
                what: "dump compressé",
            });
        }
        if size < EOCD_LEN {
            return Err(zip("fin de fichier absente"));
        }
        // Fin classique : dans les 22 + 65 535 derniers octets, commentaire
        // jusqu'à la fin exacte du fichier.
        let tail_len = size.min(EOCD_LEN + MAX_COMMENT);
        let tail_start = size - tail_len;
        let tail = read_exact_at(&mut file, tail_start, tail_len as usize)?;
        let eocd_rel = (0..=tail.len() - EOCD_LEN as usize)
            .rev()
            .find(|&at| {
                u32_at(&tail, at) == EOCD_SIG
                    && u16_at(&tail, at + 20) as usize + at + EOCD_LEN as usize == tail.len()
            })
            .ok_or(zip("fin de fichier absente"))?;
        let eocd = &tail[eocd_rel..];
        let eocd_pos = tail_start + eocd_rel as u64;
        if u16_at(eocd, 4) != 0 || u16_at(eocd, 6) != 0 {
            return Err(zip("archive sur plusieurs disques"));
        }
        let (disk_entries, total_entries) = (u16_at(eocd, 8), u16_at(eocd, 10));
        if disk_entries != total_entries {
            return Err(zip("nombre d'entrées du disque incohérent"));
        }
        let (cd_size32, cd_offset32) = (u32_at(eocd, 12), u32_at(eocd, 16));
        let zip64 =
            total_entries == 0xFFFF || cd_size32 == 0xFFFF_FFFF || cd_offset32 == 0xFFFF_FFFF;
        let (entries, cd_size, cd_offset, cd_end) = if zip64 {
            // Localisateur exactement 20 octets avant la fin classique.
            let locator_pos = eocd_pos
                .checked_sub(LOCATOR_LEN)
                .ok_or(zip("localisateur ZIP64 absent"))?;
            let locator = read_exact_at(&mut file, locator_pos, LOCATOR_LEN as usize)?;
            if u32_at(&locator, 0) != LOCATOR_SIG {
                return Err(zip("localisateur ZIP64 absent"));
            }
            if u32_at(&locator, 4) != 0 || u32_at(&locator, 16) != 1 {
                return Err(zip("archive sur plusieurs disques"));
            }
            let record_pos = u64_at(&locator, 8);
            let fixed_end = record_pos
                .checked_add(12 + ZIP64_EOCD_MIN)
                .ok_or_else(overflow)?;
            if fixed_end > locator_pos {
                return Err(zip("enregistrement ZIP64 mal placé"));
            }
            let record = read_exact_at(&mut file, record_pos, (12 + ZIP64_EOCD_MIN) as usize)?;
            if u32_at(&record, 0) != ZIP64_EOCD_SIG {
                return Err(zip("enregistrement ZIP64 absent"));
            }
            let record_size = u64_at(&record, 4);
            if record_size < ZIP64_EOCD_MIN {
                return Err(zip("enregistrement ZIP64 trop court"));
            }
            let record_end = record_pos
                .checked_add(12)
                .and_then(|p| p.checked_add(record_size))
                .ok_or_else(overflow)?;
            if record_end != locator_pos {
                return Err(zip("enregistrement ZIP64 mal placé"));
            }
            if u32_at(&record, 16) != 0 || u32_at(&record, 20) != 0 {
                return Err(zip("archive sur plusieurs disques"));
            }
            let (disk64, total64) = (u64_at(&record, 24), u64_at(&record, 32));
            let (size64, offset64) = (u64_at(&record, 40), u64_at(&record, 48));
            // Un champ classique non saturé doit dire la même chose.
            if disk64 != total64
                || (total_entries != 0xFFFF && u64::from(total_entries) != total64)
                || (cd_size32 != 0xFFFF_FFFF && u64::from(cd_size32) != size64)
                || (cd_offset32 != 0xFFFF_FFFF && u64::from(cd_offset32) != offset64)
            {
                return Err(zip("fin de fichier ZIP64 incohérente"));
            }
            (total64, size64, offset64, record_pos)
        } else {
            (
                u64::from(total_entries),
                u64::from(cd_size32),
                u64::from(cd_offset32),
                eocd_pos,
            )
        };
        if entries > limits.entries {
            return Err(SyncError::TooLarge {
                what: "nombre d'entrées",
            });
        }
        if cd_size > limits.central_directory {
            return Err(SyncError::TooLarge {
                what: "répertoire central",
            });
        }
        if cd_offset.checked_add(cd_size).ok_or_else(overflow)? != cd_end {
            return Err(zip("répertoire central hors de sa place"));
        }
        let cd = read_exact_at(&mut file, cd_offset, cd_size as usize)?;
        let mut list = Vec::with_capacity(entries.min(1 << 20) as usize);
        let mut at = 0usize;
        let mut declared_unpacked: u64 = 0;
        while at < cd.len() {
            if list.len() as u64 == entries {
                return Err(zip("octets restants dans le répertoire central"));
            }
            let entry = parse_central(&cd, &mut at)?;
            declared_unpacked = declared_unpacked
                .checked_add(entry.unpacked)
                .ok_or_else(overflow)?;
            if declared_unpacked > limits.unpacked {
                return Err(SyncError::TooLarge {
                    what: "taille décompressée déclarée",
                });
            }
            list.push(entry);
        }
        if list.len() as u64 != entries {
            return Err(zip("moins d'entrées que déclaré"));
        }
        list.sort_by_key(|e| e.offset);
        Ok(Self {
            file,
            limits: limits.clone(),
            entries: list,
            cd_offset,
            declared_unpacked,
        })
    }

    /// Somme des tailles décompressées déclarées (second contrôle disque).
    pub fn declared_unpacked(&self) -> u64 {
        self.declared_unpacked
    }

    /// Nombre d'entrées du répertoire central.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entrées dans l'ordre des offsets. Une erreur arrête l'itération : le
    /// dump entier est refusé.
    pub fn entries(&mut self) -> Entries<'_, R> {
        Entries {
            reader: self,
            next: 0,
            previous_end: 0,
            unpacked: 0,
            failed: false,
        }
    }
}

/// Une entrée du répertoire central, à `*at` ; avance `*at`.
fn parse_central(cd: &[u8], at: &mut usize) -> Result<Central, SyncError> {
    let start = *at;
    let fixed_end = start.checked_add(CENTRAL_LEN).ok_or_else(overflow)?;
    if fixed_end > cd.len() {
        return Err(zip("répertoire central tronqué"));
    }
    let h = &cd[start..fixed_end];
    if u32_at(h, 0) != CENTRAL_SIG {
        return Err(zip("signature d'entrée centrale invalide"));
    }
    let flags = u16_at(h, 8);
    let method = u16_at(h, 10);
    check_flags(flags)?;
    let crc = u32_at(h, 16);
    let (compressed, unpacked) = (u32_at(h, 20), u32_at(h, 24));
    let (name_len, extra_len, comment_len) = (
        u16_at(h, 28) as usize,
        u16_at(h, 30) as usize,
        u16_at(h, 32) as usize,
    );
    let disk = u16_at(h, 34);
    let offset = u32_at(h, 42);
    if compressed == 0xFFFF_FFFF || unpacked == 0xFFFF_FFFF || offset == 0xFFFF_FFFF {
        return Err(zip("ZIP64 par entrée non pris en charge"));
    }
    if disk != 0 {
        return Err(zip("archive sur plusieurs disques"));
    }
    check_method(method, compressed, unpacked)?;
    let name_end = fixed_end.checked_add(name_len).ok_or_else(overflow)?;
    let end = name_end
        .checked_add(extra_len)
        .and_then(|e| e.checked_add(comment_len))
        .ok_or_else(overflow)?;
    if end > cd.len() {
        return Err(zip("répertoire central tronqué"));
    }
    *at = end;
    Ok(Central {
        name: cd[fixed_end..name_end].to_vec(),
        flags,
        method,
        crc,
        compressed: u64::from(compressed),
        unpacked: u64::from(unpacked),
        offset: u64::from(offset),
    })
}

fn check_flags(flags: u16) -> Result<(), SyncError> {
    if flags & FLAG_DATA_DESCRIPTOR != 0 {
        return Err(zip(DATA_DESCRIPTOR));
    }
    if flags & FLAG_ENCRYPTED != 0 {
        return Err(zip("entrée chiffrée"));
    }
    if flags & !(FLAG_DEFLATE_OPTIONS | FLAG_UTF8) != 0 {
        return Err(zip("drapeau d'entrée non pris en charge"));
    }
    Ok(())
}

fn check_method(method: u16, compressed: u32, unpacked: u32) -> Result<(), SyncError> {
    match method {
        0 if compressed != unpacked => Err(zip("entrée stockée de tailles différentes")),
        0 | 8 => Ok(()),
        _ => Err(zip("méthode de compression non prise en charge")),
    }
}

/// Itérateur des entrées.
pub struct Entries<'a, R = File> {
    reader: &'a mut ZipReader<R>,
    next: usize,
    previous_end: u64,
    unpacked: u64,
    failed: bool,
}

impl<R: Read + Seek> Entries<'_, R> {
    fn read_next(&mut self) -> Result<Entry, SyncError> {
        let c = self.reader.entries[self.next].clone();
        self.next += 1;
        let file = &mut self.reader.file;
        // En-tête local, identique au répertoire central.
        let local = read_exact_at(file, c.offset, LOCAL_LEN as usize)?;
        if u32_at(&local, 0) != LOCAL_SIG {
            return Err(zip("signature d'en-tête local invalide"));
        }
        let (name_len, extra_len) = (u16_at(&local, 26) as u64, u16_at(&local, 28) as u64);
        if u16_at(&local, 6) != c.flags
            || u16_at(&local, 8) != c.method
            || u32_at(&local, 14) != c.crc
            || u64::from(u32_at(&local, 18)) != c.compressed
            || u64::from(u32_at(&local, 22)) != c.unpacked
            || name_len != c.name.len() as u64
        {
            return Err(zip("en-tête local différent du répertoire central"));
        }
        let name_pos = c.offset.checked_add(LOCAL_LEN).ok_or_else(overflow)?;
        let data_pos = name_pos
            .checked_add(name_len)
            .and_then(|p| p.checked_add(extra_len))
            .ok_or_else(overflow)?;
        let end = data_pos.checked_add(c.compressed).ok_or_else(overflow)?;
        if c.offset < self.previous_end {
            return Err(zip("entrées locales qui se recouvrent"));
        }
        if end > self.reader.cd_offset {
            return Err(zip("entrée locale sous le répertoire central"));
        }
        self.previous_end = end;
        if read_exact_at(file, name_pos, name_len as usize)? != c.name {
            return Err(zip("en-tête local différent du répertoire central"));
        }
        let name = String::from_utf8_lossy(&c.name).into_owned();
        if c.name.ends_with(b"/") || !valid_entry_name(&c.name) {
            return Ok(Entry {
                name,
                body: Body::Skipped(Reason::BadEntryName),
            });
        }
        if c.unpacked > self.reader.limits.entry {
            return Ok(Entry {
                name,
                body: Body::Skipped(Reason::TooLarge),
            });
        }
        file.seek(SeekFrom::Start(data_pos)).map_err(read_err)?;
        let raw = Read::take(&mut *file, c.compressed);
        // Taille déclarée + 1 octet au plus : une entrée qui ment est vue
        // sans produire davantage.
        let want = c.unpacked + 1;
        let mut data = Vec::with_capacity(c.unpacked as usize);
        if c.method == 8 {
            let mut decoder = DeflateDecoder::new(BufReader::new(raw));
            Read::take(&mut decoder, want)
                .read_to_end(&mut data)
                .map_err(|_| zip("flux deflate corrompu"))?;
            let rest = decoder.get_ref();
            if data.len() as u64 == c.unpacked
                && (!rest.buffer().is_empty() || rest.get_ref().limit() != 0)
            {
                return Err(zip("données après le flux deflate"));
            }
        } else {
            let mut raw = raw;
            raw.read_to_end(&mut data).map_err(read_err)?;
        }
        if data.len() as u64 != c.unpacked {
            return Err(zip("longueur réelle différente de la taille déclarée"));
        }
        let mut crc = Crc::new();
        crc.update(&data);
        if crc.sum() != c.crc {
            return Err(zip("CRC faux"));
        }
        self.unpacked = self.unpacked.checked_add(c.unpacked).ok_or_else(overflow)?;
        if self.unpacked > self.reader.limits.unpacked {
            return Err(SyncError::TooLarge {
                what: "taille décompressée",
            });
        }
        Ok(Entry {
            name,
            body: Body::Data(data),
        })
    }
}

impl<R: Read + Seek> Iterator for Entries<'_, R> {
    type Item = Result<Entry, SyncError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.next >= self.reader.entries.len() {
            return None;
        }
        let item = self.read_next();
        self.failed = item.is_err();
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names() {
        for good in [
            "GHSA-aaaa-bbbb-cccc.json",
            "RUSTSEC-2017-0004.json",
            "a.json",
        ] {
            assert!(valid_entry_name(good.as_bytes()), "{good}");
        }
        for bad in [
            "../../x.json",
            "/etc/x.json",
            "a/b.json",
            "x.txt",
            ".json",
            "dossier/",
            "é.json",
            &format!("{}.json", "a".repeat(65)),
        ] {
            assert!(!valid_entry_name(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn flags_and_methods() {
        assert!(check_flags(0).is_ok());
        assert!(check_flags(FLAG_UTF8 | 0b10).is_ok());
        assert_eq!(check_flags(FLAG_DATA_DESCRIPTOR), Err(zip(DATA_DESCRIPTOR)));
        assert!(check_flags(FLAG_ENCRYPTED).is_err());
        assert!(check_flags(1 << 6).is_err());
        assert!(check_flags(1 << 13).is_err());
        assert!(check_flags(1 << 5).is_err());
        assert!(check_method(0, 3, 3).is_ok());
        assert!(check_method(0, 3, 4).is_err());
        assert!(check_method(8, 3, 40).is_ok());
        assert!(check_method(12, 3, 40).is_err());
    }
}
