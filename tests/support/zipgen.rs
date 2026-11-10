//! Écrivain zip minimal des tests de synchronisation (`vulns_zip.rs`,
//! `vulns_zip_diff.rs`, `vulns_download.rs`, `vulns_sync.rs`), inclus par
//! `#[path]` : entrées stockées ou deflate (flate2), fin ZIP64 au-delà de
//! 65 535 entrées ou sur demande, et mutations nommées par entrée. Les zips
//! hostiles sont produits par les tests, jamais commités.

#![allow(dead_code)]

use std::io::Write;

use flate2::Compression;
use flate2::write::DeflateEncoder;

/// Une entrée et ses éventuels mensonges.
#[derive(Debug, Clone, Default)]
pub struct ZEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    /// Méthode 0 au lieu de deflate.
    pub stored: bool,
    /// Drapeaux écrits (local et central).
    pub flags: u16,
    /// Méthode écrite (local et central) à la place de la vraie.
    pub method: Option<u16>,
    /// Méthode écrite dans l'en-tête local seulement.
    pub local_method: Option<u16>,
    /// Nom écrit dans l'en-tête local seulement.
    pub local_name: Option<Vec<u8>>,
    pub crc: Option<u32>,
    /// Taille décompressée déclarée (local et central).
    pub unpacked: Option<u32>,
    /// Taille compressée déclarée (local et central).
    pub compressed: Option<u32>,
    /// Octets compressés écrits à la place des vrais.
    pub raw: Option<Vec<u8>>,
    /// Offset de l'en-tête local écrit dans le répertoire central.
    pub offset: Option<u32>,
}

impl ZEntry {
    pub fn new(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            ..Self::default()
        }
    }

    pub fn stored(name: &str, data: &[u8]) -> Self {
        Self {
            stored: true,
            ..Self::new(name, data)
        }
    }
}

/// Description d'une archive.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub entries: Vec<ZEntry>,
    /// Fin ZIP64 même sous 65 535 entrées.
    pub zip64: bool,
    /// Entrées centrales écrites deux fois (recouvrement).
    pub duplicate_central: Vec<usize>,
    /// Octets ajoutés à la fin du répertoire central (compris dans sa
    /// taille déclarée).
    pub central_garbage: Vec<u8>,
    /// Nombre d'entrées déclaré à la place du vrai.
    pub declared_entries: Option<u64>,
}

/// Archive écrite et position de ses structures.
#[derive(Debug, Clone)]
pub struct Built {
    pub bytes: Vec<u8>,
    pub cd_offset: usize,
    pub cd_size: usize,
    pub zip64_record: Option<usize>,
    pub locator: Option<usize>,
    pub eocd: usize,
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn u16le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn u32le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn u64le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u16(bytes: &mut [u8], at: usize, v: u16) {
    bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u32(bytes: &mut [u8], at: usize, v: u32) {
    bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u64(bytes: &mut [u8], at: usize, v: u64) {
    bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Écrit l'archive.
pub fn build(spec: &Spec) -> Built {
    let mut out = Vec::new();
    let mut centrals = Vec::new();
    for e in &spec.entries {
        let method = if e.stored { 0 } else { 8 };
        let body = match &e.raw {
            Some(raw) => raw.clone(),
            None if e.stored => e.data.clone(),
            None => deflate(&e.data),
        };
        let crc = e.crc.unwrap_or_else(|| crc32(&e.data));
        let unpacked = e.unpacked.unwrap_or(e.data.len() as u32);
        let compressed = e.compressed.unwrap_or(body.len() as u32);
        let written_method = e.method.unwrap_or(method);
        let offset = out.len() as u32;
        let local_name = e.local_name.clone().unwrap_or_else(|| e.name.clone());
        u32le(&mut out, 0x0403_4b50);
        u16le(&mut out, 20);
        u16le(&mut out, e.flags);
        u16le(&mut out, e.local_method.unwrap_or(written_method));
        u16le(&mut out, 0);
        u16le(&mut out, 0x21);
        u32le(&mut out, crc);
        u32le(&mut out, compressed);
        u32le(&mut out, unpacked);
        u16le(&mut out, local_name.len() as u16);
        u16le(&mut out, 0);
        out.extend_from_slice(&local_name);
        out.extend_from_slice(&body);
        let mut c = Vec::new();
        u32le(&mut c, 0x0201_4b50);
        u16le(&mut c, 20);
        u16le(&mut c, 20);
        u16le(&mut c, e.flags);
        u16le(&mut c, written_method);
        u16le(&mut c, 0);
        u16le(&mut c, 0x21);
        u32le(&mut c, crc);
        u32le(&mut c, compressed);
        u32le(&mut c, unpacked);
        u16le(&mut c, e.name.len() as u16);
        u16le(&mut c, 0);
        u16le(&mut c, 0);
        u16le(&mut c, 0);
        u16le(&mut c, 0);
        u32le(&mut c, 0);
        u32le(&mut c, e.offset.unwrap_or(offset));
        c.extend_from_slice(&e.name);
        centrals.push(c);
    }
    let cd_offset = out.len();
    let mut count = 0u64;
    for (i, c) in centrals.iter().enumerate() {
        out.extend_from_slice(c);
        count += 1;
        if spec.duplicate_central.contains(&i) {
            out.extend_from_slice(c);
            count += 1;
        }
    }
    out.extend_from_slice(&spec.central_garbage);
    let cd_size = out.len() - cd_offset;
    let entries = spec.declared_entries.unwrap_or(count);
    let zip64 = spec.zip64 || entries >= 0xFFFF;
    let (mut zip64_record, mut locator) = (None, None);
    if zip64 {
        zip64_record = Some(out.len());
        u32le(&mut out, 0x0606_4b50);
        u64le(&mut out, 44);
        u16le(&mut out, 45);
        u16le(&mut out, 45);
        u32le(&mut out, 0);
        u32le(&mut out, 0);
        u64le(&mut out, entries);
        u64le(&mut out, entries);
        u64le(&mut out, cd_size as u64);
        u64le(&mut out, cd_offset as u64);
        locator = Some(out.len());
        u32le(&mut out, 0x0706_4b50);
        u32le(&mut out, 0);
        u64le(&mut out, zip64_record.unwrap() as u64);
        u32le(&mut out, 1);
    }
    let eocd = out.len();
    let short = if zip64 { 0xFFFF } else { entries as u16 };
    u32le(&mut out, 0x0605_4b50);
    u16le(&mut out, 0);
    u16le(&mut out, 0);
    u16le(&mut out, short);
    u16le(&mut out, short);
    u32le(&mut out, cd_size as u32);
    u32le(&mut out, if zip64 { 0xFFFF_FFFF } else { cd_offset as u32 });
    u16le(&mut out, 0);
    Built {
        bytes: out,
        cd_offset,
        cd_size,
        zip64_record,
        locator,
        eocd,
    }
}

/// Archive saine de `entries`.
pub fn zip_of(entries: Vec<ZEntry>) -> Vec<u8> {
    build(&Spec {
        entries,
        ..Spec::default()
    })
    .bytes
}
