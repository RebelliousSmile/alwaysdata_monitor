//! Archives `.tar.gz` construites par les tests de Friends-Of-Presta
//! (`vulns_friends_of_presta.rs`, `vulns_cms_sync.rs`), incluses par
//! `#[path]` : ustar, pax et GNU `L`, sans crate `tar`. Aucune archive n'est
//! commitée.

#![allow(dead_code)]

use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;

/// Racine de l'archive GitHub.
pub const ROOT: &str = "security-advisories-main";
/// Empreinte de commit inventée.
pub const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

/// Membre d'une archive de test.
#[derive(Debug, Clone)]
pub enum TEntry {
    File(String, Vec<u8>),
    Dir(String),
    Symlink(String, String),
    HardLink(String, String),
    Device(String),
    /// Fichier dont le nom passe par un en-tête pax `path`.
    PaxFile(String, Vec<u8>),
    /// Fichier dont le nom passe par un en-tête GNU `L`.
    GnuFile(String, Vec<u8>),
    /// Octets bruts ajoutés tels quels.
    Raw(Vec<u8>),
}

/// En-tête ustar, somme de contrôle calculée.
pub fn header(name: &[u8], size: u64, flag: u8, link: &[u8]) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = flag;
    h[157..157 + link.len().min(100)].copy_from_slice(&link[..link.len().min(100)]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    fix_checksum(&mut h);
    h
}

/// Recalcule la somme de contrôle d'un en-tête modifié.
pub fn fix_checksum(h: &mut [u8; 512]) {
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
}

/// Enregistrement pax `<longueur> <clé>=<valeur>\n`.
pub fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = 1 + key.len() + 1 + value.len() + 1;
    let mut len = body + 1;
    while len.to_string().len() + body != len {
        len = len.to_string().len() + body;
    }
    let mut out = format!("{len} {key}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

fn member(out: &mut Vec<u8>, name: &[u8], flag: u8, data: &[u8], link: &[u8]) {
    out.extend_from_slice(&header(name, data.len() as u64, flag, link));
    out.extend_from_slice(data);
    pad(out);
}

/// Archive tar (non compressée) : en-tête pax global (`comment`), membres,
/// deux blocs nuls et bourrage jusqu'à 10 240 octets.
pub fn tar(entries: &[TEntry], comment: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(c) = comment {
        member(
            &mut out,
            b"pax_global_header",
            b'g',
            &pax_record("comment", c.as_bytes()),
            b"",
        );
    }
    for e in entries {
        match e {
            TEntry::File(p, d) => member(&mut out, p.as_bytes(), b'0', d, b""),
            TEntry::Dir(p) => member(&mut out, p.as_bytes(), b'5', b"", b""),
            TEntry::Symlink(p, t) => member(&mut out, p.as_bytes(), b'2', b"", t.as_bytes()),
            TEntry::HardLink(p, t) => member(&mut out, p.as_bytes(), b'1', b"", t.as_bytes()),
            TEntry::Device(p) => member(&mut out, p.as_bytes(), b'3', b"", b""),
            TEntry::PaxFile(p, d) => {
                member(
                    &mut out,
                    b"PaxHeaders/x",
                    b'x',
                    &pax_record("path", p.as_bytes()),
                    b"",
                );
                member(&mut out, b"tronque", b'0', d, b"");
            }
            TEntry::GnuFile(p, d) => {
                let mut name = p.as_bytes().to_vec();
                name.push(0);
                member(&mut out, b"././@LongLink", b'L', &name, b"");
                member(&mut out, b"tronque", b'0', d, b"");
            }
            TEntry::Raw(bytes) => out.extend_from_slice(bytes),
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    while !out.len().is_multiple_of(10_240) {
        out.push(0);
    }
    out
}

/// Compression gzip d'un seul membre.
pub fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// Avis d'un dossier de fixtures, `(nom de fichier, contenu)`, triés.
pub fn posts(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

/// Archive du dépôt telle que GitHub la sert : racine unique, README,
/// `_layouts/`, image, et les avis dans `_posts/`.
pub fn repository(posts: &[(String, Vec<u8>)]) -> Vec<TEntry> {
    let mut entries = vec![
        TEntry::Dir(format!("{ROOT}/")),
        TEntry::File(format!("{ROOT}/README.md"), b"# Avis fictifs\n".to_vec()),
        TEntry::Dir(format!("{ROOT}/_layouts/")),
        TEntry::File(
            format!("{ROOT}/_layouts/post.html"),
            b"<html>{{ content }}</html>\n".to_vec(),
        ),
        TEntry::File(format!("{ROOT}/assets/logo.png"), vec![0x89; 3000]),
        TEntry::Dir(format!("{ROOT}/_posts/")),
    ];
    for (name, data) in posts {
        entries.push(TEntry::File(format!("{ROOT}/_posts/{name}"), data.clone()));
    }
    entries
}

/// `.tar.gz` du dépôt fictif.
pub fn archive(posts: &[(String, Vec<u8>)]) -> Vec<u8> {
    gz(&tar(&repository(posts), Some(REVISION)))
}
