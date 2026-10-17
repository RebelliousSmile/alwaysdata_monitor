//! Lecteur tar borné, en flux, pour l'archive `.tar.gz` de Friends-Of-Presta
//! (F2 n'en écrit pas ; aucune crate `tar` : le format est court à lire).
//!
//! - gzip **mono-membre** (`flate2::bufread::GzDecoder`) : un octet après la
//!   fin du premier membre est une erreur ;
//! - blocs de 512 octets, somme de contrôle vérifiée, tailles octales
//!   seulement (base 256 refusée) ;
//! - en-têtes pax (`x` local, `g` global) de 64 Kio au plus, enregistrements
//!   `<longueur> <clé>=<valeur>\n` validés ; clés `path` et `comment` lues,
//!   `size` refusée, autres ignorées ; GNU `L` lu pour le nom (4 096 octets) ;
//! - chemins normalisés : absolu, `..`, octet nul ou nom illisible → membre
//!   rendu sans chemin (l'appelant le compte `bad_archive_member`) ;
//! - chaque octet produit par le décompresseur (données des membres sautés
//!   et bourrage compris) compte dans le plafond décompressé ;
//! - fin : deux blocs nuls, puis bourrage nul de 10 240 octets au plus ;
//!   tout octet non nul après est une erreur.
//!
//! Rien n'est écrit sur le disque ; la mémoire est bornée par l'en-tête pax
//! et par le plus gros membre que l'appelant choisit de lire.

use std::io::{BufRead, Read};

use flate2::bufread::GzDecoder;

use crate::vulns::sync::SyncError;

const BLOCK: usize = 512;
/// En-tête pax au plus.
pub const MAX_PAX: u64 = 64 * 1024;
/// Nom d'un membre au plus (pax `path` ou GNU `L`).
pub const MAX_NAME: usize = 4096;
/// Bourrage nul admis après les deux blocs de fin.
pub const MAX_TRAILER: u64 = 10_240;

/// Plafonds d'une archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarLimits {
    /// En-têtes lus (membres et extensions).
    pub members: u64,
    /// Octets produits par le décompresseur.
    pub unpacked: u64,
}

/// Type d'un membre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// Lien symbolique ou dur.
    Link,
    /// Périphérique ou FIFO.
    Device,
    Other,
}

/// En-tête d'un membre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Chemin normalisé (`a/b/c`), `None` s'il est refusé.
    pub path: Option<String>,
    pub kind: Kind,
    pub size: u64,
}

fn format(what: &str) -> SyncError {
    SyncError::Format(format!("archive : {what}"))
}

/// Décompresseur compté.
struct Unpacked<R: BufRead> {
    gz: GzDecoder<R>,
    total: u64,
    limit: u64,
    over: bool,
}

impl<R: BufRead> Read for Unpacked<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.gz.read(buf)?;
        self.total += n as u64;
        if self.total > self.limit {
            self.over = true;
            return Err(std::io::Error::other("plafond décompressé"));
        }
        Ok(n)
    }
}

/// Lecteur d'archive.
pub struct TarReader<R: BufRead> {
    input: Unpacked<R>,
    limits: TarLimits,
    members: u64,
    /// Données du membre courant pas encore lues.
    data_left: u64,
    /// Bourrage du membre courant.
    pad: u64,
    comment: Option<String>,
    done: bool,
}

/// Bourrage jusqu'au bloc suivant.
fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// Champ numérique octal ; base 256 refusée.
fn octal(field: &[u8]) -> Result<u64, SyncError> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(format("taille en base 256"));
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|b| *b != 0)
        .collect::<Vec<u8>>();
    let text = std::str::from_utf8(&text).map_err(|_| format("champ numérique"))?;
    let text = text.trim_matches(' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| format("champ numérique"))
}

/// Chaîne terminée par un octet nul.
fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    &field[..end]
}

/// Chemin normalisé, ou `None` : absolu, `..`, octet nul, illisible, vide
/// ou trop long.
fn normalize(raw: &[u8]) -> Option<String> {
    if raw.len() > MAX_NAME || raw.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    if text.starts_with('/') || text.contains('\\') {
        return None;
    }
    let mut parts = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            p => parts.push(p),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Enregistrements pax : `(clé, valeur)`.
fn pax_records(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, SyncError> {
    let bad = || format("en-tête pax invalide");
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        // Bourrage nul final toléré.
        if data[pos..].iter().all(|b| *b == 0) {
            break;
        }
        let space = data[pos..]
            .iter()
            .take(20)
            .position(|b| *b == b' ')
            .ok_or_else(bad)?;
        let len: usize = std::str::from_utf8(&data[pos..pos + space])
            .ok()
            .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|d| d.parse().ok())
            .ok_or_else(bad)?;
        if len == 0 || len <= space + 1 || pos + len > data.len() {
            return Err(bad());
        }
        let record = &data[pos + space + 1..pos + len];
        let (body, last) = record.split_at(record.len() - 1);
        if last != b"\n" {
            return Err(bad());
        }
        let eq = body.iter().position(|b| *b == b'=').ok_or_else(bad)?;
        let key = std::str::from_utf8(&body[..eq]).map_err(|_| bad())?;
        out.push((key.to_owned(), body[eq + 1..].to_vec()));
        pos += len;
    }
    Ok(out)
}

impl<R: BufRead> TarReader<R> {
    pub fn new(input: R, limits: TarLimits) -> Self {
        Self {
            input: Unpacked {
                gz: GzDecoder::new(input),
                total: 0,
                limit: limits.unpacked,
                over: false,
            },
            limits,
            members: 0,
            data_left: 0,
            pad: 0,
            comment: None,
            done: false,
        }
    }

    /// Commentaire de l'en-tête pax global (empreinte du commit chez
    /// GitHub).
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Octets décompressés jusqu'ici.
    pub fn unpacked(&self) -> u64 {
        self.input.total
    }

    fn io_error(&self, err: &std::io::Error) -> SyncError {
        if self.input.over {
            SyncError::TooLarge {
                what: "archive décompressée",
            }
        } else if err.kind() == std::io::ErrorKind::UnexpectedEof {
            format("archive tronquée")
        } else {
            format("gzip corrompu ou tronqué")
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SyncError> {
        match self.input.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.io_error(&e)),
        }
    }

    /// Lit et jette `n` octets.
    fn skip(&mut self, n: u64) -> Result<(), SyncError> {
        let mut left = n;
        let mut buf = [0u8; 8192];
        while left > 0 {
            let chunk = left.min(buf.len() as u64) as usize;
            self.read_exact(&mut buf[..chunk])?;
            left -= chunk as u64;
        }
        Ok(())
    }

    fn read_vec(&mut self, n: u64) -> Result<Vec<u8>, SyncError> {
        let mut data = vec![0u8; usize::try_from(n).map_err(|_| format("taille"))?];
        self.read_exact(&mut data)?;
        Ok(data)
    }

    /// Données d'une extension (pax, GNU `L`), bourrage compris.
    fn extension(&mut self, size: u64) -> Result<Vec<u8>, SyncError> {
        let data = self.read_vec(size)?;
        self.skip(padding(size))?;
        Ok(data)
    }

    /// Fin d'archive : second bloc nul, bourrage nul borné, fin du flux
    /// gzip, aucun second membre.
    fn finish(&mut self) -> Result<(), SyncError> {
        let mut block = [0u8; BLOCK];
        self.read_exact(&mut block)?;
        if block.iter().any(|b| *b != 0) {
            return Err(format("bloc nul de fin isolé"));
        }
        let mut trailer = 0u64;
        let mut buf = [0u8; 4096];
        loop {
            let n = match self.input.read(&mut buf) {
                Ok(n) => n,
                Err(e) => return Err(self.io_error(&e)),
            };
            if n == 0 {
                break;
            }
            trailer += n as u64;
            if trailer > MAX_TRAILER || buf[..n].iter().any(|b| *b != 0) {
                return Err(format("données après la fin de l'archive"));
            }
        }
        let rest = self
            .input
            .gz
            .get_mut()
            .fill_buf()
            .map_err(|_| format("lecture après le flux gzip"))?;
        if !rest.is_empty() {
            return Err(format("second membre gzip"));
        }
        self.done = true;
        Ok(())
    }

    /// Membre suivant ; `None` à la fin de l'archive. Les données du membre
    /// précédent non lues sont sautées (et comptées).
    pub fn next_member(&mut self) -> Result<Option<Member>, SyncError> {
        if self.done {
            return Ok(None);
        }
        let pending = self.data_left + self.pad;
        self.data_left = 0;
        self.pad = 0;
        self.skip(pending)?;
        let mut long_name: Option<Option<String>> = None;
        loop {
            let mut header = [0u8; BLOCK];
            self.read_exact(&mut header)?;
            if header.iter().all(|b| *b == 0) {
                self.finish()?;
                return Ok(None);
            }
            self.members += 1;
            if self.members > self.limits.members {
                return Err(SyncError::TooLarge {
                    what: "membres de l'archive",
                });
            }
            let stored = octal(&header[148..156])?;
            let sum: u64 = header
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    if (148..156).contains(&i) {
                        32
                    } else {
                        u64::from(*b)
                    }
                })
                .sum();
            if sum != stored {
                return Err(format("somme de contrôle d'en-tête fausse"));
            }
            let size = octal(&header[124..136])?;
            let flag = header[156];
            match flag {
                b'x' | b'g' => {
                    if size > MAX_PAX {
                        return Err(format("en-tête pax de plus de 64 Kio"));
                    }
                    let data = self.extension(size)?;
                    for (key, value) in pax_records(&data)? {
                        match (flag, key.as_str()) {
                            (_, "size") => return Err(format("clé pax size")),
                            (b'x', "path") => long_name = Some(normalize(&value)),
                            (b'g', "comment") => {
                                self.comment = String::from_utf8(value).ok();
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
                b'L' => {
                    if size > MAX_NAME as u64 {
                        self.skip(size + padding(size))?;
                        long_name = Some(None);
                    } else {
                        let data = self.extension(size)?;
                        long_name = Some(normalize(cstr(&data)));
                    }
                    continue;
                }
                b'K' => {
                    self.skip(size + padding(size))?;
                    continue;
                }
                _ => {}
            }
            let path = match long_name.take() {
                Some(path) => path,
                None => {
                    let name = cstr(&header[0..100]);
                    let prefix = cstr(&header[345..500]);
                    if &header[257..263] == b"ustar\0" && !prefix.is_empty() {
                        let mut full = prefix.to_vec();
                        full.push(b'/');
                        full.extend_from_slice(name);
                        normalize(&full)
                    } else {
                        normalize(name)
                    }
                }
            };
            let kind = match flag {
                b'0' | 0 | b'7' => Kind::File,
                b'5' => Kind::Dir,
                b'1' | b'2' => Kind::Link,
                b'3' | b'4' | b'6' => Kind::Device,
                _ => Kind::Other,
            };
            // Un lien, un dossier ou un périphérique n'a pas de données.
            let data = if matches!(kind, Kind::File | Kind::Other) {
                size
            } else {
                0
            };
            self.data_left = data;
            self.pad = padding(data);
            return Ok(Some(Member { path, kind, size }));
        }
    }

    /// Données du membre courant s'il fait `max` octets au plus ; sinon
    /// `None` (elles seront sautées et comptées).
    pub fn read_data(&mut self, max: u64) -> Result<Option<Vec<u8>>, SyncError> {
        if self.data_left > max {
            return Ok(None);
        }
        let data = self.read_vec(self.data_left)?;
        self.data_left = 0;
        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_normalized_or_refused() {
        assert_eq!(normalize(b"a/./b//c.md").as_deref(), Some("a/b/c.md"));
        for bad in [
            &b"/etc/x"[..],
            b"a/../x.md",
            b"..",
            b"",
            b"a\0b",
            b"a\\b",
            &[0xff],
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
        assert_eq!(normalize(&vec![b'a'; MAX_NAME + 1]), None);
    }

    #[test]
    fn pax_records_are_checked() {
        assert_eq!(
            pax_records(b"12 path=a/b\n").unwrap(),
            [("path".to_owned(), b"a/b".to_vec())]
        );
        for bad in [
            &b"0 path=a\n"[..],
            b"99 path=a\n",
            b"11 path=a/b\n",
            b"x path=a\n",
            b"5 a\n",
        ] {
            assert!(pax_records(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn octal_fields() {
        assert_eq!(octal(b"00000001750\0").unwrap(), 1000);
        assert_eq!(octal(b"      \0").unwrap(), 0);
        assert!(octal(&[0x80, 0, 0, 1]).is_err());
        assert!(octal(b"9\0").is_err());
    }
}
