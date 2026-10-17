//! Secrets lus par le code (inventaire « Secrets » de `docs/hebergement.md`)
//! : une seule règle de droits pour les clés du canal de commandes
//! (`command/key.rs`) et le jeton Wordfence (#17).
//!
//! Un secret n'est lu que s'il est un fichier ordinaire en 0600 au
//! propriétaire du processus, dans un dossier en 0700 au même propriétaire,
//! sans suivre de lien symbolique ; la vérification porte sur le fichier
//! ouvert. Hors Unix (tests et reprise locale sous Windows), les droits ne se
//! lisent pas : seuls le type de fichier et le contenu sont vérifiés.
//!
//! Aucune erreur ne cite le contenu d'un secret.

use std::fmt;
use std::io::Read;
use std::path::Path;

use ureq::http::HeaderValue;

/// Octets lus au plus dans un fichier de jeton.
pub const MAX_TOKEN_FILE: u64 = 1024;
/// Longueur d'un jeton, en caractères.
pub const TOKEN_CHARS: std::ops::RangeInclusive<usize> = 16..=512;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("{path} : {reason}")]
    Unsafe { path: String, reason: String },
    #[error("{path} : {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} : jeton refusé ({reason})")]
    Malformed { path: String, reason: &'static str },
}

/// Ouvre un secret en lecture en vérifiant ses droits et ceux de son
/// dossier, sans suivre de lien symbolique.
pub fn open_safely(path: &Path) -> Result<std::fs::File, SecretError> {
    open_with(path, false)
}

fn open_with(path: &Path, nonblocking: bool) -> Result<std::fs::File, SecretError> {
    let shown = path.display().to_string();
    check_parent(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let extra = if nonblocking { libc::O_NONBLOCK } else { 0 };
        options.custom_flags(libc::O_NOFOLLOW | extra);
    }
    #[cfg(not(unix))]
    let _ = nonblocking;
    let file = options.open(path).map_err(|source| SecretError::Io {
        path: shown.clone(),
        source,
    })?;
    let meta = file.metadata().map_err(|source| SecretError::Io {
        path: shown.clone(),
        source,
    })?;
    if !meta.is_file() {
        return Err(SecretError::Unsafe {
            path: shown,
            reason: "pas un fichier".into(),
        });
    }
    check_mode(&shown, &meta, 0o077, "600")?;
    Ok(file)
}

/// Le dossier d'un secret : un vrai dossier (pas un lien), en 0700 au
/// propriétaire du processus.
pub fn check_parent(path: &Path) -> Result<(), SecretError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let shown = parent.display().to_string();
    let meta = std::fs::symlink_metadata(parent).map_err(|source| SecretError::Io {
        path: shown.clone(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(SecretError::Unsafe {
            path: shown,
            reason: "le dossier de la clé n'est pas un dossier (lien symbolique ?)".into(),
        });
    }
    check_mode(&shown, &meta, 0o077, "700")
}

#[cfg(unix)]
fn check_mode(
    shown: &str,
    meta: &std::fs::Metadata,
    forbidden: u32,
    expected: &str,
) -> Result<(), SecretError> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o777;
    if mode & forbidden != 0 {
        return Err(SecretError::Unsafe {
            path: shown.to_owned(),
            reason: format!("mode {mode:o} : {expected} attendu (chmod {expected})"),
        });
    }
    // SAFETY: geteuid n'a ni argument ni effet de bord, et ne peut échouer.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(SecretError::Unsafe {
            path: shown.to_owned(),
            reason: format!(
                "appartient à l'uid {}, pas à l'uid {euid} du veilleur",
                meta.uid()
            ),
        });
    }
    Ok(())
}

/// Hors Unix (tests et reprise locale sous Windows), les droits ne se
/// lisent pas : rien n'est vérifié.
#[cfg(not(unix))]
fn check_mode(
    _shown: &str,
    _meta: &std::fs::Metadata,
    _forbidden: u32,
    _expected: &str,
) -> Result<(), SecretError> {
    Ok(())
}

/// Jeton d'une API : lisible par [`Token::expose`] seulement, jamais par
/// `Debug` (`Token(***)`), sans `Display` ni `Clone`.
pub struct Token(String);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(***)")
    }
}

impl Token {
    /// Le jeton en clair, pour l'en-tête d'une requête.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `Authorization: Bearer <jeton>`, valeur marquée sensible (jamais
    /// écrite par les traces HTTP).
    pub fn header(&self) -> HeaderValue {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.0))
            .expect("grammaire du jeton : ASCII imprimable");
        value.set_sensitive(true);
        value
    }
}

/// Grammaire d'un jeton : `[A-Za-z0-9._~+/=-]{16,512}`.
pub fn valid_token(raw: &str) -> bool {
    TOKEN_CHARS.contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b))
}

/// Lit un jeton : fichier ordinaire exigé avant l'ouverture (une FIFO ou un
/// périphérique est refusé sans bloquer), ouverture sans suivre de lien et
/// non bloquante, droits vérifiés sur le fichier ouvert, 1 Kio lu au plus,
/// `\r` et `\n` finaux retirés, puis la grammaire.
pub fn read_token(path: &Path) -> Result<Token, SecretError> {
    let shown = path.display().to_string();
    let meta = std::fs::symlink_metadata(path).map_err(|source| SecretError::Io {
        path: shown.clone(),
        source,
    })?;
    if !meta.file_type().is_file() {
        return Err(SecretError::Unsafe {
            path: shown,
            reason: "pas un fichier ordinaire (lien, FIFO ou périphérique ?)".into(),
        });
    }
    let file = open_with(path, true)?;
    let mut raw = Vec::new();
    file.take(MAX_TOKEN_FILE + 1)
        .read_to_end(&mut raw)
        .map_err(|source| SecretError::Io {
            path: shown.clone(),
            source,
        })?;
    if raw.len() as u64 > MAX_TOKEN_FILE {
        return Err(SecretError::Malformed {
            path: shown,
            reason: "fichier de plus de 1 Kio",
        });
    }
    while raw.last().is_some_and(|b| matches!(b, b'\r' | b'\n')) {
        raw.pop();
    }
    match String::from_utf8(raw) {
        Ok(text) if valid_token(&text) => Ok(Token(text)),
        _ => Err(SecretError::Malformed {
            path: shown,
            reason: "[A-Za-z0-9._~+/=-]{16,512} attendu",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_never_show_in_debug() {
        let token = Token("abcdefghijklmnop0123".into());
        assert_eq!(format!("{token:?}"), "Token(***)");
        assert!(token.header().is_sensitive());
        assert_eq!(
            token.header().to_str().unwrap(),
            "Bearer abcdefghijklmnop0123"
        );
    }

    #[test]
    fn token_grammar() {
        assert!(valid_token(&"a".repeat(16)));
        assert!(valid_token(&"A9._~+/=-".repeat(2)));
        assert!(valid_token(&"a".repeat(512)));
        for bad in [
            "a".repeat(15),
            "a".repeat(513),
            format!("{} b", "a".repeat(16)),
            format!("{}\nb", "a".repeat(16)),
            "é".repeat(16),
        ] {
            assert!(!valid_token(&bad), "{bad:?}");
        }
    }
}
