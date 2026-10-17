//! Clés Ed25519 du veilleur pour le canal de commandes : une clé de commandes
//! (signe les réponses de `/r/v1/commands`, lue par `serve` seul) et une clé
//! d'audit (signe le journal, lue par `serve`, `tick` et la CLI). Une clé par
//! usage (`docs/protocole-agent.md`, « Une clé par usage »).
//!
//! Fichier : la graine de 32 octets en base64 standard, sur une ligne. Lu
//! seulement s'il est en 0600 au propriétaire du processus, dans un dossier en
//! 0700 au même propriétaire, sans suivre de lien symbolique (règles de
//! `secret.rs`). Créé en création exclusive : une clé n'est jamais écrasée.
//!
//! Chaque signature porte un préfixe de domaine : une signature faite pour un
//! usage ne vaut jamais pour un autre.

use std::io::{Read, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::secret::{SecretError, check_parent, open_safely};

/// Retrait de l'agent, signé par sa clé de rapport.
pub const DOMAIN_PULL: &[u8] = b"vigie-pull-v1\n";
/// Lot de logs de l'agent (`/r/v1/logs`), signé par sa clé de rapport.
pub const DOMAIN_LOGS: &[u8] = b"vigie-logs-v1\n";
/// Réponse de `/r/v1/commands`, signée par la clé de commandes.
pub const DOMAIN_COMMANDS: &[u8] = b"vigie-commands-v1\n";
/// Entrée du journal d'audit, signée par la clé d'audit.
pub const DOMAIN_AUDIT: &[u8] = b"vigie-audit-v1\n";
/// Preuve de possession de la nouvelle clé d'un agent (`rotate-key`).
pub const DOMAIN_ROTATE: &[u8] = b"vigie-rotate-v1\n";
/// Inventaire des composants de l'agent (`/r/v1/inventory`, issue #19),
/// signé par sa clé de rapport.
pub const DOMAIN_INVENTORY: &[u8] = b"vigie-inventory-v1\n";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{path} : {reason}")]
    Unsafe { path: String, reason: String },
    #[error("{path} : {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} : clé illisible (graine Ed25519 de 32 octets en base64 attendue)")]
    Malformed { path: String },
    #[error("{path} existe déjà : une clé n'est jamais écrasée")]
    Exists { path: String },
}

/// Droits et lecture : règles communes de `secret.rs`.
impl From<SecretError> for KeyError {
    fn from(err: SecretError) -> Self {
        match err {
            SecretError::Unsafe { path, reason } => Self::Unsafe { path, reason },
            SecretError::Io { path, source } => Self::Io { path, source },
            SecretError::Malformed { path, .. } => Self::Malformed { path },
        }
    }
}

/// Message signé : préfixe de domaine puis les parties, sans séparateur
/// ajouté (les appelants placent leurs `\n`).
pub fn message(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = domain.to_vec();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// Signature base64 de `message(domain, parts)`.
pub fn sign(key: &SigningKey, domain: &[u8], parts: &[&[u8]]) -> String {
    STANDARD.encode(key.sign(&message(domain, parts)).to_bytes())
}

/// Vérification stricte (comme libsodium : signatures malléables et clés de
/// petit ordre refusées) d'une signature base64.
pub fn verify(key: &VerifyingKey, domain: &[u8], parts: &[&[u8]], signature: &str) -> bool {
    let Ok(bytes) = STANDARD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify_strict(&message(domain, parts), &signature)
        .is_ok()
        && key.verify(&message(domain, parts), &signature).is_ok()
}

/// Lit une clé privée en vérifiant ses droits.
pub fn load(path: &Path) -> Result<SigningKey, KeyError> {
    let shown = path.display().to_string();
    let mut file = open_safely(path)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|source| KeyError::Io {
            path: shown.clone(),
            source,
        })?;
    let seed = STANDARD
        .decode(raw.trim())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(KeyError::Malformed { path: shown })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Crée une clé neuve, en création exclusive et en 0600, et rend sa clé
/// publique. Le dossier doit exister et respecter les mêmes règles qu'à la
/// lecture.
pub fn create(path: &Path) -> Result<VerifyingKey, KeyError> {
    let shown = path.display().to_string();
    check_parent(path)?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| KeyError::Unsafe {
        path: shown.clone(),
        reason: format!("tirage aléatoire impossible : {err}"),
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            KeyError::Exists {
                path: shown.clone(),
            }
        } else {
            KeyError::Io {
                path: shown.clone(),
                source,
            }
        }
    })?;
    let key = SigningKey::from_bytes(&seed);
    let written = file
        .write_all(format!("{}\n", STANDARD.encode(seed)).as_bytes())
        .and_then(|()| file.sync_all());
    seed.fill(0);
    if let Err(source) = written {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(KeyError::Io {
            path: shown,
            source,
        });
    }
    Ok(key.verifying_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dossier temporaire en 0700, comme le veut la règle.
    pub(crate) fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
        }
        dir
    }

    #[test]
    fn a_created_key_reads_back_and_is_never_overwritten() {
        let dir = private_dir();
        let path = dir.path().join("commands.key");
        let public = create(&path).expect("création");
        let key = load(&path).expect("lecture");
        assert_eq!(key.verifying_key(), public);
        assert!(matches!(create(&path), Err(KeyError::Exists { .. })));
        assert_eq!(load(&path).unwrap().verifying_key(), public);
    }

    #[test]
    fn signatures_are_bound_to_their_domain() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key();
        let sig = sign(&key, DOMAIN_COMMANDS, &[b"123\n", b"{}"]);
        assert!(verify(&public, DOMAIN_COMMANDS, &[b"123\n", b"{}"], &sig));
        assert!(!verify(&public, DOMAIN_AUDIT, &[b"123\n", b"{}"], &sig));
        assert!(!verify(&public, DOMAIN_COMMANDS, &[b"124\n", b"{}"], &sig));
        assert!(!verify(
            &public,
            DOMAIN_COMMANDS,
            &[b"123\n", b"{}"],
            "pas du base64"
        ));
    }

    /// Matrice des six domaines et d'une signature sans préfixe (celle d'un
    /// rapport) : chaque signature ne vérifie que sous son propre domaine.
    #[test]
    fn each_domain_verifies_only_its_own_signatures() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let public = key.verifying_key();
        let domains: [&[u8]; 7] = [
            DOMAIN_PULL,
            DOMAIN_LOGS,
            DOMAIN_COMMANDS,
            DOMAIN_AUDIT,
            DOMAIN_ROTATE,
            DOMAIN_INVENTORY,
            b"",
        ];
        let body: &[u8] = br#"{"v":1}"#;
        for (i, signed) in domains.iter().enumerate() {
            let sig = sign(&key, signed, &[body]);
            for (j, checked) in domains.iter().enumerate() {
                assert_eq!(
                    verify(&public, checked, &[body], &sig),
                    i == j,
                    "signé sous {i}, vérifié sous {j}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("audit.key");
        create(&path).expect("création");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&path), Err(KeyError::Unsafe { .. })));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&path).is_ok());

        // Dossier ouvert aux autres.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(load(&path), Err(KeyError::Unsafe { .. })));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // Lien symbolique vers la clé : jamais suivi.
        let link = dir.path().join("lien.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load(&link).is_err());

        // Contenu illisible.
        let bad = dir.path().join("bad.key");
        std::fs::write(&bad, "xyz\n").unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load(&bad), Err(KeyError::Malformed { .. })));
    }
}
