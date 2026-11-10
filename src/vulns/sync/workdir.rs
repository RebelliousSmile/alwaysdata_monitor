//! Dossier de travail d'une source : `<dossier de la base>/vulns-work/<source>/`,
//! 0700, propriété du veilleur. Seul le dump compressé y est écrit (fichier
//! 0600 créé en `create_new`) ; rien n'est jamais extrait sur le disque.
//!
//! Le dossier est vidé à la préparation (passage interrompu) et à la fin
//! (`Drop`), par le seul détenteur du bail de la source : le moteur ne le
//! prépare qu'après `Load::begin`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use super::SyncError;

/// Réserve d'espace libre gardée en plus de ce qu'un chargement écrit : un
/// disque plein casserait aussi `serve` et `tick`.
pub const DISK_RESERVE: u64 = 1024 * 1024 * 1024;

/// Dossier de travail d'une source, vidé à sa destruction.
#[derive(Debug)]
pub struct WorkDir {
    dir: PathBuf,
    /// Espace libre imposé par les tests, à la place de `statvfs`.
    free_space_override: Option<u64>,
}

impl WorkDir {
    /// Crée (0700) ou reprend le dossier de la source sous `base_dir`, le
    /// dossier de la base, et le vide. Refuse un lien symbolique, un fichier
    /// à la place du dossier, ou (Unix) un dossier d'un autre propriétaire.
    pub fn prepare(base_dir: &Path, source: &str) -> Result<Self, SyncError> {
        let valid = !source.is_empty()
            && source.len() <= 64
            && source
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(SyncError::Io("identifiant de source invalide".into()));
        }
        let root = base_dir.join("vulns-work");
        private_dir(&root)?;
        let dir = root.join(source);
        private_dir(&dir)?;
        let work = Self {
            dir,
            free_space_override: None,
        };
        work.clear()
            .map_err(|e| SyncError::io("dossier de travail", &e))?;
        Ok(work)
    }

    /// Espace libre imposé (tests).
    pub fn with_free_space(mut self, free: Option<u64>) -> Self {
        self.free_space_override = free;
        self
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Crée un fichier neuf (0600 sous Unix) ; un fichier ou un lien déjà
    /// présent sous ce nom fait échouer la création.
    pub fn create_file(&self, name: &str) -> Result<(File, PathBuf), SyncError> {
        if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
            return Err(SyncError::Io("nom de fichier de travail invalide".into()));
        }
        let path = self.dir.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .map_err(|e| SyncError::io("création du dump", &e))?;
        Ok((file, path))
    }

    /// Espace libre du volume, en octets : `f_bavail × f_frsize` (ce qu'un
    /// utilisateur non root peut écrire). `None` hors Unix : pas de contrôle.
    pub fn free_space(&self) -> Option<u64> {
        self.free_space_override.or_else(|| statvfs_free(&self.dir))
    }

    /// Refuse si l'espace libre est inférieur à `needed` plus la réserve.
    pub fn ensure_space(&self, needed: u64) -> Result<(), SyncError> {
        let needed = needed.saturating_add(DISK_RESERVE);
        match self.free_space() {
            Some(available) if available < needed => Err(SyncError::Disk { needed, available }),
            _ => Ok(()),
        }
    }

    /// Supprime les fichiers du dossier (jamais en suivant un lien : un lien
    /// est retiré lui-même). Un sous-dossier, qui ne vient pas du veilleur,
    /// est laissé et journalisé.
    fn clear(&self) -> io::Result<()> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                log::warn!(
                    "dossier de travail {} : sous-dossier inattendu laissé en place",
                    self.dir.display()
                );
                continue;
            }
            fs::remove_file(entry.path())?;
        }
        Ok(())
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if let Err(err) = self.clear() {
            log::warn!("dossier de travail {} non vidé : {err}", self.dir.display());
        }
    }
}

/// Crée le dossier en 0700, ou vérifie celui qui existe : ni lien
/// symbolique, ni fichier, ni (Unix) autre propriétaire ; droits ramenés à
/// 0700.
fn private_dir(dir: &Path) -> Result<(), SyncError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(SyncError::Io(
                    "dossier de travail : lien symbolique ou fichier refusé".into(),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                // SAFETY: geteuid n'a ni argument ni effet de bord, et ne peut échouer.
                let euid = unsafe { libc::geteuid() };
                if meta.uid() != euid {
                    return Err(SyncError::Io(
                        "dossier de travail : autre propriétaire".into(),
                    ));
                }
                if meta.mode() & 0o777 != 0o700 {
                    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                        .map_err(|e| SyncError::io("dossier de travail", &e))?;
                }
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // `mut` ne sert qu'au mode Unix ci-dessous.
            #[cfg_attr(not(unix), allow(unused_mut))]
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(dir)
                .map_err(|e| SyncError::io("dossier de travail", &e))
        }
        Err(err) => Err(SyncError::io("dossier de travail", &err)),
    }
}

#[cfg(unix)]
// Types des champs de `statvfs` propres à chaque plateforme.
#[allow(clippy::unnecessary_cast)]
fn statvfs_free(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `stat` est une structure C sans invariant, remplie par
    // statvfs ; `path` est une chaîne C valide qui vit pendant l'appel.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut stat) };
    if rc != 0 {
        return None;
    }
    Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

#[cfg(not(unix))]
fn statvfs_free(_dir: &Path) -> Option<u64> {
    None
}
