//! Lecture des lockfiles d'un projet (issue #20, `docs/inventaire.md`) :
//! `composer.lock`, `package-lock.json` v2/v3, `pnpm-lock.yaml` `'6.0'` et
//! `'9.0'`, `yarn.lock` v1 et berry, `Cargo.lock` 3 et 4. Formats fermés :
//! reconnus par le nom du fichier, puis par leur version déclarée ; tout
//! autre nom ou version est refusé.
//!
//! Chaque lecteur rend des [`Entry`] brutes (avant la grammaire purl, appliquée
//! par `build.rs`), le nombre de dépendances hors registre (comptées dans
//! `skipped`) et le nombre de membres du projet ignorés (ni émis, ni
//! comptés). Une erreur est une raison fixe ([`LockError`]) : jamais un octet
//! du fichier. Bornes : 32 Mio, ligne de 64 Kio, 200 000 entrées, profondeur
//! JSON de `serde_json` (128). Aucun lecteur ne panique : le fuzz de
//! `tests/inventory_lockfiles.rs` le vérifie.

pub mod cargo;
pub mod composer;
pub mod lines;
pub mod npm;
pub mod pnpm;
pub mod yarn;

use std::fmt;
use std::io::Read;
use std::path::Path;

use crate::vulns::purl::PurlType;

/// Taille maximale d'un lockfile, en octets.
pub const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;
/// Longueur maximale d'une ligne, en octets.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Entrées (paquets) au plus dans un lockfile.
pub const MAX_ENTRIES: usize = 200_000;

/// Format de lockfile, reconnu par le nom du fichier seul.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Composer,
    Npm,
    Pnpm,
    Yarn,
    Cargo,
}

impl Kind {
    pub const ALL: [Self; 5] = [
        Self::Composer,
        Self::Npm,
        Self::Pnpm,
        Self::Yarn,
        Self::Cargo,
    ];

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Composer => "composer.lock",
            Self::Npm => "package-lock.json",
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Yarn => "yarn.lock",
            Self::Cargo => "Cargo.lock",
        }
    }

    /// `None` pour tout autre nom : format inconnu.
    pub fn from_file_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.file_name() == name)
    }

    /// Famille npm : décrit un `node_modules`.
    pub fn is_npm_family(self) -> bool {
        match self {
            Self::Npm | Self::Pnpm | Self::Yarn => true,
            Self::Composer | Self::Cargo => false,
        }
    }
}

/// Paquet lu dans un lockfile, avant la grammaire purl (`build.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub ecosystem: PurlType,
    /// Vendor Composer, scope npm (`@scope`) ; `None` sinon.
    pub namespace: Option<String>,
    pub name: String,
    /// Version brute, vide si inconnue.
    pub version: String,
    /// Dépendance de développement, là où le format le dit.
    pub dev: bool,
}

impl Entry {
    /// Paquet npm de nom complet `name` (`@scope/nom` ou `nom`).
    pub fn npm(name: &str, version: &str, dev: bool) -> Self {
        let (namespace, short) = match name.strip_prefix('@').and(name.split_once('/')) {
            Some((scope, short)) => (Some(scope.to_owned()), short),
            None => (None, name),
        };
        Self {
            ecosystem: PurlType::Npm,
            namespace,
            name: short.to_owned(),
            version: version.to_owned(),
            dev,
        }
    }
}

/// Contenu utile d'un lockfile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    pub entries: Vec<Entry>,
    /// Dépendances hors registre (git, `file:`, archive, chemin, autre
    /// registre) : non émises, comptées dans `skipped`.
    pub offregistry: usize,
    /// Membres du projet (workspaces, liens, paquets étrangers à
    /// l'arbre) : ni émis, ni comptés ; affichés seulement.
    pub ignored: usize,
}

impl Parsed {
    /// Ajoute une entrée, dans la borne de [`MAX_ENTRIES`].
    fn push(&mut self, entry: Entry) -> Result<(), LockError> {
        self.count()?;
        self.entries.push(entry);
        Ok(())
    }

    fn offregistry(&mut self) -> Result<(), LockError> {
        self.count()?;
        self.offregistry += 1;
        Ok(())
    }

    fn ignore(&mut self) -> Result<(), LockError> {
        self.count()?;
        self.ignored += 1;
        Ok(())
    }

    fn count(&self) -> Result<(), LockError> {
        if self.entries.len() + self.offregistry + self.ignored >= MAX_ENTRIES {
            return Err(LockError::TooManyEntries);
        }
        Ok(())
    }
}

/// Refus d'un lockfile, à raison fixe : aucun octet du fichier n'y est
/// recopié (seulement un numéro de ligne).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Nom de fichier hors des cinq connus.
    UnknownFormat,
    /// Version de format absente ou non gérée.
    UnsupportedVersion,
    /// JSON ou TOML illisible, ou type inattendu.
    Unreadable,
    /// Structure inattendue à cette ligne (1 pour la première).
    Structure {
        line: usize,
    },
    TooLarge,
    TooManyEntries,
    /// Lecture du fichier en échec, ou UTF-8 invalide.
    Io,
    /// Plusieurs lockfiles npm dans un même dossier (noms connus seulement).
    SeveralNpm {
        dir: String,
        names: Vec<&'static str>,
        explicit: bool,
    },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat => f.write_str("format inconnu"),
            Self::UnsupportedVersion => f.write_str("version de format non gérée"),
            Self::Unreadable => f.write_str("JSON ou TOML illisible"),
            Self::Structure { line } => write!(f, "structure inattendue ligne {line}"),
            Self::TooLarge => f.write_str("trop gros (32 Mio, ligne de 64 Kio au plus)"),
            Self::TooManyEntries => f.write_str("trop d'entrées (200 000 au plus)"),
            Self::Io => f.write_str("illisible (lecture ou UTF-8)"),
            Self::SeveralNpm {
                dir,
                names,
                explicit: false,
            } => write!(
                f,
                "plusieurs lockfiles npm dans {dir} ({}) : en désigner un par --lockfile",
                names.join(", ")
            ),
            Self::SeveralNpm {
                dir,
                names,
                explicit: true,
            } => write!(
                f,
                "deux lockfiles npm du même dossier {dir} ({}) : n'en garder qu'un",
                names.join(", ")
            ),
        }
    }
}

impl std::error::Error for LockError {}

/// Lecture bornée : taille lue par `metadata`, puis lecture limitée (un
/// fichier qui grossit entre-temps est refusé aussi), UTF-8 valide.
pub fn read_bounded(path: &Path) -> Result<String, LockError> {
    let file = std::fs::File::open(path).map_err(|_| LockError::Io)?;
    let len = file.metadata().map_err(|_| LockError::Io)?.len();
    if len > MAX_LOCKFILE_BYTES {
        return Err(LockError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(MAX_LOCKFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LockError::Io)?;
    if bytes.len() as u64 > MAX_LOCKFILE_BYTES {
        return Err(LockError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| LockError::Io)
}

/// Lit le texte d'un lockfile du format `kind`.
pub fn parse(kind: Kind, text: &str) -> Result<Parsed, LockError> {
    if text.len() as u64 > MAX_LOCKFILE_BYTES
        || text.split('\n').any(|line| line.len() > MAX_LINE_BYTES)
    {
        return Err(LockError::TooLarge);
    }
    match kind {
        Kind::Composer => composer::parse(text),
        Kind::Npm => npm::parse(text),
        Kind::Pnpm => pnpm::parse(text),
        Kind::Yarn => yarn::parse(text),
        Kind::Cargo => cargo::parse(text),
    }
}

/// Un lockfile npm par dossier, sans priorité : deux gestionnaires dans un
/// même dossier décrivent le même `node_modules`, et choisir à la place de
/// l'exploitant pourrait lire celui qui n'est pas installé. `lockfiles` :
/// chemins relatifs au projet, séparateur `/` ; `explicit` : désignés par
/// `--lockfile` (sinon trouvés à la racine).
pub fn one_npm_lockfile_per_dir(lockfiles: &[String], explicit: bool) -> Result<(), LockError> {
    let mut by_dir: std::collections::BTreeMap<&str, Vec<&'static str>> = Default::default();
    for path in lockfiles {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        if let Some(kind) = Kind::from_file_name(name).filter(|k| k.is_npm_family()) {
            by_dir.entry(dir).or_default().push(kind.file_name());
        }
    }
    match by_dir.into_iter().find(|(_, names)| names.len() > 1) {
        None => Ok(()),
        Some((dir, names)) => Err(LockError::SeveralNpm {
            dir: if dir.is_empty() {
                "la racine du projet".to_owned()
            } else {
                dir.to_owned()
            },
            names,
            explicit,
        }),
    }
}

/// Raison fixe d'une erreur de `serde_json` : son texte recopie des octets
/// lus, il n'est jamais formaté.
fn json_error(_: serde_json::Error) -> LockError {
    LockError::Unreadable
}

/// Clés d'un objet JSON dans l'ordre du fichier (l'ordre de troncature suit
/// celui du lockfile), sans `preserve_order`.
struct Ordered<V>(Vec<(String, V)>);

impl<'de, V: serde::Deserialize<'de>> serde::Deserialize<'de> for Ordered<V> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit<V>(std::marker::PhantomData<V>);
        impl<'de, V: serde::Deserialize<'de>> serde::de::Visitor<'de> for Visit<V> {
            type Value = Ordered<V>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("un objet")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, V>()? {
                    if out.len() >= MAX_ENTRIES {
                        return Err(serde::de::Error::custom("trop d'entrées"));
                    }
                    out.push((key, value));
                }
                Ok(Ordered(out))
            }
        }
        deserializer.deserialize_map(Visit(std::marker::PhantomData))
    }
}

/// `resolved` (npm, yarn v1) d'une archive de registre : `…/-/<fichier>.tgz`,
/// sans `git+`, `git:`, `github:` ni `file:` (règle commune avec l'agent PHP).
fn registry_tarball(resolved: &str) -> bool {
    if ["git+", "git:", "github:", "file:"]
        .iter()
        .any(|p| resolved.starts_with(p))
    {
        return false;
    }
    resolved.rsplit_once("/-/").is_some_and(|(_, file)| {
        (1..=256).contains(&file.len()) && !file.contains('/') && file.ends_with(".tgz")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_known_by_file_name_only() {
        assert_eq!(Kind::from_file_name("yarn.lock"), Some(Kind::Yarn));
        assert_eq!(Kind::from_file_name("Cargo.lock"), Some(Kind::Cargo));
        for unknown in [
            "npm-shrinkwrap.json",
            "bun.lock",
            "cargo.lock",
            "poetry.lock",
        ] {
            assert_eq!(Kind::from_file_name(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn registry_tarballs_have_the_registry_form() {
        assert!(registry_tarball(
            "https://registry.npmjs.org/@exemple/paquet/-/paquet-2.0.0.tgz"
        ));
        for off in [
            "git+ssh://git@git.example.org/exemple/lib.git#0123",
            "file:../lib",
            "https://files.example.org/lib-tarball-1.0.0.tgz",
            "https://registry.example.org/-/a/b.tgz",
            "github:exemple/lib",
        ] {
            assert!(!registry_tarball(off), "{off}");
        }
    }

    #[test]
    fn several_npm_lockfiles_in_one_dir_are_refused_without_priority() {
        let both = ["package-lock.json".to_owned(), "yarn.lock".to_owned()];
        let err = one_npm_lockfile_per_dir(&both, false).expect_err("refus");
        assert_eq!(
            err.to_string(),
            "plusieurs lockfiles npm dans la racine du projet (package-lock.json, yarn.lock) : \
             en désigner un par --lockfile"
        );
        assert!(one_npm_lockfile_per_dir(&both, true).is_err());
        let apart = [
            "package-lock.json".to_owned(),
            "front/yarn.lock".to_owned(),
            "composer.lock".to_owned(),
        ];
        assert!(one_npm_lockfile_per_dir(&apart, true).is_ok());
    }
}
