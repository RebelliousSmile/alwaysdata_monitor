//! Veilleur de test de la CLI du rapprochement (#21), inclus par `#[path]`
//! avec `match_harness.rs` et `matching_data.rs` : un fichier
//! `config.toml` réel (lu par le binaire), la même configuration en mémoire
//! pour `tick`, des clés d'audit de test. Données fictives seulement.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use super::match_harness::Harness;

/// Instant réel du test, à la minute : la CLI lit l'horloge du système, et
/// une dérogation se juge contre elle (90 jours au plus).
pub fn now() -> i64 {
    vigie::now() / 60 * 60
}

/// `AAAA-MM-JJ` de `secs`.
pub fn day(secs: i64) -> String {
    vigie::iso_utc(secs).chars().take(10).collect()
}

pub struct Cli {
    pub harness: Harness,
    pub config: PathBuf,
}

/// `inventory` : contenu de `[sites.inventory]` ; `commands` : `[commands]`
/// avec des clés d'audit de test.
pub fn setup(kind: &str, inventory: &str, commands: bool) -> Cli {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path();
    let token = path.join("wordfence-token");
    std::fs::write(&token, "jeton-fictif\n").unwrap();
    let mut raw = format!(
        "database = '{}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n",
        path.join("vigie.db").display(),
        path.join("smtp-password").display()
    );
    if commands {
        // Dossier des clés en 700, comme sur le VPS.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = path.join("commands.key");
        let audit = path.join("audit.key");
        vigie::command::key::create(&key).expect("clé de commandes");
        vigie::command::key::create(&audit).expect("clé d'audit");
        raw.push_str(&format!(
            "[commands]\nkey_file = '{}'\naudit_key_file = '{}'\n",
            key.display(),
            audit.display()
        ));
    }
    raw.push_str(&format!(
        "[vulns]\nsources = [\"osv-packagist\", \"wordfence\"]\n[vulns.wordfence]\ntoken_file = '{}'\nterms_reviewed = \"2026-10-01\"\n",
        token.display()
    ));
    raw.push_str(&format!(
        "[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\nkind = \"{kind}\"\nagent_silence = 3153600000\n"
    ));
    if !inventory.is_empty() {
        raw.push_str(&format!("[sites.inventory]\n{inventory}\n"));
    }
    raw.push_str(
        "[[sites]]\nid = \"site-b\"\nurl = \"https://site-b.example.org/\"\nkind = \"wordpress\"\n",
    );
    let config_path = path.join("config.toml");
    std::fs::write(&config_path, &raw).unwrap();
    let config = vigie::config::parse(&config_path, &raw).expect("configuration");
    let harness = Harness::from_config(dir, config, now() - 3_600);
    Cli {
        harness,
        config: config_path,
    }
}

impl Cli {
    pub fn run(&self, args: &[&str]) -> Output {
        run(&self.config, args)
    }

    pub fn dir(&self) -> &Path {
        self.harness.dir.path()
    }
}

pub fn run(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vigie"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("VIGIE_CONFIG")
        .env("RUST_LOG", "off")
        .output()
        .expect("lancement de vigie")
}

/// Sortie standard, sans caractère de contrôle hors saut de ligne.
pub fn stdout(out: &Output) -> String {
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(
        text.chars().all(|c| c == '\n' || !c.is_control()),
        "{text:?}"
    );
    text
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}
