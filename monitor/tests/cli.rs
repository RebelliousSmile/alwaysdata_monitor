use std::path::Path;
use std::process::{Command, Output};

fn monitor(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_monitor"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("MONITOR_CONFIG")
        .output()
        .expect("lancement de monitor")
}

fn write_config(dir: &Path, extra: &str) -> std::path::PathBuf {
    let db = dir.join("monitor.db");
    // TOML : chemin Windows en chaîne littérale.
    let raw = format!(
        "database = '{}'\n{extra}\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"monitor@example.org\"\n",
        db.display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, raw).expect("écriture");
    path
}

#[test]
fn unknown_key_exits_with_code_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "inconnu = true");
    let out = monitor(&config, &["tick"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("inconnu"));
}

#[test]
fn missing_config_exits_with_code_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = monitor(&dir.path().join("absent.toml"), &["tick"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn tick_then_status_succeeds_and_migrations_rerun_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "");
    let before = monitor(&config, &["status"]);
    assert_eq!(before.status.code(), Some(1), "aucun tick : {before:?}");
    for _ in 0..2 {
        let out = monitor(&config, &["tick"]);
        assert!(out.status.success(), "{out:?}");
    }
    let after = monitor(&config, &["status"]);
    assert!(after.status.success(), "{after:?}");
    let stdout = String::from_utf8_lossy(&after.stdout);
    assert!(stdout.contains("schéma v1"), "{stdout}");
    assert!(stdout.contains("→ ok"), "{stdout}");
}
