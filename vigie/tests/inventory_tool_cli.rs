//! `vigie-inventory`, binaire réel (issue #20, phase 3) : sous-commandes,
//! options, codes de sortie et fichiers, sans veilleur. L'envoi accepté est
//! dans `inventory_tool_e2e.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

/// Graine de test et sa forme base64.
const SEED: [u8; 32] = [42; 32];

fn seed_b64() -> String {
    STANDARD.encode(SEED)
}

fn tool(args: &[&str], key: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vigie-inventory"));
    command
        .args(args)
        .env_remove("VIGIE_INVENTORY_KEY")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY");
    if let Some(key) = key {
        command.env("VIGIE_INVENTORY_KEY", key);
    }
    command.output().expect("lancement de vigie-inventory")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Ni la graine, ni `secret-xyz` (nom de composant fictif), ni rien qui
/// ressemble à une signature (88 caractères base64) sur stdout ou stderr.
fn assert_clean(out: &Output) {
    let all = format!("{}{}", stdout(out), stderr(out));
    assert!(!all.contains(&seed_b64()), "graine : {all}");
    assert!(!all.contains("secret-xyz"), "composant : {all}");
    assert!(
        !all.split(|c: char| c.is_whitespace() || c == '"')
            .any(|w| w.len() == 88 && w.ends_with("==")),
        "signature : {all}"
    );
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inventory-tool")
}

/// Projet temporaire : fixtures du dossier copiées sous leur vrai nom.
fn project(dir: &str) -> tempfile::TempDir {
    let out = tempfile::tempdir().expect("tempdir");
    for entry in std::fs::read_dir(fixtures().join(dir)).expect(dir) {
        let path = entry.expect("entrée").path();
        let name = path.file_name().and_then(|n| n.to_str()).expect("nom");
        let real = name.strip_suffix(".fixture").expect(".fixture");
        std::fs::copy(&path, out.path().join(real)).expect("copie");
    }
    out
}

/// Projet à un seul lockfile npm, dont un paquet fictif `secret-xyz`.
fn secret_project() -> tempfile::TempDir {
    let out = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        out.path().join("package-lock.json"),
        r#"{"name": "exemple-app", "lockfileVersion": 3, "packages": {
            "": {"name": "exemple-app"},
            "node_modules/secret-xyz": {"version": "1.0.0",
              "resolved": "https://registry.npmjs.org/secret-xyz/-/secret-xyz-1.0.0.tgz"}
        }}"#,
    )
    .expect("écriture");
    out
}

/// Dossier temporaire en 0700, comme l'exige un fichier de graine.
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
    }
    dir
}

fn dir_arg(dir: &Path) -> String {
    dir.display().to_string()
}

#[test]
fn version_and_help_never_show_the_seed() {
    let out = tool(&["--version"], Some(&seed_b64()));
    assert_eq!(stdout(&out).trim(), "vigie-inventory 0.1.0");
    for args in [
        ["--help"].as_slice(),
        &["push", "--help"],
        &["push", "--inconnu"],
        &["push"],
    ] {
        let out = tool(args, Some(&seed_b64()));
        assert_clean(&out);
        assert!(!stdout(&out).contains("VIGIE_INVENTORY_KEY="), "{args:?}");
    }
    // Erreur d'argument : code 2 de clap.
    assert_eq!(tool(&["push", "--inconnu"], None).status.code(), Some(2));
    // L'option de test reste cachée.
    assert!(!stdout(&tool(&["push", "--help"], None)).contains("allow-http-loopback"));
}

#[test]
fn keygen_writes_an_exclusive_0600_seed_and_shows_only_the_public_key() {
    let dir = private_dir();
    let path = dir.path().join("inventaire.key");
    let out = tool(&["keygen", "--out", &dir_arg(&path)], None);
    assert!(out.status.success(), "{out:?}");
    let public = stdout(&out).trim().to_owned();
    assert_eq!(public.len(), 44, "{public}");
    assert!(stderr(&out).contains("vigie site inventory-key <site> add --pubkey"));
    let seed = std::fs::read_to_string(&path).expect("graine");
    let all = format!("{}{}", stdout(&out), stderr(&out));
    assert!(!all.contains(seed.trim()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("droits")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Même clé publique par la variable et par --key-file.
    let by_env = tool(&["pubkey"], Some(seed.trim()));
    assert_eq!(stdout(&by_env).trim(), public);
    let by_file = tool(&["pubkey", "--key-file", &dir_arg(&path)], None);
    assert_eq!(stdout(&by_file).trim(), public, "{by_file:?}");
    // Fichier existant : jamais écrasé.
    let again = tool(&["keygen", "--out", &dir_arg(&path)], None);
    assert_eq!(again.status.code(), Some(2), "{again:?}");
    assert_eq!(std::fs::read_to_string(&path).expect("graine"), seed);
}

#[cfg(unix)]
#[test]
fn key_files_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_dir();
    let path = dir.path().join("inventaire.key");
    assert!(
        tool(&["keygen", "--out", &dir_arg(&path)], None)
            .status
            .success()
    );
    let key = dir_arg(&path);
    let set = |p: &Path, mode| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).expect("chmod")
    };
    set(&path, 0o644);
    let out = tool(&["pubkey", "--key-file", &key], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    set(&path, 0o600);
    set(dir.path(), 0o755);
    let out = tool(&["pubkey", "--key-file", &key], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let shown = dir.path().display().to_string();
    assert!(
        stderr(&out).contains(&format!("chmod 700 {shown}")),
        "{}",
        stderr(&out)
    );
    set(dir.path(), 0o700);
    let link = dir.path().join("lien.key");
    std::os::unix::fs::symlink(&path, &link).expect("lien");
    let out = tool(&["pubkey", "--key-file", &dir_arg(&link)], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    // Variable et fichier ensemble, graine illisible.
    let out = tool(&["pubkey", "--key-file", &key], Some(&seed_b64()));
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_clean(&out);
    let out = tool(&["pubkey"], Some("pas*une*graine"));
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let out = tool(&["pubkey"], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn sbom_writes_the_bom_alone_without_key_or_network() {
    let project = project("composer");
    let output = project.path().join("sbom.json");
    let out = tool(
        &[
            "sbom",
            "--project-dir",
            &dir_arg(project.path()),
            "--output",
            &dir_arg(&output),
            "--cms",
            "wordpress",
        ],
        None,
    );
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).is_empty());
    let bom: Value =
        serde_json::from_str(&std::fs::read_to_string(&output).expect("sbom")).expect("json");
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.7");
    assert_eq!(bom["metadata"]["component"]["name"], "projet");
    assert!(bom.get("v").is_none() && bom.get("source").is_none());
    assert!(
        bom["components"]
            .as_array()
            .expect("composants")
            .iter()
            .any(|c| c["purl"] == "pkg:wordpress/theme/twentynineteen@1.9")
    );
    // Sur la sortie standard, avec --site.
    let out = tool(
        &[
            "sbom",
            "--project-dir",
            &dir_arg(project.path()),
            "--site",
            "site-a",
        ],
        None,
    );
    let bom: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(bom["metadata"]["component"]["name"], "site-a");
    let out = tool(
        &[
            "sbom",
            "--project-dir",
            &dir_arg(project.path()),
            "--site",
            "Site A",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn dry_run_shows_the_unsigned_envelope_and_sends_nothing() {
    let project = secret_project();
    let out = tool(
        &[
            "push",
            "--site",
            "site-a",
            "--endpoint",
            "https://vigie.example.org",
            "--project-dir",
            &dir_arg(project.path()),
            "--dry-run",
        ],
        None,
    );
    assert!(out.status.success(), "{out:?}");
    let envelope: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(envelope["source"], "ci");
    assert_eq!(envelope["site"], "site-a");
    assert_eq!(envelope["agent"], "vigie-inventory/0.1.0");
    assert!(envelope["seq"].as_i64().expect("seq") > 1_700_000_000_000);
    assert!(stderr(&out).contains("rien n'est envoyé"));
    assert!(!stderr(&out).contains("secret-xyz"));
}

#[test]
fn endpoints_keys_and_network_errors_have_their_exit_codes() {
    let project = secret_project();
    let dir = dir_arg(project.path());
    let push = |endpoint: &str, extra: &[&str], key: Option<&str>| {
        let mut args = vec!["push", "--site", "site-a", "--endpoint", endpoint];
        args.extend(["--project-dir", &dir]);
        args.extend(extra);
        tool(&args, key)
    };
    let seed = seed_b64();
    for endpoint in [
        "http://192.0.2.10",
        "https://vigie.example.org/r/v1/inventory",
        "https://vigie.example.org/?x",
        "https://vigie.example.org/#y",
    ] {
        let out = push(endpoint, &[], Some(&seed));
        assert_eq!(out.status.code(), Some(2), "{endpoint} : {out:?}");
        assert_clean(&out);
    }
    let out = push("http://127.0.0.1:9", &[], Some(&seed));
    assert_eq!(
        out.status.code(),
        Some(2),
        "boucle locale sans l'option : {out:?}"
    );
    // Aucune clé.
    let out = push("https://vigie.example.org", &[], None);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let out = push("https://vigie.example.org", &["--skip-without-key"], None);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(stderr(&out).contains("non envoyé"), "{out:?}");
    // Veilleur injoignable : port fermé de la boucle locale.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
    let port = closed.local_addr().expect("adresse").port();
    drop(closed);
    let output = project.path().join("sbom.json");
    let out = push(
        &format!("http://127.0.0.1:{port}"),
        &["--allow-http-loopback", "--output", &dir_arg(&output)],
        Some(&seed),
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr(&out).contains("veilleur injoignable"), "{out:?}");
    assert!(!stderr(&out).contains(&port.to_string()), "{out:?}");
    assert_clean(&out);
    // --output écrit avant l'envoi.
    assert!(output.is_file());
}

#[test]
fn projects_and_lockfiles_are_checked_before_anything_is_written() {
    let empty = tempfile::tempdir().expect("tempdir");
    let output = empty.path().join("sbom.json");
    let sbom = |dir: &Path, extra: &[&str]| {
        let mut args = vec![
            "sbom".to_owned(),
            "--project-dir".to_owned(),
            dir_arg(dir),
            "--output".to_owned(),
            dir_arg(&output),
        ];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        tool(&args, None)
    };
    let out = sbom(empty.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(stderr(&out).contains("aucun lockfile reconnu"), "{out:?}");

    let project = project("npm-and-yarn");
    let out = sbom(project.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        stderr(&out).contains("package-lock.json, yarn.lock"),
        "{out:?}"
    );
    let out = sbom(project.path(), &["--lockfile", "yarn.lock"]);
    assert!(out.status.success(), "{out:?}");
    std::fs::remove_file(&output).expect("nettoyage");
    let out = sbom(
        project.path(),
        &["--lockfile", "package-lock.json", "--lockfile", "yarn.lock"],
    );
    assert_eq!(out.status.code(), Some(2), "{out:?}");

    // Nom inconnu, chemin qui remonte, absolu, doublon, 11 --lockfile.
    std::fs::write(project.path().join("bun.lock"), "{}").expect("écriture");
    for extra in [
        vec!["--lockfile", "bun.lock"],
        vec!["--lockfile", "../hors/yarn.lock"],
        vec!["--lockfile", "/etc/yarn.lock"],
        vec!["--lockfile", "yarn.lock", "--lockfile", "./yarn.lock"],
        ["--lockfile", "yarn.lock"].repeat(11),
    ] {
        let out = sbom(project.path(), &extra);
        assert_eq!(out.status.code(), Some(2), "{extra:?} : {out:?}");
    }
    #[cfg(unix)]
    {
        // Lien vers un lockfile hors du projet.
        let outside = tempfile::tempdir().expect("tempdir");
        let target = outside.path().join("Cargo.lock");
        std::fs::write(&target, "version = 4\n").expect("écriture");
        std::os::unix::fs::symlink(&target, project.path().join("Cargo.lock")).expect("lien");
        let out = sbom(project.path(), &["--lockfile", "Cargo.lock"]);
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(stderr(&out).contains("hors du projet"), "{out:?}");
    }

    // Lockfile corrompu : code 2, --output jamais écrit.
    let broken = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        broken.path().join("composer.lock"),
        "{\"packages\": [secret-xyz",
    )
    .expect("écriture");
    let out = sbom(broken.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        stderr(&out).contains("composer.lock : JSON ou TOML illisible"),
        "{out:?}"
    );
    assert_clean(&out);
    assert!(!output.exists());
}

#[test]
fn messages_name_no_component() {
    let project = secret_project();
    let out = tool(
        &[
            "sbom",
            "--project-dir",
            &dir_arg(project.path()),
            "--output",
            &dir_arg(&project.path().join("s.json")),
        ],
        Some(&seed_b64()),
    );
    assert!(out.status.success(), "{out:?}");
    assert_clean(&out);
    assert!(stderr(&out).contains("composants : 1"), "{out:?}");
}
