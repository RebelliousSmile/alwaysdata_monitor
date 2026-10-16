use std::path::Path;
use std::process::{Command, Output};

fn vigie(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vigie"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("VIGIE_CONFIG")
        .output()
        .expect("lancement de vigie")
}

fn write_config(dir: &Path, extra: &str) -> std::path::PathBuf {
    let db = dir.join("vigie.db");
    // TOML : chemin Windows en chaîne littérale.
    let raw = format!(
        "database = '{}'\n{extra}\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n",
        db.display(),
        dir.join("smtp-password").display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, raw).expect("écriture");
    path
}

#[test]
fn unknown_key_exits_with_code_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "inconnu = true");
    let out = vigie(&config, &["tick"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("inconnu"));
}

#[test]
fn missing_config_exits_with_code_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = vigie(&dir.path().join("absent.toml"), &["tick"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn tick_then_status_succeeds_and_migrations_rerun_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "");
    let before = vigie(&config, &["status"]);
    assert_eq!(before.status.code(), Some(1), "aucun tick : {before:?}");
    for _ in 0..2 {
        let out = vigie(&config, &["tick"]);
        assert!(out.status.success(), "{out:?}");
    }
    let after = vigie(&config, &["status"]);
    assert!(after.status.success(), "{after:?}");
    let stdout = String::from_utf8_lossy(&after.stdout);
    assert!(stdout.contains("schéma v7"), "{stdout}");
    assert!(stdout.contains("→ ok"), "{stdout}");
    assert!(stdout.contains("incidents ouverts : aucun"), "{stdout}");
    assert!(stdout.contains("notifications en attente : 0"), "{stdout}");
}

#[test]
fn check_requires_once_and_a_known_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "");
    let out = vigie(&config, &["check", "absent"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--once"));
    let out = vigie(&config, &["check", "absent", "--once"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!dir.path().join("vigie.db").exists());
}

#[test]
fn ack_of_an_unknown_incident_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "");
    let out = vigie(&config, &["ack", "42"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("aucun incident 42"));
}

/// Clés publiques des tests 1 et 2 de la RFC 8032, section 7.1.
const KEY_1: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const KEY_2: &str = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";

const SITE_A: &str = "[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\n";

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn site_add_checks_the_key_and_the_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), SITE_A);

    let short = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let out = vigie(&config, &["site", "add", "site-a", "--pubkey", short]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        stderr(&out).contains("31 octet(s) au lieu de 32"),
        "{out:?}"
    );
    let out = vigie(
        &config,
        &["site", "add", "site-a", "--pubkey", "pas*du*base64"],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let out = vigie(&config, &["site", "add", "site-b", "--pubkey", KEY_1]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr(&out).contains("aucun site « site-b »"), "{out:?}");
    assert!(!dir.path().join("vigie.db").exists());

    let out = vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_1]);
    assert!(out.status.success(), "{out:?}");
    let out = vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_2]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr(&out).contains("rotate-key"), "{out:?}");

    let out = vigie(&config, &["site", "list"]);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).contains("aucun rapport"), "{out:?}");
}

#[test]
fn rotate_key_then_remove_with_and_without_confirmation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), SITE_A);

    let out = vigie(
        &config,
        &["site", "rotate-key", "site-a", "--pubkey", KEY_1],
    );
    assert_eq!(out.status.code(), Some(1), "pas encore de clé : {out:?}");
    let out = vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_1]);
    assert!(out.status.success(), "{out:?}");
    let out = vigie(
        &config,
        &["site", "rotate-key", "site-a", "--pubkey", KEY_1],
    );
    assert_eq!(out.status.code(), Some(1), "même clé : {out:?}");
    let out = vigie(
        &config,
        &["site", "rotate-key", "site-a", "--pubkey", KEY_2],
    );
    assert!(out.status.success(), "{out:?}");

    // Sans --yes, stdin fermé : aucune confirmation, rien n'est retiré.
    let out = vigie(&config, &["site", "remove", "site-a"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!stdout(&vigie(&config, &["site", "list"])).contains("sans agent"));

    let out = vigie(&config, &["site", "remove", "site-a", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&vigie(&config, &["site", "list"])).contains("sans agent"));
    let out = vigie(&config, &["site", "remove", "site-a", "--yes"]);
    assert_eq!(out.status.code(), Some(1), "déjà retirée : {out:?}");
}

#[test]
fn status_shows_the_agent_of_each_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), SITE_A);
    assert!(
        vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_1])
            .status
            .success()
    );
    let out = vigie(&config, &["status"]);
    let text = stdout(&out);
    assert!(text.contains("agent : clé enregistrée il y a"), "{text}");
}

const API: &str = "[api]\npublic_url = \"https://veilleur.example.org\"\n";

fn api(public_url: &str) -> String {
    format!("[api]\npublic_url = \"{public_url}\"\n")
}

/// Relit le QR code imprimé par `device pair` : deux modules par caractère,
/// un demi-bloc plein est un module clair.
fn decode_qr(lines: &[&str]) -> String {
    let rows: Vec<Vec<char>> = lines.iter().map(|l| l.chars().collect()).collect();
    let width = rows.iter().map(Vec::len).max().expect("QR vide");
    let light = |x: usize, y: usize| -> bool {
        let c = rows[y / 2].get(x).copied().unwrap_or(' ');
        match (c, y % 2) {
            ('█', _) | ('▀', 0) | ('▄', 1) => true,
            (' ' | '▀' | '▄', _) => false,
            _ => panic!("caractère inattendu dans le QR : {c:?}"),
        }
    };
    const SCALE: usize = 4;
    const MARGIN: usize = 8;
    let (w, h) = (width, rows.len() * 2);
    let mut image = rqrr::PreparedImage::prepare_from_greyscale(
        w * SCALE + 2 * MARGIN,
        h * SCALE + 2 * MARGIN,
        |x, y| {
            let inside = (MARGIN..MARGIN + w * SCALE).contains(&x)
                && (MARGIN..MARGIN + h * SCALE).contains(&y);
            if !inside || light((x - MARGIN) / SCALE, (y - MARGIN) / SCALE) {
                255
            } else {
                0
            }
        },
    );
    let grids = image.detect_grids();
    assert_eq!(grids.len(), 1, "un seul QR code attendu");
    grids[0].decode().expect("QR illisible").1
}

/// Le QR code, puis le lien, dans la sortie de `device pair`.
fn pair_output(out: &Output) -> (String, String) {
    let text = stdout(out);
    let lines: Vec<&str> = text.lines().collect();
    let blank = lines.iter().position(|l| l.is_empty()).expect("ligne vide");
    let link = lines[blank + 1].to_owned();
    (decode_qr(&lines[..blank]), link)
}

#[test]
fn device_pair_needs_an_api_section_and_a_safe_url() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("vigie.db");

    let config = write_config(dir.path(), "");
    let out = vigie(&config, &["device", "pair", "--name", "pc"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr(&out).contains("[api]"), "{out:?}");

    let config = write_config(dir.path(), &api("http://site-a.example.org"));
    let out = vigie(&config, &["device", "pair", "--name", "pc"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!db.exists(), "aucune base pour une adresse refusée");

    let config = write_config(dir.path(), API);
    let out = vigie(&config, &["device", "pair", "--name", "   "]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr(&out).contains("nom d'appareil vide"), "{out:?}");
    assert!(!db.exists());

    let config = write_config(dir.path(), &api("http://127.0.0.1:8080"));
    let out = vigie(&config, &["device", "pair", "--name", "pc"]);
    assert!(out.status.success(), "boucle locale admise : {out:?}");
}

#[test]
fn device_pair_prints_a_qr_code_of_the_link_and_list_shows_no_secret() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), API);

    let out = vigie(&config, &["device", "pair", "--name", "téléphone"]);
    assert!(out.status.success(), "{out:?}");
    let (decoded, link) = pair_output(&out);
    assert_eq!(decoded, link);
    let code = link
        .strip_prefix("vigie://pair?u=https%3A%2F%2Fveilleur.example.org&c=")
        .unwrap_or_else(|| panic!("lien inattendu : {link}"));
    assert_eq!(code.len(), 22);
    assert!(stdout(&out).contains("(10 min), une seule fois"), "{out:?}");

    let out = vigie(&config, &["device", "list"]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(text.contains("appareils : aucun"), "{text}");
    assert!(text.contains("en attente d'appairage : 1"), "{text}");
    assert!(text.contains("téléphone"), "{text}");
    assert!(!text.contains(code), "code affiché par list : {text}");

    let out = vigie(&config, &["device", "revoke", "99"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr(&out).contains("aucun appareil 99"), "{out:?}");
}

#[test]
fn device_revoke_marks_a_paired_device_revoked() {
    use vigie::device;
    use vigie::store::Store;

    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), API);
    let out = vigie(&config, &["device", "pair", "--name", "pc"]);
    assert!(out.status.success(), "{out:?}");
    let (_, link) = pair_output(&out);
    let code = link.rsplit("&c=").next().expect("code");

    // Ce que fait `POST /api/v1/pair`, sans serveur.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("horloge")
        .as_secs() as i64;
    let paired = Store::open(&dir.path().join("vigie.db"))
        .expect("open")
        .consume_pairing(&device::hash(code), &device::hash("jeton"), now)
        .expect("consume")
        .expect("appareil");

    let text = stdout(&vigie(&config, &["device", "list"]));
    assert!(text.contains("appareils : 1"), "{text}");
    assert!(text.contains("actif, jamais vu"), "{text}");
    assert!(!text.contains("en attente"), "{text}");

    let id = paired.id.to_string();
    let out = vigie(&config, &["device", "revoke", &id]);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).contains("révoqué"), "{out:?}");
    let out = vigie(&config, &["device", "revoke", &id]);
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).contains("déjà révoqué"), "{out:?}");

    let text = stdout(&vigie(&config, &["device", "list"]));
    assert!(text.contains(&format!("#{id}  pc  révoqué le")), "{text}");
}

#[test]
fn a_site_without_runtime_warns_and_lists_a_dash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), SITE_A);
    let out = vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_1]);
    assert!(out.status.success(), "{out:?}");
    assert!(stderr(&out).contains("n'admet aucune commande"), "{out:?}");
    let out = vigie(&config, &["site", "list"]);
    assert!(stdout(&out).trim_end().ends_with("\t-"), "{out:?}");

    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), &format!("{SITE_A}kind = \"wordpress\"\n"));
    let out = vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_1]);
    assert!(out.status.success(), "{out:?}");
    assert!(!stderr(&out).contains("n'admet aucune commande"), "{out:?}");
    let out = vigie(&config, &["site", "list"]);
    assert!(stdout(&out).trim_end().ends_with("\tphp"), "{out:?}");
}

#[test]
fn status_says_when_serve_has_not_seen_the_typology() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), SITE_A);
    let out = vigie(&config, &["status"]);
    assert!(
        stdout(&out).contains("tick : inconnue ; serve : inconnue"),
        "{out:?}"
    );

    // Base en v7 créée par une commande, sans passage de serve.
    assert!(
        vigie(&config, &["site", "add", "site-a", "--pubkey", KEY_1])
            .status
            .success()
    );
    let out = vigie(&config, &["status"]);
    let text = stdout(&out);
    assert!(text.contains("serve : aucune"), "{text}");
    assert!(text.contains("serve à redémarrer"), "{text}");
}
