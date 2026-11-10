//! `vigie site recommend` (#13) : aperçu, calcul de l'empreinte par
//! l'agent, application, bloc en place repris, `--replace`, et
//! `site command … htaccess-rollback`. Les résultats de l'agent sont posés
//! en base à la main.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use vigie::analysis::catalog;
use vigie::analysis::findings::{self, Analysis, BotSeen};
use vigie::store::{AcceptedReport, Store};

/// Clé publique du test 1 de la RFC 8032, section 7.1.
const KEY_1: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const PREV: &str = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";
const NEW: &str = "8978bc0aa6aece0fc74de901712dd160c804917cda1ade8afb59f29f526ff94a";

fn vigie(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vigie"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("VIGIE_CONFIG")
        .output()
        .expect("lancement de vigie")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn setup(dir: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let raw = format!(
        "database = '{db}'\n[commands]\nkey_file = '{k}'\naudit_key_file = '{a}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{p}'\n[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\nkind = \"wordpress\"\n[sites.logs]\nsource = \"alwaysdata\"\ntz = \"Europe/Paris\"\nhosts = [\"site-a.example.org\"]\nprotect_ips = [\"192.0.2.250\"]\n",
        db = dir.join("vigie.db").display(),
        k = dir.join("commands.key").display(),
        a = dir.join("audit.key").display(),
        p = dir.join("smtp-password").display(),
    );
    let config = dir.join("config.toml");
    std::fs::write(&config, raw).unwrap();
    for args in [
        &["commands", "init-keys"][..],
        &["site", "add", "site-a", "--pubkey", KEY_1],
        &["site", "commands", "site-a", "enable"],
    ] {
        let out = vigie(&config, args);
        assert!(out.status.success(), "{args:?} : {out:?}");
    }
    let now = vigie::now();
    let mut store = Store::open(&dir.join("vigie.db")).unwrap();
    let bots = ["Bytespider", "GPTBot", "Googlebot"]
        .iter()
        .map(|name| {
            let bot = catalog::find(name).unwrap();
            BotSeen {
                name: bot.name.into(),
                publisher: bot.publisher.into(),
                purpose: bot.purpose.into(),
                robots_only: bot.robots_only,
                honours_robots: bot.honours_robots,
                class: bot.class,
                protected: bot.protected(),
                requests: 100,
            }
        })
        .collect();
    let analysis = Analysis {
        site: "site-a".into(),
        generated_at: now,
        reference_ms: now * 1000,
        bots,
        verdicts: Vec::new(),
        scored: 0,
        unscored: 0,
        rules: Vec::new(),
        load: Vec::new(),
        load_threshold_us: 0,
    };
    findings::persist(&mut store, &analysis).unwrap();
    report(dir, 1, PREV);
    config
}

fn report(dir: &Path, seq: i64, htaccess: &str) {
    let mut store = Store::open(&dir.join("vigie.db")).unwrap();
    let pubkey: [u8; 32] = STANDARD.decode(KEY_1).unwrap().try_into().unwrap();
    let files = json!({".htaccess": htaccess}).to_string();
    // Les rapports sont espacés d'une minute au moins : dates du passé.
    let at = vigie::now() - 3600 + seq * 120;
    store
        .accept_report(
            &AcceptedReport {
                site: "site-a",
                pubkey: &pubkey,
                seq,
                agent: "vigie-agent-php/0.4.0",
                facts: "{}",
                files: &files,
                findings: &[],
                dropped: 0,
            },
            at,
            &|_, _| true,
        )
        .unwrap();
}

/// Résultat de l'agent posé à la main sur la dernière commande.
fn agent_result(dir: &Path, status: &str, data: Value) -> (String, Value) {
    let conn = rusqlite::Connection::open(dir.join("vigie.db")).unwrap();
    let (id, params): (String, String) = conn
        .query_row(
            "SELECT id, params FROM commands ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let result = json!({"command_id": id, "status": status, "detail": "d", "data": data});
    conn.execute(
        "UPDATE commands SET state = 'done', result = ?2, closed_at = 1 WHERE id = ?1",
        rusqlite::params![id, result.to_string()],
    )
    .unwrap();
    (id, serde_json::from_str(&params).unwrap())
}

#[test]
fn recommend_previews_computes_then_applies_and_keeps_the_block_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let config = setup(dir.path());

    let out = vigie(&config, &["site", "recommend", "site-a"]);
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("User-agent: GPTBot\nDisallow: /"), "{shown}");
    assert!(shown.contains("règle d'UA : Bytespider"), "{shown}");
    assert!(!shown.contains("Googlebot"), "{shown}");
    assert!(shown.contains("règles en place inconnues"), "{shown}");
    assert!(
        shown.contains("RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC]"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("previous_sha256 : {PREV}")),
        "{shown}"
    );
    assert!(shown.contains("aperçu seulement"), "{shown}");

    // Règles en place inconnues : --replace exigé.
    let out = vigie(&config, &["site", "recommend", "site-a", "--apply"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("--replace"), "{}", text(&out));

    // Premier --apply : calcul seul par l'agent.
    let out = vigie(
        &config,
        &["site", "recommend", "site-a", "--apply", "--replace"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("calcul seul"), "{}", text(&out));
    let (_, params) = agent_result(
        dir.path(),
        "ok",
        json!({"current_sha256": PREV, "new_sha256": NEW}),
    );
    assert_eq!(params["new_sha256"], Value::Null);
    assert_eq!(params["previous_sha256"], PREV);
    let block = params["block"].as_str().unwrap().to_owned();

    // Second --apply : application, avec l'empreinte calculée.
    let out = vigie(
        &config,
        &["site", "recommend", "site-a", "--apply", "--replace"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains(&format!("new_sha256 : {NEW}")),
        "{}",
        text(&out)
    );
    let (applied, params) = agent_result(dir.path(), "ok", json!({"current_sha256": NEW}));
    assert_eq!(params["new_sha256"], NEW);
    assert_eq!(params["block"], block.as_str());

    // Le rapport porte le nouveau .htaccess : le bloc en place est connu.
    report(dir.path(), 2, NEW);
    let out = vigie(&config, &["site", "recommend", "site-a"]);
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains(&format!("bloc en place : celui de la commande {applied}")),
        "{shown}"
    );
    assert!(shown.contains("= reprise   UA Bytespider"), "{shown}");
    assert!(shown.contains("rien à appliquer"), "{shown}");

    // Retour arrière : paramètres tirés du rapport et de l'application.
    let out = vigie(&config, &["site", "command", "site-a", "htaccess-rollback"]);
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains(&format!(
            "{{\"expected_current_sha256\":\"{NEW}\",\"prev_sha256\":\"{PREV}\"}}"
        )),
        "{shown}"
    );

    // Modifié hors de Vigie : règles inconnues de nouveau.
    report(
        dir.path(),
        3,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    let out = vigie(&config, &["site", "recommend", "site-a", "--apply"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("--replace"), "{}", text(&out));
    let out = vigie(&config, &["site", "command", "site-a", "htaccess-rollback"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("rien à défaire"), "{}", text(&out));
}
