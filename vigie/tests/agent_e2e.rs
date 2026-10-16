//! Bout en bout réel : le routeur de `serve` sur 127.0.0.1 et l'agent PHP,
//! lancé comme par la tâche planifiée. `ping` puis `rotate-key` vont jusqu'à
//! leur accusé.
//!
//! Hors de `cargo test` ordinaire (pas de PHP dans le CI Rust) : lancé par
//! `VIGIE_E2E_PHP="<commande php>" cargo test --test agent_e2e -- --ignored`.
//! En CI, la commande est le PHP 8.1 épinglé en Docker (`vigie.yml`). La
//! variable posée, le test échoue au lieu d'être sauté.
//!
//! L'agent parle en http à la boucle locale (seul cas où il admet http) :
//! le veilleur est en HTTP derrière Caddy, et TLS n'est pas l'objet du test.
//! L'horloge du veilleur est une `FakeClock` partie de l'heure réelle et
//! avancée entre deux passages, pour franchir les débits (rapport 60 s,
//! retrait 30 s) sans attendre, dans la tolérance de ±300 s de l'agent.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use vigie::capability::CommandKind;
use vigie::clock::{Clock, FakeClock, SystemClock};
use vigie::command::{State, key, uuid_v7};
use vigie::config::{self, Runtime};
use vigie::serve;
use vigie::store::Store;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn private_file(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

struct Agent {
    php: Vec<String>,
    script: PathBuf,
    config: PathBuf,
}

impl Agent {
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.php[0])
            .args(&self.php[1..])
            .arg(&self.script)
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .output()
            .expect("lancement de l'agent PHP")
    }
}

#[test]
#[ignore = "lancé avec VIGIE_E2E_PHP (voir l'en-tête)"]
fn ping_then_rotate_key_go_end_to_end_with_the_real_php_agent() {
    let php: Vec<String> = std::env::var("VIGIE_E2E_PHP")
        .expect("VIGIE_E2E_PHP : commande PHP (par exemple « php »)")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let base = std::env::temp_dir().join(format!("vigie-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let veilleur = base.join("veilleur");
    let keys = veilleur.join("keys");
    let agent_dir = base.join("agent");
    private_dir(&base);
    private_dir(&veilleur);
    private_dir(&keys);
    private_dir(&agent_dir);
    let commands_public = key::create(&keys.join("commands.key")).unwrap();
    key::create(&keys.join("audit.key")).unwrap();
    let audit_key = key::load(&keys.join("audit.key")).unwrap();

    let config_path = veilleur.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "database = '{db}'\n[commands]\nkey_file = '{k}'\naudit_key_file = '{a}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{p}'\n[[sites]]\nid = \"site-a\"\nurl = \"https://site-a.example.org/\"\nkind = \"wordpress\"\n",
            db = veilleur.join("vigie.db").display(),
            k = keys.join("commands.key").display(),
            a = keys.join("audit.key").display(),
            p = veilleur.join("smtp-password").display(),
        ),
    )
    .unwrap();
    let config = config::load(&config_path).unwrap();
    let mut store = Store::open(&config.database).unwrap();

    let clock = Arc::new(FakeClock::new(SystemClock.unix()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = serve::router_with(
        config.clone(),
        Arc::clone(&clock) as Arc<dyn Clock>,
        Some(config_path.clone()),
    );
    // Le veilleur tourne sur son propre fil, comme `serve` sur le VPS.
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router).await
        })
    });

    let site_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("agent/php/tests/fixtures/wp-healthy");
    let agent_config = agent_dir.join("config.json");
    private_file(
        &agent_config,
        &serde_json::json!({
            "site": "site-a",
            "endpoint": format!("http://127.0.0.1:{port}/r/v1/report"),
            "root": site_root,
            "kind": "wordpress",
            "critical": ["wp-config.php"],
            "commands": {
                "endpoint": format!("http://127.0.0.1:{port}/r/v1/commands"),
                "pubkey": STANDARD.encode(commands_public.to_bytes()),
            }
        })
        .to_string(),
    );
    let agent = Agent {
        php,
        script: Path::new(env!("CARGO_MANIFEST_DIR")).join("agent/php/vigie-agent.php"),
        config: agent_config,
    };
    let init = agent.run(&["--init"]);
    assert!(init.status.success(), "{init:?}");
    let public = String::from_utf8_lossy(&init.stdout)
        .lines()
        .find(|l| l.len() == 44 && l.ends_with('='))
        .expect("clé publique")
        .to_owned();
    let public: [u8; 32] = STANDARD.decode(&public).unwrap().try_into().unwrap();
    store.add_key("site-a", &public, clock.unix()).unwrap();
    store
        .set_commands_enabled("site-a", true, clock.unix(), &audit_key)
        .unwrap();
    let typology = config::typology_fingerprint(&config);
    let enqueue = |store: &mut Store, kind: CommandKind| {
        let id = uuid_v7(clock.unix_ms()).unwrap();
        store
            .enqueue_command(
                "site-a",
                kind,
                Runtime::Php,
                "{}",
                &typology,
                &id,
                clock.unix(),
                false,
                &audit_key,
            )
            .unwrap()
            .expect("en file");
        id
    };
    let run = |clock: &FakeClock, agent: &Agent| {
        let out = agent.run(&[]);
        clock.advance(61);
        out
    };

    // ping : servi au premier passage, accusé au second.
    let ping = enqueue(&mut store, CommandKind::Ping);
    let first = run(&clock, &agent);
    assert!(first.status.success(), "{first:?}");
    assert_eq!(store.command(&ping).unwrap().unwrap().state, State::Served);
    let second = run(&clock, &agent);
    assert!(second.status.success(), "{second:?}");
    let done = store.command(&ping).unwrap().unwrap();
    assert_eq!(done.state, State::Done, "{second:?}");
    assert!(done.result.unwrap().contains("pong"));

    // rotate-key : nouvelle clé prouvée, basculée des deux côtés.
    let rotate = enqueue(&mut store, CommandKind::RotateKey);
    let third = run(&clock, &agent);
    assert!(third.status.success(), "{third:?}");
    let fourth = run(&clock, &agent);
    assert!(fourth.status.success(), "{fourth:?}");
    assert_eq!(
        store.command(&rotate).unwrap().unwrap().state,
        State::Done,
        "{fourth:?}"
    );
    let new_key = store.agent("site-a").unwrap().unwrap().pubkey;
    assert_ne!(new_key, public, "clé remplacée au veilleur");
    let secret = std::fs::read_to_string(agent_dir.join("secret.key")).unwrap();
    let secret = STANDARD.decode(secret.trim()).unwrap();
    assert_eq!(&secret[32..], &new_key, "clé basculée chez l'agent");
    // Le passage suivant, signé par la nouvelle clé, est accepté.
    let fifth = run(&clock, &agent);
    assert!(fifth.status.success(), "{fifth:?}");

    let records = store.audit_records("site-a").unwrap();
    vigie::command::audit::verify("site-a", &records, &audit_key.verifying_key(), None).unwrap();
    let _ = std::fs::remove_dir_all(&base);
}
