//! Sources CMS branchées sur le cadre de F2 (#17, phase 3) : verrou de
//! relecture Wordfence, jeton, débit, redirections, `LOADER_VERSION`,
//! archive Friends-Of-Presta, plafonds, et `vigie vulns match | sources` de
//! bout en bout. Serveur HTTPS local de F2, fixtures **fictives**. Aucun
//! réseau.

#[path = "support/dump_server.rs"]
mod dump_server;
#[path = "support/targen.rs"]
mod targen;
#[path = "support/veilleur.rs"]
mod veilleur;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use vigie::clock::FakeClock;
use vigie::config::{Config, Vulns, WordfenceConfig};
use vigie::http::Trust;
use vigie::secret::read_token;
use vigie::store::Store;
use vigie::vulns::advisory::Tally;
use vigie::vulns::sources::friends_of_presta::{self, FriendsOfPresta};
use vigie::vulns::sources::wordfence::{self, Wordfence};
use vigie::vulns::store::{Outcome, SyncState, active_count, sync_state};
use vigie::vulns::sync::download::Download;
use vigie::vulns::sync::engine::sync_source;
use vigie::vulns::sync::{
    FetchOutcome, Limits, NotReady, Sink, SourceMeta, SourceReport, SyncContext, SyncError,
    SyncOptions, VulnSource,
};

use dump_server::{DumpServer, Reply};

const T0: i64 = 1_800_000_000;
const LM: &str = "Sat, 17 Oct 2026 03:00:00 GMT";
const REVIEW: &str = "2099-01-01";
const TOKEN: &str = "jeton-fictif-0123456789abcdef";
const WF_PATH: &str = "/api/intelligence/v3/vulnerabilities/production";
const FOP_PATH: &str = "/friends-of-presta/security-advisories/archive/refs/heads/main.tar.gz";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulns")
}

fn feed() -> Vec<u8> {
    std::fs::read(fixtures().join("wordfence/production.json")).unwrap()
}

fn fop_archive() -> Vec<u8> {
    targen::archive(&targen::posts(&fixtures().join("friends-of-presta/_posts")))
}

/// Dossier en 0700, comme le veut la règle des secrets.
fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// Fichier en 0600.
fn private_file(path: &Path, content: &[u8]) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

struct Env {
    dir: tempfile::TempDir,
    server: DumpServer,
    config: Config,
    clock: FakeClock,
    limits: Option<Limits>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        private_dir(&keys);
        let token_file = keys.join("wordfence-token");
        private_file(&token_file, format!("{TOKEN}\r\n").as_bytes());
        let mut config = veilleur::config(dir.path().join("data").join("vigie.db"));
        config.vulns = Some(Vulns {
            sources: vec!["friends-of-presta".into(), "wordfence".into()],
            wordfence: Some(WordfenceConfig {
                token_file,
                terms_reviewed: REVIEW.into(),
            }),
        });
        let server = DumpServer::start();
        server.route(WF_PATH, Reply::ok_etag(feed(), "\"w1\"", LM));
        server.route(
            FOP_PATH,
            Reply::Redirect(server.url("/codeload/main.tar.gz")),
        );
        server.route(
            "/codeload/main.tar.gz",
            Reply::ok_etag(fop_archive(), "\"f1\"", LM),
        );
        Self {
            dir,
            server,
            config,
            clock: FakeClock::new(T0),
            limits: None,
        }
    }

    fn options(&self) -> SyncOptions {
        SyncOptions {
            trust: Trust::Custom(vec![self.server.ca.clone()]),
            endpoint_override: Some(self.server.base()),
            limits_override: self.limits.clone(),
            free_space_override: None,
        }
    }

    fn wf_config(&self) -> WordfenceConfig {
        self.config
            .vulns
            .as_ref()
            .unwrap()
            .wordfence
            .clone()
            .unwrap()
    }

    /// Wordfence avec la relecture du binaire donnée (la constante réelle
    /// reste `None`).
    fn wordfence(&self, reviewed: Option<&'static str>) -> Wordfence {
        Wordfence::new(Some(self.wf_config())).with_binary_review(reviewed)
    }

    fn run_source(&self, source: &dyn VulnSource) -> SourceReport {
        let mut store = Store::open(&self.config.database).unwrap();
        sync_source(
            &mut store,
            self.config.database.parent().unwrap(),
            source,
            &self.options(),
            &self.clock,
            false,
        )
    }

    fn state(&self, id: &str) -> SyncState {
        sync_state(&Store::open(&self.config.database).unwrap(), id)
            .unwrap()
            .expect("source")
    }

    fn count(&self, id: &str) -> i64 {
        active_count(&Store::open(&self.config.database).unwrap(), id).unwrap()
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.config.database).unwrap()
    }

    /// Fichier de configuration pour la CLI (lecture de la base seulement).
    fn cli_config(&self) -> PathBuf {
        let raw = format!(
            "database = '{}'\n[alerts]\nto = \"alertes@example.org\"\nfrom = \"vigie@example.org\"\nsmtp_host = \"smtp.example.org\"\npassword_file = '{}'\n",
            self.config.database.display(),
            self.dir.path().join("smtp-password").display()
        );
        let path = self.dir.path().join("config.toml");
        std::fs::write(&path, raw).unwrap();
        path
    }

    fn vigie(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vigie"))
            .arg("--config")
            .arg(self.cli_config())
            .args(args)
            .env_remove("VIGIE_CONFIG")
            .output()
            .expect("lancement de vigie")
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

// ---------------------------------------------------------------- verrou

#[test]
fn an_undeclared_wordfence_is_absent() {
    let mut env = Env::new();
    env.config.vulns = Some(Vulns {
        sources: vec!["friends-of-presta".into()],
        wordfence: None,
    });
    let report =
        vigie::vulns::sync::run(&env.config, &env.options(), &env.clock, None, false).unwrap();
    let ids: Vec<&str> = report.sources.iter().map(|s| s.id).collect();
    assert_eq!(ids, ["friends-of-presta"]);
    assert_eq!(report.failures(), 0, "{report:?}");
    assert!(env.server.seen().iter().all(|s| s.path != WF_PATH));
}

#[test]
fn the_real_constant_refuses_without_any_request() {
    let env = Env::new();
    // Par le registre : la constante réelle vaut `None`.
    assert_eq!(wordfence::WORDFENCE_TERMS_REVIEWED, None);
    let report = vigie::vulns::sync::run(
        &env.config,
        &env.options(),
        &env.clock,
        Some("wordfence"),
        false,
    )
    .unwrap();
    assert_eq!(report.sources[0].outcome, Outcome::Failed);
    assert_eq!(report.failures(), 1);
    assert_eq!(env.server.requests(), 0);
    let state = env.state("wordfence");
    let err = state.last_error.unwrap();
    assert!(err.contains(wordfence::DISABLED), "{err}");
    // Visible dans `vulns sources`, avec son niveau de redistribution.
    let text = stdout(&env.vigie(&["vulns", "sources"]));
    assert!(
        text.contains("relecture des conditions non consignée"),
        "{text}"
    );
    assert!(text.contains("redistribution : usage interne"), "{text}");
}

#[test]
fn a_mismatched_review_date_refuses_without_any_request() {
    let env = Env::new();
    let report = env.run_source(&env.wordfence(Some("2099-01-02")));
    assert_eq!(report.outcome, Outcome::Failed);
    assert!(report.line.contains("terms_reviewed"), "{}", report.line);
    assert_eq!(env.server.requests(), 0);
}

/// `ready` toujours vrai : seul `fetch` peut encore refuser.
struct SkipReady(Wordfence);

impl VulnSource for SkipReady {
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn meta(&self) -> SourceMeta {
        self.0.meta()
    }
    fn ready(&self, _: &SyncContext) -> Result<(), NotReady> {
        Ok(())
    }
    fn fetch(
        &self,
        dl: &mut Download,
        sink: &mut dyn Sink,
        tally: &mut Tally,
    ) -> Result<FetchOutcome, SyncError> {
        self.0.fetch(dl, sink, tally)
    }
}

#[test]
fn fetch_rechecks_the_lock() {
    let env = Env::new();
    for reviewed in [None, Some("2099-01-02")] {
        // Le débit de F2 réserve la fenêtre avant `fetch` : on la rouvre.
        env.clock.advance(31 * 60);
        let report = env.run_source(&SkipReady(env.wordfence(reviewed)));
        assert_eq!(report.outcome, Outcome::Failed, "{}", report.line);
        assert!(report.line.contains("pas prête"), "{}", report.line);
    }
    assert_eq!(env.server.requests(), 0);
}

// ---------------------------------------------------------------- bout en bout

#[test]
fn an_open_lock_loads_wordfence_with_a_sensitive_bearer() {
    let env = Env::new();
    let report = env.run_source(&env.wordfence(Some(REVIEW)));
    assert_eq!(report.outcome, Outcome::Loaded, "{}", report.line);
    assert!(!report.line.contains(TOKEN));
    assert_eq!(env.count("wordfence"), 15);
    let seen = env.server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    let state = env.state("wordfence");
    assert_eq!(state.loader_version, Some(wordfence::LOADER_VERSION));
    assert!(state.last_error.is_none());

    let out = env.vigie(&[
        "vulns",
        "match",
        "pkg:wordpress/plugin/exemple-plugin@1.2.3",
    ]);
    let text = stdout(&out);
    assert!(
        text.contains("WF-00000000-0000-4000-8000-000000000001  touché  corrigée en 1.2.4"),
        "{text}"
    );
    assert!(text.contains("[usage interne]"), "{text}");
    assert!(text.contains("Exemple Intelligence SARL"), "{text}");
    let core = stdout(&env.vigie(&["vulns", "match", "pkg:wordpress/core/core@6.4.1"]));
    assert!(
        core.contains("WF-00000000-0000-4000-8000-000000000003  touché  corrigée en 6.4.2"),
        "{core}"
    );
}

#[test]
fn friends_of_presta_follows_its_redirect_and_keeps_the_revision() {
    let env = Env::new();
    let meta = FriendsOfPresta.meta();
    assert_eq!(
        meta.origins,
        [("github.com", 443), ("codeload.github.com", 443)]
    );
    assert_eq!(
        wordfence::Wordfence::new(None).meta().origins,
        [("www.wordfence.com", 443)]
    );
    let report = env.run_source(&FriendsOfPresta);
    assert_eq!(report.outcome, Outcome::Loaded, "{}", report.line);
    assert_eq!(env.count("friends-of-presta"), 12);
    let state = env.state("friends-of-presta");
    assert_eq!(state.revision.as_deref(), Some(targen::REVISION));
    assert_eq!(
        state.loader_version,
        Some(friends_of_presta::LOADER_VERSION)
    );
    // Seconde synchronisation : ETag inchangé, rien d'écrit.
    let generation = state.active_generation;
    let again = env.run_source(&FriendsOfPresta);
    assert_eq!(again.outcome, Outcome::NotModified, "{}", again.line);
    assert_eq!(env.state("friends-of-presta").active_generation, generation);
    // Même empreinte sans ETag : inchangée.
    env.server
        .route("/codeload/main.tar.gz", Reply::ok(fop_archive()));
    assert_eq!(env.run_source(&FriendsOfPresta).outcome, Outcome::Unchanged);

    let m = stdout(&env.vigie(&[
        "vulns",
        "match",
        "pkg:prestashop/module/exemplemodule@1.5.0",
    ]));
    assert!(
        m.contains("FOP-2099-01-15-exemplemodule  touché  corrigée en 1.5.1"),
        "{m}"
    );
    assert!(m.contains("[faits seulement]"), "{m}");
    let free = stdout(&env.vigie(&["vulns", "match", "pkg:prestashop/module/modulelibre@3.0.0"]));
    assert!(free.contains("plage inconnue"), "{free}");
    assert!(!free.contains("aucune faille"), "{free}");

    let sources = stdout(&env.vigie(&["vulns", "sources"]));
    for want in [
        "friends-of-presta  licence CC-BY-SA-4.0",
        "redistribution : faits seulement",
        &format!("révision : {}", targen::REVISION),
        "out_of_scope 1",
        "unevaluable",
    ] {
        assert!(sources.contains(want), "{want}\n{sources}");
    }
}

#[test]
fn a_redirect_to_an_unknown_host_is_refused() {
    let env = Env::new();
    assert_eq!(env.run_source(&FriendsOfPresta).outcome, Outcome::Loaded);
    let before = env.count("friends-of-presta");
    let other = DumpServer::start();
    other.route("/main.tar.gz", Reply::ok(fop_archive()));
    env.server.route(
        "/codeload/main.tar.gz",
        Reply::Redirect(other.url("/main.tar.gz")),
    );
    env.server
        .route(FOP_PATH, Reply::Redirect(other.url("/main.tar.gz")));
    let report = env.run_source(&FriendsOfPresta);
    assert_eq!(report.outcome, Outcome::Failed, "{}", report.line);
    assert_eq!(other.requests(), 0);
    assert_eq!(env.count("friends-of-presta"), before);

    // Wordfence : le jeton ne part jamais vers un autre hôte.
    let wf_other = DumpServer::start();
    wf_other.route(WF_PATH, Reply::ok(feed()));
    env.server
        .route(WF_PATH, Reply::Redirect(wf_other.url(WF_PATH)));
    let report = env.run_source(&env.wordfence(Some(REVIEW)));
    assert_eq!(report.outcome, Outcome::Failed, "{}", report.line);
    assert_eq!(wf_other.requests(), 0);
}

// ---------------------------------------------------------------- débit

#[test]
fn wordfence_is_requested_at_most_every_thirty_minutes() {
    let env = Env::new();
    let wf = env.wordfence(Some(REVIEW));
    assert_eq!(env.run_source(&wf).outcome, Outcome::Loaded);
    env.clock.advance(10 * 60);
    let early = env.run_source(&wf);
    assert_eq!(early.outcome, Outcome::RateLimited, "{}", early.line);
    assert_eq!(env.server.requests(), 1);
    env.clock.advance(21 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::NotModified);
    assert_eq!(env.server.requests(), 2);
}

#[test]
fn retry_after_is_kept_by_the_framework() {
    let env = Env::new();
    env.server.route(
        WF_PATH,
        Reply::Status {
            code: 429,
            retry_after: Some("3600".into()),
        },
    );
    let wf = env.wordfence(Some(REVIEW));
    assert_eq!(env.run_source(&wf).outcome, Outcome::RateLimited);
    assert_eq!(env.state("wordfence").retry_after_until, Some(T0 + 3600));
    env.server.route(WF_PATH, Reply::ok(feed()));
    env.clock.advance(31 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::RateLimited);
    assert_eq!(env.server.requests(), 1);
    env.clock.set(T0 + 3601);
    assert_eq!(env.run_source(&wf).outcome, Outcome::Loaded);
}

#[test]
fn a_refused_token_says_so_without_the_body() {
    for code in [401, 403] {
        let env = Env::new();
        env.server.route(
            WF_PATH,
            Reply::Status {
                code,
                retry_after: None,
            },
        );
        let report = env.run_source(&env.wordfence(Some(REVIEW)));
        assert_eq!(report.outcome, Outcome::Failed);
        let err = env.state("wordfence").last_error.unwrap();
        assert!(err.contains("jeton refusé"), "{err}");
        assert!(!err.contains("corps") && !err.contains(TOKEN), "{err}");
    }
}

#[test]
fn a_new_loader_version_reloads_the_same_dump() {
    let env = Env::new();
    let wf = env.wordfence(Some(REVIEW));
    assert_eq!(env.run_source(&wf).outcome, Outcome::Loaded);
    let generation = env.state("wordfence").active_generation;
    env.sql()
        .execute(
            "UPDATE vuln_sources SET loader_version = 0 WHERE id = 'wordfence'",
            [],
        )
        .unwrap();
    env.clock.advance(31 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::Loaded);
    assert!(env.state("wordfence").active_generation > generation);
}

// ---------------------------------------------------------------- seuils

/// Flux Wordfence fictif de `good` failles valides et `bad` illisibles.
fn synthetic_feed(good: usize, bad: usize, copyrights: &str) -> Vec<u8> {
    let mut items = Vec::new();
    for n in 0..good + bad {
        let id = format!("00000000-0000-4000-8000-{:012x}", 0x1000 + n);
        if n < good {
            items.push(format!(
                r#""{id}": {{"id": "{id}", "published": "2099-01-01 00:00:00", "copyrights": {copyrights},
                  "software": [{{"type": "plugin", "slug": "exemple-{n}",
                    "affected_versions": {{"* - 1.0": {{"from_version": "*", "to_version": "1.0", "to_inclusive": true}}}}}}]}}"#
            ));
        } else {
            items.push(format!(r#""{id}": {{"id": 1, "software": []}}"#));
        }
    }
    format!("{{{}}}", items.join(",")).into_bytes()
}

#[test]
fn the_drop_ratio_counts_only_real_losses() {
    let env = Env::new();
    let wf = env.wordfence(Some(REVIEW));
    env.server
        .route(WF_PATH, Reply::ok(synthetic_feed(90, 10, "{}")));
    let report = env.run_source(&wf);
    assert_eq!(report.outcome, Outcome::Failed, "{}", report.line);
    assert!(report.line.contains("taux d'écart"), "{}", report.line);
    assert_eq!(env.state("wordfence").active_generation, 0);
    // La moitié en `empty_copyrights` : simple note, chargée.
    let mixed: Vec<u8> = {
        let a = String::from_utf8(synthetic_feed(50, 0, "{}")).unwrap();
        a.into_bytes()
    };
    env.server.route(WF_PATH, Reply::ok(mixed));
    env.clock.advance(31 * 60);
    let report = env.run_source(&wf);
    assert_eq!(report.outcome, Outcome::Loaded, "{}", report.line);
    assert!(
        report.line.contains("empty_copyrights 50"),
        "{}",
        report.line
    );
}

// ---------------------------------------------------------------- échecs

#[test]
fn failures_keep_the_active_generation() {
    let mut env = Env::new();
    let wf = env.wordfence(Some(REVIEW));
    assert_eq!(env.run_source(&wf).outcome, Outcome::Loaded);
    assert_eq!(env.run_source(&FriendsOfPresta).outcome, Outcome::Loaded);
    let (wf_gen, fop_gen) = (
        env.state("wordfence").active_generation,
        env.state("friends-of-presta").active_generation,
    );
    // Flux tronqué (syntaxe), puis corps tronqué.
    let body = feed();
    env.server
        .route(WF_PATH, Reply::ok(body[..body.len() / 2].to_vec()));
    env.clock.advance(31 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::Failed);
    env.server.route(
        WF_PATH,
        Reply::Truncated {
            body: body[..100].to_vec(),
            announced: body.len() as u64,
        },
    );
    env.clock.advance(31 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::Failed);
    // Flux trop gros (plafond compressé), puis trop lent.
    env.server.route(WF_PATH, Reply::ok(body.clone()));
    env.limits = Some(Limits {
        compressed: 1024,
        ..wf.meta().limits
    });
    env.clock.advance(31 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::Failed);
    env.server.route(WF_PATH, Reply::Hang);
    env.limits = Some(Limits {
        duration: Duration::from_secs(1),
        ..wf.meta().limits
    });
    env.clock.advance(31 * 60);
    assert_eq!(env.run_source(&wf).outcome, Outcome::Failed);
    // Archive au-delà des plafonds.
    let mut posts = targen::posts(&fixtures().join("friends-of-presta/_posts"));
    posts.push(("2099-03-01-autre.md".into(), posts[0].1.clone()));
    env.server
        .route("/codeload/main.tar.gz", Reply::ok(targen::archive(&posts)));
    env.limits = Some(Limits {
        unpacked: 4096,
        ..FriendsOfPresta.meta().limits
    });
    let report = env.run_source(&FriendsOfPresta);
    assert_eq!(report.outcome, Outcome::Failed, "{}", report.line);
    assert_eq!(env.state("wordfence").active_generation, wf_gen);
    assert_eq!(env.state("friends-of-presta").active_generation, fop_gen);
    assert_eq!(env.count("wordfence"), 15);
    assert_eq!(env.count("friends-of-presta"), 12);
}

// ---------------------------------------------------------------- jeton

fn token_env() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    private_dir(&keys);
    (dir, keys)
}

#[test]
fn token_grammar_and_size() {
    let (_dir, keys) = token_env();
    let path = keys.join("token");
    private_file(&path, format!("{TOKEN}\r\n").as_bytes());
    let token = read_token(&path).unwrap();
    assert_eq!(token.expose(), TOKEN);
    assert_eq!(format!("{token:?}"), "Token(***)");
    assert!(token.header().is_sensitive());
    for bad in [
        format!("{TOKEN} x"),
        format!("{TOKEN}\nx"),
        "a".repeat(15),
        "a".repeat(513),
        "a".repeat(10 * 1024 * 1024),
    ] {
        private_file(&path, bad.as_bytes());
        let err = read_token(&path).expect_err("refusé");
        assert!(!err.to_string().contains(TOKEN), "{err}");
    }
}

#[cfg(unix)]
#[test]
fn unsafe_token_files_are_refused_before_any_request() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, keys) = token_env();
    let path = keys.join("token");
    private_file(&path, TOKEN.as_bytes());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_token(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read_token(&path).is_err());
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(read_token(&path).is_ok());
    let link = keys.join("lien");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_token(&link).is_err());
    // FIFO à la place du fichier : refusée sans bloquer.
    let fifo = keys.join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: chemin C valide, terminé par un octet nul.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert!(read_token(&fifo).is_err());

    // Par la source : aucune requête, message sans le jeton.
    let env = Env::new();
    let token_file = env.wf_config().token_file;
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let report = env.run_source(&env.wordfence(Some(REVIEW)));
    assert_eq!(report.outcome, Outcome::Failed);
    assert!(
        report.line.contains("jeton Wordfence illisible"),
        "{}",
        report.line
    );
    assert!(!report.line.contains(TOKEN));
    assert_eq!(env.server.requests(), 0);
}
