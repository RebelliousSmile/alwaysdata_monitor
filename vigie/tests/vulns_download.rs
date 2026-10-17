//! Téléchargeur borné et dossier de travail (`vulns/sync/download.rs`,
//! `workdir.rs`) contre deux instances du serveur HTTPS local
//! (`support/dump_server.rs`, même autorité de test). Aucun réseau.

#[path = "support/dump_server.rs"]
mod dump_server;

use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use url::Url;

use vigie::http::{Trust, agent};
use vigie::vulns::sync::download::{Download, Fetched, Received, Request, Validators};
use vigie::vulns::sync::origin::Origins;
use vigie::vulns::sync::workdir::{DISK_RESERVE, WorkDir};
use vigie::vulns::sync::{Limits, SyncError};

use dump_server::{DumpServer, Reply};

const SOURCE: &str = "osv-test";
const LM: &str = "Sat, 17 Oct 2026 03:00:00 GMT";

fn limits() -> Limits {
    Limits {
        compressed: 1024 * 1024,
        unpacked: 4 * 1024 * 1024,
        entries: 1000,
        entry: 1024 * 1024,
        central_directory: 1024 * 1024,
        duration: Duration::from_secs(2),
        max_dropped_ratio: 0.01,
    }
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Téléchargeur admis vers les origines données, échéance de 2 s.
fn download(base: &Path, ca: &DumpServer, admitted: &[&DumpServer], v: Validators) -> Download {
    let urls: Vec<Url> = admitted.iter().map(|s| s.base()).collect();
    let refs: Vec<&Url> = urls.iter().collect();
    Download::new(
        agent(&Trust::Custom(vec![ca.ca.clone()]), Duration::from_secs(2)),
        Origins::pinned(&refs).expect("origines"),
        v,
        limits(),
        Instant::now() + Duration::from_secs(2),
        WorkDir::prepare(base, SOURCE).expect("dossier de travail"),
    )
}

fn get(dl: &mut Download, url: &str) -> Result<Fetched, SyncError> {
    dl.get_to_file(&Request::get(Url::parse(url).unwrap()))
}

fn work_files(base: &Path) -> usize {
    std::fs::read_dir(base.join("vulns-work").join(SOURCE))
        .map(|d| d.count())
        .unwrap_or(0)
}

// --- Téléchargement ---

#[test]
fn ok_with_validators_writes_a_private_file() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    let body = b"PK fictif".repeat(100);
    server.route("/all.zip", Reply::ok_etag(body.clone(), "\"v1\"", LM));
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    let Fetched::Dump(dump) = get(&mut dl, &server.url("/all.zip")).unwrap() else {
        panic!("dump attendu");
    };
    assert_eq!(std::fs::read(&dump.path).unwrap(), body);
    assert_eq!(dump.sha256, sha(&body));
    assert_eq!(dump.bytes, body.len() as u64);
    assert_eq!(
        dump.validators,
        Received {
            etag: Some("\"v1\"".into()),
            last_modified: Some(LM.into()),
        }
    );
    assert!(
        dump.path
            .starts_with(dir.path().join("vulns-work").join(SOURCE))
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dump.path), 0o600);
        assert_eq!(mode(&dir.path().join("vulns-work").join(SOURCE)), 0o700);
        assert_eq!(mode(&dir.path().join("vulns-work")), 0o700);
    }
    let seen = server.seen();
    assert_eq!(seen[0].header("accept-encoding"), Some("identity"));
    assert_eq!(seen[0].header("if-none-match"), None);
    drop(dl);
    assert_eq!(work_files(dir.path()), 0, "dossier vidé à la fin");
}

#[test]
fn known_validators_and_304_give_not_modified() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route("/all.zip", Reply::ok_etag(b"dump".to_vec(), "\"v1\"", LM));
    let v = Validators {
        etag: Some("\"v1\"".into()),
        last_modified: Some(LM.into()),
        active_sha256: Some(sha(b"dump")),
        conditional: true,
    };
    let mut dl = download(dir.path(), &server, &[&server], v);
    assert_eq!(
        get(&mut dl, &server.url("/all.zip")).unwrap(),
        Fetched::NotModified
    );
    let seen = server.seen();
    assert_eq!(seen[0].header("if-none-match"), Some("\"v1\""));
    assert_eq!(seen[0].header("if-modified-since"), Some(LM));
    assert_eq!(work_files(dir.path()), 0);
}

#[test]
fn non_conditional_validators_send_nothing_and_ignore_the_digest() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route("/all.zip", Reply::ok_etag(b"dump".to_vec(), "\"v1\"", LM));
    let v = Validators {
        etag: Some("\"v1\"".into()),
        last_modified: Some(LM.into()),
        active_sha256: Some(sha(b"dump")),
        conditional: false,
    };
    let mut dl = download(dir.path(), &server, &[&server], v);
    assert!(matches!(
        get(&mut dl, &server.url("/all.zip")).unwrap(),
        Fetched::Dump(_)
    ));
    let seen = server.seen();
    assert_eq!(seen[0].header("if-none-match"), None);
    assert_eq!(seen[0].header("if-modified-since"), None);
}

#[test]
fn same_digest_as_the_active_dump() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route("/all.zip", Reply::ok(b"dump".to_vec()));
    let v = Validators {
        active_sha256: Some(sha(b"dump")),
        conditional: true,
        ..Validators::default()
    };
    let mut dl = download(dir.path(), &server, &[&server], v);
    assert_eq!(
        get(&mut dl, &server.url("/all.zip")).unwrap(),
        Fetched::SameDigest {
            validators: Received::default(),
            bytes: 4
        }
    );
    assert_eq!(work_files(dir.path()), 0, "aucun fichier gardé");
}

#[test]
fn oversize_bodies_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route("/huge", Reply::HugeLength);
    server.route("/endless", Reply::Endless);
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    assert_eq!(
        get(&mut dl, &server.url("/huge")),
        Err(SyncError::TooLarge {
            what: "dump compressé (Content-Length)"
        })
    );
    assert_eq!(
        get(&mut dl, &server.url("/endless")),
        Err(SyncError::TooLarge {
            what: "dump compressé"
        })
    );
    assert_eq!(work_files(dir.path()), 0, "fichier partiel supprimé");
}

#[test]
fn truncated_body_fails_and_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route(
        "/all.zip",
        Reply::Truncated {
            body: vec![1; 1000],
            announced: 5000,
        },
    );
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    assert_eq!(
        get(&mut dl, &server.url("/all.zip")),
        Err(SyncError::Truncated)
    );
    assert_eq!(work_files(dir.path()), 0);
}

#[test]
fn unexpected_content_encoding_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route(
        "/all.zip",
        Reply::Ok {
            body: std::sync::Arc::new(b"\x1f\x8b".to_vec()),
            etag: None,
            last_modified: None,
            content_encoding: Some("gzip".into()),
        },
    );
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    let err = get(&mut dl, &server.url("/all.zip")).unwrap_err();
    assert_eq!(err.to_string(), "encodage de contenu inattendu : gzip");
}

#[test]
fn statuses_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    let status = |code, retry_after: Option<&str>| Reply::Status {
        code,
        retry_after: retry_after.map(str::to_owned),
    };
    server.route("/500", status(500, None));
    server.route("/429", status(429, Some("3600")));
    server.route("/429-long", status(429, Some("999999")));
    server.route("/401", status(401, None));
    server.route("/403", status(403, None));
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    assert_eq!(
        get(&mut dl, &server.url("/500")),
        Err(SyncError::Status {
            code: 500,
            retry_after: None
        })
    );
    assert_eq!(
        get(&mut dl, &server.url("/429")),
        Err(SyncError::Status {
            code: 429,
            retry_after: Some(3600)
        })
    );
    assert_eq!(
        get(&mut dl, &server.url("/429-long")),
        Err(SyncError::Status {
            code: 429,
            retry_after: Some(86_400)
        })
    );
    assert_eq!(
        get(&mut dl, &server.url("/401")),
        Err(SyncError::Unauthorized)
    );
    assert_eq!(get(&mut dl, &server.url("/403")), Err(SyncError::Forbidden));
}

#[test]
fn silent_server_fails_within_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route("/all.zip", Reply::Hang);
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    let started = Instant::now();
    assert_eq!(
        get(&mut dl, &server.url("/all.zip")),
        Err(SyncError::Deadline)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn refused_urls_never_connect() {
    let dir = tempfile::tempdir().unwrap();
    let servers = DumpServer::start_many(2);
    let (a, b) = (&servers[0], &servers[1]);
    let mut dl = download(dir.path(), a, &[a], Validators::default());
    for url in [
        format!("http://127.0.0.1:{}/all.zip", a.port),
        b.url("/all.zip"),
        format!("https://localhost:{}/all.zip", a.port),
        format!("https://user:pass@127.0.0.1:{}/all.zip", a.port),
    ] {
        assert_eq!(get(&mut dl, &url), Err(SyncError::OriginRefused), "{url}");
    }
    assert_eq!(a.requests(), 0);
    assert_eq!(b.requests(), 0);
}

#[test]
fn redirects_are_rechecked() {
    let dir = tempfile::tempdir().unwrap();
    let servers = DumpServer::start_many(2);
    let (a, b) = (&servers[0], &servers[1]);
    b.route("/all.zip", Reply::ok(b"dump".to_vec()));
    a.route("/vers-b", Reply::Redirect(b.url("/all.zip")));
    a.route(
        "/vers-http",
        Reply::Redirect(format!("http://127.0.0.1:{}/all.zip", b.port)),
    );
    a.route("/boucle", Reply::Redirect("/boucle".into()));
    // Admise : vers la seconde origine.
    let mut both = download(dir.path(), a, &[a, b], Validators::default());
    assert!(matches!(
        get(&mut both, &a.url("/vers-b")).unwrap(),
        Fetched::Dump(_)
    ));
    assert_eq!(b.requests(), 1);
    assert_eq!(
        get(&mut both, &a.url("/vers-http")),
        Err(SyncError::OriginRefused)
    );
    assert_eq!(
        get(&mut both, &a.url("/boucle")),
        Err(SyncError::Redirect("plus de 3 redirections"))
    );
    assert_eq!(a.seen().iter().filter(|s| s.path == "/boucle").count(), 4);
    drop(both);
    // Même hôte, autre port, non admis : aucune requête vers b.
    b.reset();
    let mut only_a = download(dir.path(), a, &[a], Validators::default());
    assert_eq!(
        get(&mut only_a, &a.url("/vers-b")),
        Err(SyncError::OriginRefused)
    );
    assert_eq!(b.requests(), 0);
}

#[test]
fn sensitive_headers_stay_with_the_first_origin() {
    let dir = tempfile::tempdir().unwrap();
    let servers = DumpServer::start_many(2);
    let (a, b) = (&servers[0], &servers[1]);
    b.route("/all.zip", Reply::ok(b"dump".to_vec()));
    a.route("/vers-b", Reply::Redirect(b.url("/all.zip")));
    let mut dl = download(dir.path(), a, &[a, b], Validators::default());
    let request = Request {
        url: Url::parse(&a.url("/vers-b")).unwrap(),
        sensitive_headers: vec![("Authorization".into(), "Bearer jeton-de-test".into())],
    };
    assert!(matches!(
        dl.get_to_file(&request).unwrap(),
        Fetched::Dump(_)
    ));
    assert_eq!(
        a.seen()[0].header("authorization"),
        Some("Bearer jeton-de-test")
    );
    assert_eq!(b.seen()[0].header("authorization"), None);
    assert!(!format!("{request:?}").contains("jeton-de-test"));
}

#[test]
fn hostile_validators_are_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route(
        "/long",
        Reply::ok_etag(b"a".to_vec(), &"e".repeat(300), "pas une date"),
    );
    server.route(
        "/controle",
        Reply::ok_etag(b"b".to_vec(), "\"a\tb\"", "Sat, 17 Oct 2026 25:00:00 GMT"),
    );
    let mut dl = download(dir.path(), &server, &[&server], Validators::default());
    for path in ["/long", "/controle"] {
        let Fetched::Dump(dump) = get(&mut dl, &server.url(path)).unwrap() else {
            panic!("dump attendu");
        };
        assert_eq!(dump.validators, Received::default(), "{path}");
    }
}

// --- Dossier de travail ---

#[test]
fn workdir_is_created_private_and_cleared() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("vulns-work").join(SOURCE);
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("dump-1.part"), b"reste d'un passage interrompu").unwrap();
    let wd = WorkDir::prepare(dir.path(), SOURCE).expect("préparé");
    assert_eq!(work_files(dir.path()), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&work).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    let (_file, path) = wd.create_file("dump-1.part").expect("créé");
    assert!(path.exists());
    assert!(wd.create_file("dump-1.part").is_err(), "create_new");
    assert!(wd.create_file("../x").is_err());
    drop(wd);
    assert_eq!(work_files(dir.path()), 0, "vidé à la fin");
    assert!(WorkDir::prepare(dir.path(), "../evasion").is_err());
}

#[cfg(unix)]
#[test]
fn workdir_replaced_by_a_symlink_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("vulns-work")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("vulns-work").join(SOURCE))
        .unwrap();
    std::fs::write(elsewhere.path().join("garde.txt"), b"x").unwrap();
    assert!(WorkDir::prepare(dir.path(), SOURCE).is_err());
    assert!(elsewhere.path().join("garde.txt").exists(), "rien suivi");
}

#[test]
fn workdir_is_cleared_after_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let server = DumpServer::start();
    server.route(
        "/all.zip",
        Reply::Truncated {
            body: vec![1; 10],
            announced: 50,
        },
    );
    {
        let mut dl = download(dir.path(), &server, &[&server], Validators::default());
        assert!(get(&mut dl, &server.url("/all.zip")).is_err());
    }
    assert_eq!(work_files(dir.path()), 0);
}

#[test]
fn insufficient_free_space_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let wd = WorkDir::prepare(dir.path(), SOURCE)
        .unwrap()
        .with_free_space(Some(DISK_RESERVE + 100));
    assert!(wd.ensure_space(100).is_ok());
    assert_eq!(
        wd.ensure_space(101),
        Err(SyncError::Disk {
            needed: DISK_RESERVE + 101,
            available: DISK_RESERVE + 100
        })
    );
    // Avant le dump : le téléchargeur contrôle la taille annoncée.
    let server = DumpServer::start();
    server.route("/all.zip", Reply::ok(vec![0; 1000]));
    let mut dl = Download::new(
        agent(
            &Trust::Custom(vec![server.ca.clone()]),
            Duration::from_secs(2),
        ),
        Origins::pinned(&[&server.base()]).unwrap(),
        Validators::default(),
        limits(),
        Instant::now() + Duration::from_secs(2),
        WorkDir::prepare(dir.path(), SOURCE)
            .unwrap()
            .with_free_space(Some(DISK_RESERVE + 999)),
    );
    assert!(matches!(
        get(&mut dl, &server.url("/all.zip")),
        Err(SyncError::Disk { .. })
    ));
}
