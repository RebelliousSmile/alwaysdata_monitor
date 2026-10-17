//! `/api/v1` du rapprochement (#21, phase 4) : composants, failles et
//! sources, contre le routeur de `serve` en processus, sur une base
//! rapprochée par `tick::run_with_sources`. Données fictives seulement.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use vigie::clock::{Clock, FakeClock};
use vigie::config::{InventorySource, SiteKind};
use vigie::device::{self, PAIRING_TTL};
use vigie::inventory::Source;
use vigie::serve;
use vigie::vulns::advisory::Advisory;
use vigie::vulns::version::Scheme;

#[path = "support/match_harness.rs"]
mod match_harness;
#[path = "support/matching_data.rs"]
mod matching_data;
use match_harness::*;
use matching_data::*;

const VULNS: &[&str] = &["osv-packagist", "wordfence"];
const PEER: &str = "192.0.2.10:40000";
const PATH_SEED: &str = "chemin-seme/propre-au-site";
const REASON_SEED: &str = "motif-de-derogation-seme";
const OPERATOR_SEED: &str = "operateur-seme";

fn wf(id: &str, cve: &str, score: u8, attribution: &str) -> Advisory {
    let aliases = [cve];
    let ranges = [("0", "1.2.4")];
    build(&Fake {
        id,
        aliases: &aliases,
        purl: PLUGIN,
        scheme: Scheme::Php,
        ranges: &ranges,
        score: Some(score),
        attribution,
        ..Fake::default()
    })
}

struct Api {
    h: Harness,
    clock: Arc<FakeClock>,
    router: Router,
    token: String,
}

impl Api {
    async fn new(h: Harness) -> Self {
        let clock = Arc::new(FakeClock::new(T0 + 600));
        let router = serve::router_with_clock(
            h.config.borrow().clone(),
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let mut api = Self {
            h,
            clock,
            router,
            token: String::new(),
        };
        let code = device::new_code().unwrap();
        let now = api.clock.unix();
        api.h
            .store()
            .create_pairing(&device::hash(&code), "poste", now, now + PAIRING_TTL)
            .unwrap();
        let body = serde_json::json!({ "code": code }).to_string();
        let request = Request::post("/api/v1/pair")
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(Body::from(body))
            .unwrap();
        let (status, reply) = api.send(request).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        api.token = reply["token"].as_str().unwrap().to_owned();
        api
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self
            .router
            .clone()
            .layer(MockConnectInfo(
                PEER.parse::<std::net::SocketAddr>().unwrap(),
            ))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, value)
    }

    async fn call(&self, method: Method, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.call(Method::GET, path, Some(&self.token)).await
    }
}

/// Site A WordPress (agent), site B sans inventaire : une extension
/// critique sous Wordfence, un paquet touché par une GHSA, trois paquets
/// sans faille.
async fn populated() -> Api {
    let h = Harness::new(
        vec![
            site("site-a", SiteKind::Wordpress, &[InventorySource::AgentPhp]),
            site("site-b", SiteKind::Wordpress, &[]),
            site("site-c", SiteKind::Wordpress, &[InventorySource::AgentPhp]),
        ],
        VULNS,
    );
    h.load(
        "wordfence",
        &[wf(
            "WF-2099-0002",
            "CVE-2099-0002",
            95,
            "Exemple Intelligence SARL\u{1b}[2J\u{202e} attribution fictive",
        )],
        T0,
    );
    let aliases = ["CVE-2099-0003"];
    h.load(
        "osv-packagist",
        &[build(&Fake {
            id: "GHSA-2099-aaaa-0003",
            aliases: &aliases,
            score: Some(75),
            ..Fake::default()
        })],
        T0,
    );
    let plugin = format!("{PLUGIN}@1.2.3");
    let paquet = format!("{PAQUET}@1.2.3");
    h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[
            (&plugin, PATH_SEED),
            (&paquet, "vendor"),
            ("pkg:npm/sans-faille-a@1.0.0", "package.json"),
            ("pkg:npm/sans-faille-b@1.0.0", "package.json"),
            ("pkg:npm/sans-faille-c@1.0.0", "package.json"),
        ],
        T0,
    );
    h.tick(T0 + 60);
    Api::new(h).await
}

#[tokio::test]
async fn components_are_listed_by_severity_without_paths() {
    let api = populated().await;
    let (status, body) = api.get("/api/v1/sites/site-a/components").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["site"], "site-a");
    assert!(body["runs"]["agent"].is_i64());
    assert!(body["runs"]["ci"].is_null());
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    assert_eq!(items[0]["purl"], PLUGIN);
    assert_eq!(items[0]["severity"], "critical");
    assert_eq!(items[0]["version"], "1.2.3");
    assert_eq!(items[0]["vulns"], 1);
    assert_eq!(items[0]["source"], "agent");
    assert_eq!(items[1]["purl"], PAQUET);
    assert!(items[4]["severity"].is_null());
    assert!(body["next_cursor"].is_null());
    assert!(!body.to_string().contains(PATH_SEED), "jamais vigie:path");
}

#[tokio::test]
async fn vulns_embed_their_component_versions_and_attributions() {
    let api = populated().await;
    api.h
        .raw()
        .execute(
            "INSERT INTO vuln_waivers (site, source, base, advisory_ref, version, covered_ids,
                 reason, until, operator, created_at, audit_hash)
             VALUES ('site-a', 'agent', ?1, 'CVE-2099-0003', '1.2.3',
                 '[\"CVE-2099-0003\",\"GHSA-2099-aaaa-0003\"]', ?2, ?3, ?4, ?5, 'h')",
            rusqlite::params![PAQUET, REASON_SEED, T0 + 30 * DAY, OPERATOR_SEED, T0],
        )
        .unwrap();
    let (status, body) = api.get("/api/v1/sites/site-a/vulns").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{body}");
    let first = &items[0];
    assert_eq!(first["group"], "CVE-2099-0002");
    assert_eq!(first["component"], PLUGIN);
    assert_eq!(first["versions"][0]["source"], "agent");
    assert_eq!(first["versions"][0]["version"], "1.2.3");
    assert_eq!(first["verdict"], "affected");
    assert_eq!(first["fixed"][0], "1.2.4");
    assert_eq!(first["severity"], "critical");
    assert_eq!(first["score"], 95);
    assert_eq!(first["redistribution"], "internal");
    assert_eq!(
        first["links"][0]["url"],
        "https://example.org/avis/WF-2099-0002"
    );
    assert_eq!(
        first["attributions"][0],
        "Exemple Intelligence SARL\u{fffd}[2J\u{fffd} attribution fictive"
    );
    let second = &items[1];
    assert_eq!(second["waiver"]["state"], "valid");
    assert_eq!(second["waiver"]["source"], "agent");
    let text = body.to_string();
    for seed in [REASON_SEED, OPERATOR_SEED, PATH_SEED, "Faille fictive"] {
        assert!(!text.contains(seed), "{seed} servi");
    }
}

#[tokio::test]
async fn sources_report_age_attribution_dataset_and_open_sync_incident() {
    let api = populated().await;
    let (status, body) = api.get("/api/v1/vulns/sources").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sources = body["sources"].as_array().unwrap();
    let ids: Vec<&str> = sources.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["osv-packagist", "wordfence", "kev", "epss"]);
    let wordfence = &sources[1];
    assert_eq!(wordfence["kind"], "vulns");
    assert_eq!(wordfence["entries"], 1);
    assert_eq!(wordfence["redistribution"], "internal");
    assert_eq!(
        wordfence["attribution"],
        "Attribution fictive de la source wordfence"
    );
    let kev = &sources[2];
    assert_eq!(kev["kind"], "enrichment");
    assert!(kev["last_success_at"].is_null(), "jamais chargé");
    assert!(kev["dataset"].is_null());
    assert!(kev["incident"].is_null());

    // Aucune source déclarée : liste vide.
    let h = Harness::new(
        vec![site(
            "site-a",
            SiteKind::Wordpress,
            &[InventorySource::AgentPhp],
        )],
        &[],
    );
    h.config.borrow_mut().vulns = None;
    let api = Api::new(h).await;
    let (_, body) = api.get("/api/v1/vulns/sources").await;
    assert_eq!(body["sources"], serde_json::json!([]));
}

#[tokio::test]
async fn a_vulns_incident_is_served_sanitized_line_by_line() {
    let api = populated().await;
    let incident = api.h.open("site-a")[0].clone();
    let (status, body) = api.get(&format!("/api/v1/incidents/{}", incident.id)).await;
    assert_eq!(status, StatusCode::OK);
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.contains('\n'), "lignes gardées");
    assert!(!detail.contains('\u{1b}') && !detail.contains('\u{202e}'));
    assert!(detail.chars().count() <= 4_096);
}

#[tokio::test]
async fn pages_hold_still_until_a_run_is_switched() {
    let api = populated().await;
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(c) => format!("/api/v1/sites/site-a/components?limit=2&cursor={c}"),
            None => "/api/v1/sites/site-a/components?limit=2".to_owned(),
        };
        let (status, body) = api.get(&path).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        pages += 1;
        for item in body["items"].as_array().unwrap() {
            seen.push(item["purl"].as_str().unwrap().to_owned());
        }
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!((seen.len(), unique.len()), (5, 5), "sans doublon ni trou");

    // Un run basculé entre deux pages (réévaluation KEV) : 409.
    let (_, first) = api.get("/api/v1/sites/site-a/vulns?limit=1").await;
    let next = first["next_cursor"].as_str().unwrap().to_owned();
    api.h.kev(&["CVE-2099-0003"], T0 + 120);
    api.h.tick(T0 + 180);
    let (status, body) = api
        .get(&format!("/api/v1/sites/site-a/vulns?limit=1&cursor={next}"))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "cursor_expired");

    // Curseur forgé, trop long, ou d'une autre route : 400.
    let (_, components) = api.get("/api/v1/sites/site-a/components?limit=1").await;
    let other = components["next_cursor"].as_str().unwrap().to_owned();
    for bad in [URL_SAFE_NO_PAD.encode("f1|x|-|0"), "a".repeat(257), other] {
        let (status, _) = api
            .get(&format!("/api/v1/sites/site-a/vulns?cursor={bad}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn unknown_unwatched_or_unmatched_sites_are_the_same_404() {
    let api = populated().await;
    let mut bodies = Vec::new();
    for site in ["inconnu", "site-b", "site-c"] {
        for route in ["components", "vulns"] {
            let (status, body) = api.get(&format!("/api/v1/sites/{site}/{route}")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{site}/{route}");
            bodies.push(body["error"]["code"].clone());
        }
    }
    assert!(bodies.iter().all(|c| *c == "not_found"));
    for method in [Method::POST, Method::OPTIONS, Method::DELETE] {
        for path in [
            "/api/v1/sites/site-a/components",
            "/api/v1/sites/site-a/vulns",
            "/api/v1/vulns/sources",
        ] {
            let (status, _) = api.call(method.clone(), path, Some(&api.token)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
    // Sans jeton : 401.
    for path in [
        "/api/v1/sites/site-a/components",
        "/api/v1/sites/site-a/vulns",
        "/api/v1/vulns/sources",
    ] {
        let (status, _) = api.call(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn a_critical_vulns_incident_makes_the_site_non_compliant() {
    let api = populated().await;
    let (_, overview) = api.get("/api/v1/overview").await;
    let site_a = overview["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "site-a")
        .unwrap()
        .clone();
    assert_eq!(site_a["state"], "non_compliant");

    // Information seulement : ne compte pas.
    let h = Harness::new(
        vec![site(
            "site-a",
            SiteKind::Wordpress,
            &[InventorySource::AgentPhp],
        )],
        VULNS,
    );
    h.load(
        "wordfence",
        &[wf("WF-2099-0004", "CVE-2099-0004", 95, ATTRIBUTION_WF)],
        T0,
    );
    let plugin = format!("{PLUGIN}@1.2.3");
    h.inventory("site-a", Source::Agent, true, &[(&plugin, PATH_SEED)], T0);
    h.tick(T0 + 60);
    h.raw()
        .execute(
            "INSERT INTO vuln_waivers (site, source, base, advisory_ref, version, covered_ids,
                 reason, until, operator, created_at, audit_hash)
             VALUES ('site-a', 'agent', ?1, 'CVE-2099-0004', '1.2.3',
                 '[\"CVE-2099-0004\",\"WF-2099-0004\"]', 'motif', ?2, 'o', ?3, 'h')",
            rusqlite::params![PLUGIN, T0 + 30 * DAY, T0 + 100],
        )
        .unwrap();
    h.tick(T0 + 120);
    assert_eq!(h.open("site-a")[0].severity, vigie::finding::Severity::Info);
    for check in vigie::checks::CheckKind::ALL {
        h.store()
            .record_run("site-a", check.name(), T0 + 100)
            .unwrap();
    }
    let api = Api::new(h).await;
    let (_, overview) = api.get("/api/v1/overview").await;
    assert_eq!(overview["sites"][0]["state"], "ok", "{overview}");
}
