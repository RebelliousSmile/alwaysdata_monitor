//! Vecteurs de `/r/v1/inventory` écrits par l'agent PHP
//! (`agent/php/tests/make-interop-fixture.php`, `fixtures/inventory-vectors.json`) :
//! chaque corps, signé par sodium sous son propre domaine, est rejoué contre
//! le routeur de `serve`. Seul l'inventaire signé sur `vigie-inventory-v1\n`
//! est accepté ; un rapport, un retrait, un lot de logs ou un inventaire sans
//! préfixe sont refusés.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use tower::ServiceExt;

#[path = "support/veilleur.rs"]
mod veilleur;

use vigie::clock::FakeClock;
use vigie::command::key::DOMAIN_INVENTORY;
use vigie::config::{InventorySource, SiteInventory, SiteKind};
use vigie::ingest::{HEADER_SIGNATURE, HEADER_SITE};
use vigie::serve;
use vigie::store::Store;

#[derive(Deserialize)]
struct Vectors {
    domain: String,
    public_key: String,
    now: i64,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    body: String,
    signature: String,
    status: u16,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("fixtures/inventory-vectors.json")).expect("vecteurs")
}

#[test]
fn the_php_domain_is_the_watcher_domain() {
    assert_eq!(vectors().domain.as_bytes(), DOMAIN_INVENTORY);
}

#[tokio::test]
async fn each_vector_gets_its_status_from_the_router() {
    let v = vectors();
    let names: Vec<&str> = v.vectors.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "valid",
            "report-replayed",
            "pull-replayed",
            "logs-replayed",
            "unprefixed"
        ]
    );
    let public: [u8; 32] = STANDARD
        .decode(&v.public_key)
        .expect("base64")
        .try_into()
        .expect("32 octets");
    for vector in &v.vectors {
        // Base neuve par vecteur : aucun ne dépend d'un `seq` déjà vu.
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("vigie.db");
        Store::open(&database)
            .expect("base")
            .add_key("site-a", &public, v.now - 600)
            .expect("add_key");
        let mut config = veilleur::config(database.clone());
        config.sites[0].kind = SiteKind::Wordpress;
        config.sites[0].inventory = Some(SiteInventory::new(&[InventorySource::AgentPhp]));
        let router = serve::router_with_clock(config, Arc::new(FakeClock::new(v.now)));
        let request = Request::post("/r/v1/inventory")
            .header(HEADER_SITE, "site-a")
            .header(HEADER_SIGNATURE, &vector.signature)
            .body(Body::from(vector.body.clone()))
            .expect("requête");
        let status = router.oneshot(request).await.expect("réponse").status();
        assert_eq!(
            status,
            StatusCode::from_u16(vector.status).expect("statut"),
            "{}",
            vector.name
        );
        let stored = Store::open(&database)
            .expect("base")
            .last_inventory("site-a", vigie::inventory::Source::Agent)
            .expect("lecture")
            .is_some();
        assert_eq!(stored, vector.status == 204, "{}", vector.name);
    }
}
