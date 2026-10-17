//! `POST /r/v1/inventory` : inventaire des composants poussé par l'agent d'un
//! site (issue #19) ou par `vigie-inventory` en CI (issue #20,
//! `docs/protocole-agent.md`).
//!
//! Vérifications, dans l'ordre, arrêt au premier échec (404 commun, raison
//! fixe au journal) :
//!
//! 1. **avant de lire le corps** ([`gate`]) : `X-Vigie-Site` bien formé, site
//!    connu, `[sites.inventory]` déclarée, au moins une source déclarée dont
//!    la clé est enregistrée (clé d'agent pour `agent-php`, clé d'inventaire
//!    pour `ci`), en-tête de signature présent ;
//! 2. corps de 512 Kio au plus en 10 s (`serve`) ;
//! 3. **hors du writer** ([`verify`]) : signature sur
//!    `vigie-inventory-v1\n` + octets du corps, essayée avec la clé d'agent
//!    puis la clé d'inventaire : la clé qui vérifie **fixe la source** (aucun
//!    en-tête ni champ non signé ne la choisit) ; liste blanche, `source` de
//!    l'enveloppe égale à la source fixée, purl, liste canonique et digest,
//!    horloge ±300 s ;
//! 4. **dans le writer** ([`store`], `Store::accept_inventory`) : clé
//!    inchangée, `seq`, débit, plafond quotidien, écriture, par
//!    (site, source).
//!
//! Le journal ne porte que des raisons fixes et des nombres : jamais le texte
//! d'erreur de serde, ni un nom, une version ou un purl reçu.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;

use super::{Inventory, Source, bom};
use crate::capability;
use crate::command::key::{self, DOMAIN_INVENTORY};
use crate::config::{Config, InventorySource, SiteKind, is_valid_id};
use crate::ingest::{Reason, Refusal};
use crate::report::MAX_CLOCK_SKEW;
use crate::store::{InventoryDoc, InventoryOutcome, Store};

pub const ROUTE: &str = "/r/v1/inventory";

/// Site admis par la porte : ce qu'il faut pour vérifier le corps ensuite.
#[derive(Debug, Clone)]
pub struct Opened {
    pub site: String,
    pub kind: SiteKind,
    /// Clés des sources déclarées et enregistrées, dans l'ordre d'essai :
    /// clé d'agent, puis clé d'inventaire.
    pub keys: Vec<(Source, [u8; 32])>,
    pub signature: String,
}

impl Opened {
    /// Clé de la source fixée par la signature.
    fn key(&self, source: Source) -> Option<&[u8; 32]> {
        self.keys
            .iter()
            .find(|(s, _)| *s == source)
            .map(|(_, key)| key)
    }
}

/// Ce qu'un inventaire accepté a fait, pour le journal : des nombres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub site: String,
    pub source: Source,
    pub seq: i64,
    pub components: usize,
    /// Composants écartés à la réception, par raison fixe.
    pub dropped: BTreeMap<&'static str, usize>,
    pub skipped: i64,
    pub complete: bool,
    /// Faux pour un renvoi inchangé.
    pub new: bool,
}

/// Porte, avant toute lecture du corps. `store` : connexion de lecture, `None`
/// sans base (refusé comme un site inconnu).
pub fn gate(
    store: Option<&Store>,
    config: &Config,
    site_header: Option<&str>,
    signature_header: Option<&str>,
) -> Result<Opened, Refusal> {
    let refuse = |reason| Refusal::new(site_header, reason);
    let site_id = site_header
        .filter(|s| is_valid_id(s))
        .ok_or_else(|| refuse(Reason::MissingSite))?;
    let site = config
        .sites
        .iter()
        .find(|s| s.id == site_id)
        .ok_or_else(|| refuse(Reason::UnknownSite))?;
    let mut sources = capability::inventory_sources(site);
    if sources.is_empty() {
        return Err(refuse(Reason::InventoryClosed));
    }
    let store = store.ok_or_else(|| refuse(Reason::UnknownSite))?;
    let internal = |e: anyhow::Error| refuse(Reason::Internal(format!("{e:#}")));
    // Ordre d'essai fixe : clé d'agent, puis clé d'inventaire.
    sources.sort_unstable();
    let mut keys = Vec::with_capacity(sources.len());
    for source in sources {
        let key = match source {
            InventorySource::AgentPhp => store.agent(site_id).map_err(internal)?.map(|a| a.pubkey),
            InventorySource::Ci => store.inventory_key(site_id).map_err(internal)?,
        };
        if let Some(key) = key {
            keys.push((Source::from(source), key));
        }
    }
    if keys.is_empty() {
        return Err(refuse(Reason::UnknownSite));
    }
    let signature = signature_header.ok_or_else(|| refuse(Reason::MissingSignature))?;
    Ok(Opened {
        site: site_id.to_owned(),
        kind: site.kind,
        keys,
        signature: signature.to_owned(),
    })
}

/// Signature, liste blanche, source, purl, digest et horloge : le travail
/// CPU, hors du writer. `now` en secondes Unix. L'inventaire rendu porte la
/// source fixée par la clé qui a vérifié la signature.
pub fn verify(opened: &Opened, body: &[u8], now: i64) -> Result<Inventory, Refusal> {
    let refuse = |reason| Refusal::new(Some(&opened.site), reason);
    let mut signed_by = None;
    for (source, pubkey) in &opened.keys {
        let key = VerifyingKey::from_bytes(pubkey).map_err(|_| refuse(Reason::BadKey))?;
        if key::verify(&key, DOMAIN_INVENTORY, &[body], &opened.signature) {
            signed_by = Some(*source);
            break;
        }
    }
    let source = signed_by.ok_or_else(|| refuse(Reason::BadSignature))?;
    let inventory = bom::parse(body, &opened.site, opened.kind)
        .map_err(|e| refuse(Reason::Schema(e.0.to_owned())))?;
    if inventory.source != source {
        // Raison fixe : ni la valeur reçue ni la clé.
        return Err(refuse(Reason::Schema("source".to_owned())).with_seq(inventory.seq));
    }
    let skew = inventory.sent_at.saturating_sub(now);
    if skew.saturating_abs() > MAX_CLOCK_SKEW {
        return Err(refuse(Reason::Clock { skew }).with_seq(inventory.seq));
    }
    Ok(inventory)
}

/// Écriture, par la connexion d'écriture de `serve`.
pub fn store(
    store: &mut Store,
    opened: &Opened,
    inventory: &Inventory,
    now: i64,
) -> Result<Received, Refusal> {
    let refuse = |reason| Refusal::new(Some(&opened.site), reason).with_seq(inventory.seq);
    // `verify` a fixé la source par une clé de `opened` : elle y est.
    let pubkey = opened
        .key(inventory.source)
        .ok_or_else(|| refuse(Reason::UnknownSite))?;
    let outcome = store
        .accept_inventory(
            &InventoryDoc {
                site: &opened.site,
                source: inventory.source,
                pubkey,
                inventory,
            },
            now,
        )
        .map_err(|e| refuse(Reason::Internal(format!("{e:#}"))))?;
    let new = match outcome {
        InventoryOutcome::Accepted { new, .. } => new,
        InventoryOutcome::UnknownSite => return Err(refuse(Reason::UnknownSite)),
        InventoryOutcome::Replay { last_seq } => {
            return Err(refuse(Reason::Replay {
                seq: inventory.seq,
                last_seq,
            }));
        }
        InventoryOutcome::TooSoon { seen_at } => {
            return Err(refuse(Reason::TooSoon {
                last_valid_at: seen_at,
            }));
        }
        InventoryOutcome::Quota { new_today } => {
            return Err(refuse(Reason::InventoryQuota { new_today }));
        }
    };
    Ok(Received {
        site: opened.site.clone(),
        source: inventory.source,
        seq: inventory.seq,
        components: inventory.components.len(),
        dropped: inventory.dropped.clone(),
        skipped: inventory.skipped,
        complete: inventory.complete,
        new,
    })
}
