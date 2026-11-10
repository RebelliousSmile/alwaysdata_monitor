//! Journal d'audit du canal de commandes : une chaîne par site, en ajout
//! seul (déclencheurs SQLite qui refusent `UPDATE` et `DELETE`).
//!
//! Chaque entrée est sérialisée une fois ; ses octets sont stockés tels quels
//! et c'est sur eux que porte le hash : `hash = SHA-256(hash précédent ‖
//! octets)`, le premier hash précédent valant 32 octets nuls. Le hash est
//! signé par la clé d'audit sur `vigie-audit-v1\n` + hash en hex.
//!
//! Une entrée modifiée ou retirée casse la chaîne ; une fin de chaîne coupée
//! ne se voit que contre une tête connue d'ailleurs : `tick` envoie la tête
//! par e-mail à chaque création et clôture de commande (ancre externe).

use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::key::{self, DOMAIN_AUDIT};

/// Hash précédent de la première entrée d'un site.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Ce qu'une entrée raconte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub site: String,
    /// Secondes Unix.
    pub at: i64,
    /// `enabled`, `disabled`, `created`, `served`, `result`, `result-late`,
    /// `result-rejected`, `expired`, `unknown`, `cancelled`, `key-rotated` ;
    /// `range-corrected`, `range-correction-cleared` (#17, pseudo-site
    /// `_veilleur`) ; `vuln-waived`, `vuln-waiver-revoked` (#21 : `detail` =
    /// purl, faille, échéance, opérateur et `reason_sha256`, jamais le motif).
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    pub detail: String,
    /// Empreinte de la typologie au moment de l'évènement, si elle compte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typology: Option<String>,
}

/// Une ligne du journal, telle qu'exportée en JSONL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Octets JSON de l'entrée, tels que hachés.
    pub entry: String,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `SHA-256(hash précédent ‖ octets de l'entrée)`, en hex minuscule.
pub fn chain_hash(prev_hash: &str, entry: &str) -> Option<String> {
    let prev = unhex(prev_hash).filter(|p| p.len() == 32)?;
    let mut hasher = Sha256::new();
    hasher.update(&prev);
    hasher.update(entry.as_bytes());
    Some(hex(&hasher.finalize()))
}

/// Tête de la chaîne d'un site (`GENESIS` si vide).
pub fn head(tx: &rusqlite::Connection, site: &str) -> rusqlite::Result<String> {
    Ok(tx
        .query_row(
            "SELECT hash FROM command_audit WHERE site = ?1 ORDER BY id DESC LIMIT 1",
            [site],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_else(|| GENESIS.to_owned()))
}

/// Ajoute une entrée dans la transaction de l'évènement qu'elle raconte ;
/// rend le nouveau hash de tête.
pub fn append(tx: &Transaction<'_>, signer: &SigningKey, entry: &Entry) -> anyhow::Result<String> {
    let bytes = serde_json::to_string(entry)?;
    let prev = head(tx, &entry.site)?;
    let hash =
        chain_hash(&prev, &bytes).ok_or_else(|| anyhow::anyhow!("tête d'audit illisible"))?;
    let signature = key::sign(signer, DOMAIN_AUDIT, &[hash.as_bytes()]);
    tx.execute(
        "INSERT INTO command_audit (site, entry, prev_hash, hash, signature) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![entry.site, bytes, prev, hash, signature],
    )?;
    Ok(hash)
}

/// Lignes du journal d'un site, dans l'ordre.
pub fn records(conn: &rusqlite::Connection, site: &str) -> rusqlite::Result<Vec<Record>> {
    let mut stmt = conn.prepare(
        "SELECT entry, prev_hash, hash, signature FROM command_audit WHERE site = ?1 ORDER BY id",
    )?;
    stmt.query_map([site], |row| {
        Ok(Record {
            entry: row.get(0)?,
            prev_hash: row.get(1)?,
            hash: row.get(2)?,
            signature: row.get(3)?,
        })
    })?
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("entrée {index} : {reason}")]
pub struct Broken {
    /// Rang de la première entrée fautive, à partir de 1 ; 0 pour la tête.
    pub index: usize,
    pub reason: String,
}

/// Vérifie une chaîne exportée : lien de chaque entrée à la précédente, hash
/// recalculé sur ses octets, signature, site constant ; puis, si donnée, que
/// la tête vaut la tête attendue (ancre externe).
pub fn verify(
    site: &str,
    records: &[Record],
    public: &VerifyingKey,
    expected_head: Option<&str>,
) -> Result<(), Broken> {
    let mut prev = GENESIS.to_owned();
    for (i, record) in records.iter().enumerate() {
        let broken = |reason: &str| Broken {
            index: i + 1,
            reason: reason.to_owned(),
        };
        if record.prev_hash != prev {
            return Err(broken("ne suit pas l'entrée précédente"));
        }
        if chain_hash(&prev, &record.entry).as_deref() != Some(record.hash.as_str()) {
            return Err(broken("hash faux : entrée modifiée"));
        }
        if !key::verify(
            public,
            DOMAIN_AUDIT,
            &[record.hash.as_bytes()],
            &record.signature,
        ) {
            return Err(broken("signature fausse"));
        }
        let entry: Entry =
            serde_json::from_str(&record.entry).map_err(|_| broken("entrée illisible"))?;
        if entry.site != site {
            return Err(broken("entrée d'un autre site"));
        }
        prev = record.hash.clone();
    }
    if let Some(expected) = expected_head
        && prev != expected
    {
        return Err(Broken {
            index: 0,
            reason: format!("tête {prev}, {expected} attendue : chaîne tronquée ou autre"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use rusqlite::TransactionBehavior;

    fn entry(site: &str, event: &str, at: i64) -> Entry {
        Entry {
            site: site.into(),
            at,
            event: event.into(),
            command_id: None,
            detail: format!("{event} à {at}"),
            typology: None,
        }
    }

    #[test]
    fn a_chain_verifies_and_any_change_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
        let signer = SigningKey::from_bytes(&[3; 32]);
        let public = signer.verifying_key();
        let mut heads = Vec::new();
        for (i, (site, event)) in [
            ("site-a", "enabled"),
            ("site-b", "enabled"),
            ("site-a", "created"),
        ]
        .into_iter()
        .enumerate()
        {
            let tx = store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            heads.push(append(&tx, &signer, &entry(site, event, i as i64)).unwrap());
            tx.commit().unwrap();
        }
        let a = records(&store.conn, "site-a").unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].prev_hash, GENESIS);
        assert_eq!(a[1].prev_hash, a[0].hash);
        assert_eq!(verify("site-a", &a, &public, Some(&heads[2])), Ok(()));
        assert_eq!(
            verify(
                "site-b",
                &records(&store.conn, "site-b").unwrap(),
                &public,
                None
            ),
            Ok(())
        );

        // Entrée modifiée.
        let mut altered = a.clone();
        altered[0].entry = altered[0].entry.replace("enabled", "disabled");
        assert_eq!(
            verify("site-a", &altered, &public, None).unwrap_err().index,
            1
        );
        // Fin coupée : invisible sans ancre, vue contre la tête attendue.
        assert_eq!(verify("site-a", &a[..1], &public, None), Ok(()));
        assert_eq!(
            verify("site-a", &a[..1], &public, Some(&heads[2]))
                .unwrap_err()
                .index,
            0
        );
        // Autre clé.
        let other = SigningKey::from_bytes(&[4; 32]).verifying_key();
        assert_eq!(verify("site-a", &a, &other, None).unwrap_err().index, 1);
        // Entrée d'un autre site glissée dans l'export.
        assert!(verify("site-b", &a, &public, None).is_err());

        // La base refuse la réécriture.
        assert!(
            store
                .conn
                .execute("UPDATE command_audit SET entry = 'x'", [])
                .is_err()
        );
        assert!(store.conn.execute("DELETE FROM command_audit", []).is_err());
        assert_eq!(records(&store.conn, "site-a").unwrap(), a);
    }
}
