//! File des commandes, en base (`migrations/0008.sql`). Toute écriture se
//! fait en transaction IMMEDIATE et ajoute son entrée d'audit dans la même
//! transaction : un changement d'état n'existe jamais sans sa trace.

use ed25519_dalek::SigningKey;
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};

use super::audit::{self, Entry};
use super::{COMMAND_TTL, State};
use crate::capability::CommandKind;
use crate::config::Runtime;
use crate::store::Store;

/// Une commande en base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub id: String,
    pub site: String,
    pub seq: i64,
    pub kind: CommandKind,
    pub runtime: String,
    /// Paramètres validés, JSON.
    pub params: String,
    /// Empreinte de la typologie à la création.
    pub typology: String,
    pub state: State,
    pub created_at: i64,
    pub expires_at: i64,
    pub served_at: Option<i64>,
    pub closed_at: Option<i64>,
    /// Résultat déclaré par l'agent, JSON.
    pub result: Option<String>,
}

pub(crate) const COLUMNS: &str = "id, site, seq, name, runtime, params, typology, state, created_at, expires_at, served_at, closed_at, result";

pub(crate) fn from_row(row: &Row<'_>) -> rusqlite::Result<Command> {
    let name: String = row.get(3)?;
    let state: String = row.get(7)?;
    let invalid = |what: String| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(what)),
        )
    };
    Ok(Command {
        id: row.get(0)?,
        site: row.get(1)?,
        seq: row.get(2)?,
        kind: CommandKind::from_name(&name).ok_or_else(|| invalid(format!("commande {name}")))?,
        runtime: row.get(4)?,
        params: row.get(5)?,
        typology: row.get(6)?,
        state: State::parse(&state).ok_or_else(|| invalid(format!("état {state}")))?,
        created_at: row.get(8)?,
        expires_at: row.get(9)?,
        served_at: row.get(10)?,
        closed_at: row.get(11)?,
        result: row.get(12)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueError {
    /// Canal désactivé pour ce site (`site commands enable`).
    Disabled,
    /// Une commande est déjà en vol (`pending` ou `served`).
    InFlight { id: String },
    /// La précédente commande de ce type a une issue inconnue : `--force`.
    UnknownNeedsForce { id: String },
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str(
                "canal de commandes désactivé pour ce site : `vigie site commands enable <site>`",
            ),
            Self::InFlight { id } => write!(
                f,
                "commande {id} déjà en vol : attendre son issue ou l'annuler"
            ),
            Self::UnknownNeedsForce { id } => write!(
                f,
                "issue inconnue de la commande {id} (elle a pu s'exécuter) : --force pour en créer une autre"
            ),
        }
    }
}

/// Entrée d'audit d'un évènement de commande.
pub(crate) fn event(
    site: &str,
    at: i64,
    event: &str,
    command_id: Option<&str>,
    detail: impl Into<String>,
    typology: Option<&str>,
) -> Entry {
    Entry {
        site: site.to_owned(),
        at,
        event: event.to_owned(),
        command_id: command_id.map(str::to_owned),
        detail: detail.into(),
        typology: typology.map(str::to_owned),
    }
}

/// Passe une commande à `next`, si la transition est permise.
pub(crate) fn transition(
    tx: &Transaction<'_>,
    command: &Command,
    next: State,
    at: i64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        command.state.can_become(next),
        "transition interdite : {} → {}",
        command.state.as_str(),
        next.as_str()
    );
    let closes = !next.is_open() && next != State::Unknown;
    let changed = tx.execute(
        "UPDATE commands SET state = ?2,
             served_at = CASE WHEN ?2 = 'served' THEN ?3 ELSE served_at END,
             closed_at = CASE WHEN ?4 THEN ?3 ELSE closed_at END
         WHERE id = ?1 AND state = ?5",
        params![
            command.id,
            next.as_str(),
            at,
            closes,
            command.state.as_str()
        ],
    )?;
    anyhow::ensure!(changed == 1, "commande {} changée entre-temps", command.id);
    Ok(())
}

/// Annule les commandes non closes d'un site, avec leur audit.
fn cancel_open(
    tx: &Transaction<'_>,
    audit_key: &SigningKey,
    site: &str,
    now: i64,
    why: &str,
) -> anyhow::Result<Vec<String>> {
    let open = open_commands(tx, site)?;
    for command in &open {
        transition(tx, command, State::Cancelled, now)?;
        audit::append(
            tx,
            audit_key,
            &event(site, now, "cancelled", Some(&command.id), why, None),
        )?;
    }
    Ok(open.into_iter().map(|c| c.id).collect())
}

fn open_commands(conn: &rusqlite::Connection, site: &str) -> rusqlite::Result<Vec<Command>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM commands WHERE site = ?1 AND state IN ('pending', 'served') ORDER BY seq"
    ))?;
    stmt.query_map([site], from_row)?.collect()
}

impl Store {
    pub fn commands_enabled(&self, site: &str) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT enabled FROM command_sites WHERE site = ?1",
                [site],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// Kill-switch. Désactiver annule la commande en vol. Rend les commandes
    /// annulées.
    pub fn set_commands_enabled(
        &mut self,
        site: &str,
        enabled: bool,
        now: i64,
        audit_key: &SigningKey,
    ) -> anyhow::Result<Vec<String>> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO command_sites (site, enabled) VALUES (?1, ?2)
             ON CONFLICT (site) DO UPDATE SET enabled = excluded.enabled",
            params![site, enabled],
        )?;
        let cancelled = if enabled {
            Vec::new()
        } else {
            cancel_open(&tx, audit_key, site, now, "canal désactivé")?
        };
        audit::append(
            &tx,
            audit_key,
            &event(
                site,
                now,
                if enabled { "enabled" } else { "disabled" },
                None,
                if enabled {
                    "canal activé"
                } else {
                    "canal désactivé"
                },
                None,
            ),
        )?;
        tx.commit()?;
        Ok(cancelled)
    }

    /// Avant `site remove` ou `site rotate-key` (CLI) : canal désactivé et
    /// commande en vol annulée, pour qu'un site réinstallé n'hérite de rien.
    /// Sans clé d'audit, refusé seulement s'il y a quelque chose à annuler.
    pub fn reset_commands(
        &mut self,
        site: &str,
        now: i64,
        audit_key: Option<&SigningKey>,
        why: &str,
    ) -> anyhow::Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let enabled: bool = tx
            .query_row(
                "SELECT enabled FROM command_sites WHERE site = ?1",
                [site],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false);
        let open = open_commands(&tx, site)?;
        if !enabled && open.is_empty() {
            return Ok(());
        }
        let Some(audit_key) = audit_key else {
            anyhow::bail!(
                "{site} a le canal de commandes actif ou une commande en vol : [commands] et sa clé d'audit sont nécessaires pour les arrêter"
            );
        };
        tx.execute(
            "UPDATE command_sites SET enabled = 0 WHERE site = ?1",
            [site],
        )?;
        cancel_open(&tx, audit_key, site, now, why)?;
        audit::append(
            &tx,
            audit_key,
            &event(site, now, "disabled", None, why, None),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Crée une commande. `permit` a été vérifié par l'appelant contre la
    /// configuration du moment ; `typology` en est l'empreinte.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_command(
        &mut self,
        site: &str,
        kind: CommandKind,
        runtime: Runtime,
        params_json: &str,
        typology: &str,
        id: &str,
        now: i64,
        force: bool,
        audit_key: &SigningKey,
    ) -> anyhow::Result<Result<Command, EnqueueError>> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(bool, i64)> = tx
            .query_row(
                "SELECT enabled, last_command_seq FROM command_sites WHERE site = ?1",
                [site],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((true, last_seq)) = row else {
            return Ok(Err(EnqueueError::Disabled));
        };
        if let Some(open) = open_commands(&tx, site)?.into_iter().next() {
            return Ok(Err(EnqueueError::InFlight { id: open.id }));
        }
        if kind.non_idempotent() && !force {
            let unknown: Option<String> = tx
                .query_row(
                    "SELECT id FROM commands WHERE site = ?1 AND name = ?2 ORDER BY seq DESC LIMIT 1",
                    params![site, kind.name()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(previous) = unknown {
                let state: String = tx.query_row(
                    "SELECT state FROM commands WHERE id = ?1",
                    [&previous],
                    |row| row.get(0),
                )?;
                if state == State::Unknown.as_str() {
                    return Ok(Err(EnqueueError::UnknownNeedsForce { id: previous }));
                }
            }
        }
        let seq = last_seq + 1;
        tx.execute(
            "INSERT INTO commands (id, site, seq, name, runtime, params, typology, state, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)",
            params![
                id,
                site,
                seq,
                kind.name(),
                runtime.as_str(),
                params_json,
                typology,
                now,
                now + COMMAND_TTL
            ],
        )?;
        tx.execute(
            "UPDATE command_sites SET last_command_seq = ?2 WHERE site = ?1",
            params![site, seq],
        )?;
        audit::append(
            &tx,
            audit_key,
            &event(
                site,
                now,
                "created",
                Some(id),
                format!(
                    "{} (seq {seq}){}",
                    kind.name(),
                    if force { ", --force" } else { "" }
                ),
                Some(typology),
            ),
        )?;
        let command = tx.query_row(
            &format!("SELECT {COLUMNS} FROM commands WHERE id = ?1"),
            [id],
            from_row,
        )?;
        tx.commit()?;
        Ok(Ok(command))
    }

    /// Annule la commande en vol d'un site (`site command-cancel`).
    pub fn cancel_command(
        &mut self,
        site: &str,
        now: i64,
        audit_key: &SigningKey,
    ) -> anyhow::Result<Vec<String>> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cancelled = cancel_open(&tx, audit_key, site, now, "annulée par l'exploitant")?;
        tx.commit()?;
        Ok(cancelled)
    }

    pub fn command(&self, id: &str) -> anyhow::Result<Option<Command>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM commands WHERE id = ?1"),
                [id],
                from_row,
            )
            .optional()?)
    }

    pub fn commands(&self, site: &str) -> anyhow::Result<Vec<Command>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM commands WHERE site = ?1 ORDER BY seq"
        ))?;
        Ok(stmt
            .query_map([site], from_row)?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// `tick` : une commande `pending` de 24 h passe `expired`, une commande
    /// `served` sans résultat à 24 h passe `unknown` (elle a pu s'exécuter).
    /// Rend les sites dont la chaîne d'audit a bougé.
    pub fn expire_commands(&mut self, now: i64, audit_key: &SigningKey) -> anyhow::Result<usize> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stmt = tx.prepare(&format!(
            "SELECT {COLUMNS} FROM commands WHERE state IN ('pending', 'served') AND expires_at <= ?1"
        ))?;
        let due: Vec<Command> = stmt
            .query_map([now], from_row)?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        for command in &due {
            let (next, label) = if command.state == State::Pending {
                (State::Expired, "expired")
            } else {
                (State::Unknown, "unknown")
            };
            transition(&tx, command, next, now)?;
            audit::append(
                &tx,
                audit_key,
                &event(
                    &command.site,
                    now,
                    label,
                    Some(&command.id),
                    format!(
                        "{} sans {}",
                        command.kind.name(),
                        if next == State::Expired {
                            "retrait en 24 h"
                        } else {
                            "résultat en 24 h"
                        }
                    ),
                    None,
                ),
            )?;
        }
        tx.commit()?;
        Ok(due.len())
    }

    pub fn audit_records(&self, site: &str) -> anyhow::Result<Vec<audit::Record>> {
        Ok(audit::records(&self.conn, site)?)
    }

    pub fn audit_head(&self, site: &str) -> anyhow::Result<String> {
        Ok(audit::head(&self.conn, site)?)
    }

    /// Sites dont la tête d'audit n'a pas encore été envoyée par e-mail.
    pub fn audit_heads_to_notify(&self) -> anyhow::Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.site, a.hash FROM command_audit a
             WHERE a.id = (SELECT MAX(id) FROM command_audit WHERE site = a.site)
               AND a.hash IS NOT (SELECT last_hash FROM audit_notified WHERE site = a.site)
             ORDER BY a.site",
        )?;
        Ok(stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    pub fn mark_audit_notified(&mut self, site: &str, hash: &str, now: i64) -> anyhow::Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO audit_notified (site, last_hash, notified_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (site) DO UPDATE SET last_hash = excluded.last_hash, notified_at = excluded.notified_at",
            params![site, hash, now],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn enqueue(
        store: &mut Store,
        kind: CommandKind,
        id: &str,
        now: i64,
        force: bool,
    ) -> Result<Command, EnqueueError> {
        store
            .enqueue_command(
                "site-a",
                kind,
                Runtime::Php,
                "{}",
                "typo",
                id,
                now,
                force,
                &audit_key(),
            )
            .expect("base")
    }

    fn uuid(n: u8) -> String {
        format!("0192f5a8-7c3e-7d41-9b2a-5c1e8f0a4b{n:02x}")
    }

    #[test]
    fn one_command_in_flight_per_enabled_site() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
        assert_eq!(
            enqueue(&mut store, CommandKind::Ping, &uuid(1), 100, false),
            Err(EnqueueError::Disabled)
        );
        store
            .set_commands_enabled("site-a", true, 100, &audit_key())
            .unwrap();
        let first = enqueue(&mut store, CommandKind::Ping, &uuid(1), 100, false).unwrap();
        assert_eq!((first.seq, first.state), (1, State::Pending));
        assert_eq!(
            enqueue(&mut store, CommandKind::Ping, &uuid(2), 101, false),
            Err(EnqueueError::InFlight { id: uuid(1) })
        );
        // Même hors de la transaction applicative, l'index unique partiel tient.
        let raw = store.conn.execute(
            "INSERT INTO commands (id, site, seq, name, runtime, params, typology, state, created_at, expires_at)
             VALUES ('x', 'site-a', 9, 'ping', 'php', '{}', 't', 'pending', 0, 1)",
            [],
        );
        assert!(raw.is_err());
        // Désactiver annule la commande en vol.
        assert_eq!(
            store
                .set_commands_enabled("site-a", false, 102, &audit_key())
                .unwrap(),
            [uuid(1)]
        );
        assert_eq!(
            store.command(&uuid(1)).unwrap().unwrap().state,
            State::Cancelled
        );
        let records = store.audit_records("site-a").unwrap();
        let events: Vec<String> = records
            .iter()
            .map(|r| serde_json::from_str::<Entry>(&r.entry).unwrap().event)
            .collect();
        assert_eq!(events, ["enabled", "created", "cancelled", "disabled"]);
        audit::verify("site-a", &records, &audit_key().verifying_key(), None).unwrap();
    }

    #[test]
    fn stale_commands_expire_or_become_unknown_and_unknown_needs_force() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
        store
            .set_commands_enabled("site-a", true, 0, &audit_key())
            .unwrap();
        enqueue(&mut store, CommandKind::RotateKey, &uuid(1), 0, false).unwrap();
        assert_eq!(
            store
                .expire_commands(COMMAND_TTL - 1, &audit_key())
                .unwrap(),
            0
        );
        assert_eq!(store.expire_commands(COMMAND_TTL, &audit_key()).unwrap(), 1);
        assert_eq!(
            store.command(&uuid(1)).unwrap().unwrap().state,
            State::Expired
        );

        let second = enqueue(&mut store, CommandKind::RotateKey, &uuid(2), 10, false).unwrap();
        assert_eq!(second.seq, 2);
        // Servie puis jamais acquittée.
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transition(&tx, &second, State::Served, 20).unwrap();
        tx.commit().unwrap();
        store
            .expire_commands(10 + COMMAND_TTL, &audit_key())
            .unwrap();
        assert_eq!(
            store.command(&uuid(2)).unwrap().unwrap().state,
            State::Unknown
        );
        assert_eq!(
            enqueue(
                &mut store,
                CommandKind::RotateKey,
                &uuid(3),
                30 + COMMAND_TTL,
                false
            ),
            Err(EnqueueError::UnknownNeedsForce { id: uuid(2) })
        );
        // ping est idempotent : pas besoin de --force.
        assert!(
            enqueue(
                &mut store,
                CommandKind::Ping,
                &uuid(4),
                30 + COMMAND_TTL,
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn reset_before_remove_needs_the_audit_key_only_when_something_runs() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("vigie.db")).unwrap();
        store
            .reset_commands("site-a", 0, None, "site remove")
            .unwrap();
        store
            .set_commands_enabled("site-a", true, 0, &audit_key())
            .unwrap();
        enqueue(&mut store, CommandKind::Ping, &uuid(1), 0, false).unwrap();
        assert!(
            store
                .reset_commands("site-a", 1, None, "site remove")
                .is_err()
        );
        store
            .reset_commands("site-a", 1, Some(&audit_key()), "site remove")
            .unwrap();
        assert!(!store.commands_enabled("site-a").unwrap());
        assert_eq!(
            store.command(&uuid(1)).unwrap().unwrap().state,
            State::Cancelled
        );
    }
}
