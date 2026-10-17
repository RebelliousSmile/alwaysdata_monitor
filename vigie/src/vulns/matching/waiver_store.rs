//! Dérogations auditées (#21) : la seule écriture de F7 hors de `tick`,
//! par `vigie site vulns-ack`, aperçu puis `--apply`.
//!
//! Une dérogation par source d'inventaire : elle vaut pour la version que
//! **cette** source voit. Chaque ligne de `vuln_waivers` et son entrée dans
//! la chaîne d'audit signée du site (`vuln-waived`, `vuln-waiver-revoked`)
//! sont écrites dans la même transaction IMMEDIATE. L'entrée ne porte que
//! l'**empreinte SHA-256 du motif** (`reason_sha256`), avec le purl indexé,
//! l'identifiant de faille, l'échéance et l'opérateur : le texte du motif ne
//! vit que dans `vuln_waivers`, purgée par `site remove`.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::command::audit::{self, Entry};
use crate::inventory::Source;
use crate::store::Store;
use crate::vulns::UsageError;
use crate::vulns::exploit::{Cve, Exploitation};

use super::assess::GroupResult;
use super::finding::day;
use super::store::{run_results, site_states};
use super::waiver::{self, validate_against};
use super::{Component, key};

/// Évènement d'audit d'une dérogation saisie.
pub const EVENT_WAIVED: &str = "vuln-waived";
/// Évènement d'audit d'une dérogation retirée.
pub const EVENT_REVOKED: &str = "vuln-waiver-revoked";

/// Ce que l'entrée d'audit raconte : jamais le texte du motif.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDetail {
    /// purl sans version, tel qu'indexé.
    pub purl: String,
    /// Identifiant de faille saisi, normalisé.
    pub advisory: String,
    /// Échéance, `AAAA-MM-JJ`.
    pub until: String,
    pub operator: String,
    /// SHA-256 du motif (saisie) ou du motif de retrait, en hexadécimal.
    pub reason_sha256: String,
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Motif gardé : sans espace autour, assaini (500 caractères au plus).
fn clean_reason(reason: &str) -> String {
    crate::api::log_text::LogText::new(reason.trim(), waiver::MAX_REASON_CHARS).into()
}

/// Dérogation demandée, déjà validée (échéance, motif) avant toute lecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub site: String,
    pub sources: Vec<Source>,
    /// Clé du constat : purl sans version canonique.
    pub base: String,
    /// Identifiant ou alias saisi, normalisé.
    pub advisory: String,
    pub reason: String,
    pub until: i64,
}

/// Une dérogation à écrire, telle que l'aperçu la montre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub source: Source,
    /// Run actif lu : revérifié à l'écriture.
    pub run: i64,
    pub version: String,
    pub group: GroupResult,
}

/// Composant vu par une source, et ses groupes.
type Seen = (Component, Vec<GroupResult>);

/// Composants d'un purl sans version dans le run actif d'une source, et
/// ce run.
fn seen_by(
    store: &Store,
    site: &str,
    source: Source,
    base: &str,
) -> anyhow::Result<Option<(i64, Vec<Seen>)>> {
    let Some(run) = site_states(&store.conn, site)?
        .into_iter()
        .find(|s| s.source == Some(source))
        .and_then(|s| s.active_run)
    else {
        return Ok(None);
    };
    let found = run_results(&store.conn, site, source, run)?
        .into_iter()
        .filter(|r| key(&r.component.base) == base)
        .map(|r| (r.component, r.groups))
        .collect();
    Ok(Some((run, found)))
}

/// Aperçu : une dérogation par source citée, ou le refus (code 2) :
/// composant absent du dernier inventaire de la source, version inconnue,
/// faille qui ne touche pas le composant, faille exploitée (KEV).
pub fn preview(
    store: &Store,
    tables: &impl Exploitation,
    request: &Request,
) -> anyhow::Result<Vec<Preview>> {
    let mut out = Vec::new();
    for &source in &request.sources {
        let Some((run, found)) = seen_by(store, &request.site, source, &request.base)? else {
            return Err(UsageError(format!(
                "source {} jamais rapprochée pour {} : attendre le prochain tick",
                source.as_str(),
                request.site
            ))
            .into());
        };
        if found.is_empty() {
            return Err(UsageError(format!(
                "{} absent du dernier inventaire de la source {}",
                request.base,
                source.as_str()
            ))
            .into());
        }
        let versions: BTreeSet<Option<String>> =
            found.iter().map(|(c, _)| c.version.clone()).collect();
        let version = match versions.into_iter().collect::<Vec<_>>().as_slice() {
            [Some(v)] => v.clone(),
            [None] => {
                return Err(UsageError(
                    "version inconnue : une dérogation exige une version ; acquitter l'incident avec `vigie ack <incident>`".into(),
                )
                .into());
            }
            _ => {
                return Err(UsageError(format!(
                    "{} vu à plusieurs versions par la source {} : une dérogation vaut pour une version",
                    request.base,
                    source.as_str()
                ))
                .into());
            }
        };
        let Some(group) = found
            .iter()
            .flat_map(|(_, groups)| groups)
            .find(|g| g.ids.contains(&request.advisory))
            .cloned()
        else {
            return Err(UsageError(format!(
                "la faille {} ne touche pas {} vu par la source {}",
                request.advisory,
                request.base,
                source.as_str()
            ))
            .into());
        };
        validate_against(&group, Some(&version))?;
        // KEV relu à la saisie : une faille entrée depuis le dernier passage.
        let in_kev = group
            .members
            .iter()
            .flat_map(|m| &m.cves)
            .filter_map(|c| Cve::parse(c))
            .any(|c| tables.kev(&c).is_some());
        if in_kev {
            return Err(UsageError("faille exploitée (KEV) : dérogation interdite".into()).into());
        }
        out.push(Preview {
            source,
            run,
            version,
            group,
        });
    }
    Ok(out)
}

/// Écrit les dérogations de l'aperçu, toutes ou aucune, chacune avec son
/// entrée d'audit dans la même transaction. Rend leurs `id`.
pub fn add(
    store: &mut Store,
    signer: &SigningKey,
    request: &Request,
    previews: &[Preview],
    operator: &str,
    now: i64,
) -> anyhow::Result<Vec<i64>> {
    waiver::validate(request.until, &request.reason, now)?;
    let reason = clean_reason(&request.reason);
    let reason = reason.as_str();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut ids = Vec::new();
    for p in previews {
        let active: Option<i64> = tx
            .query_row(
                "SELECT active_run FROM vuln_match_state WHERE site = ?1 AND source = ?2",
                params![request.site, p.source.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if active != Some(p.run) {
            return Err(UsageError(
                "rapprochement changé depuis l'aperçu : relancer la commande".into(),
            )
            .into());
        }
        let detail = AuditDetail {
            purl: request.base.clone(),
            advisory: request.advisory.clone(),
            until: day(request.until),
            operator: operator.to_owned(),
            reason_sha256: sha256_hex(reason),
        };
        let hash = audit::append(
            &tx,
            signer,
            &Entry {
                site: request.site.clone(),
                at: now,
                event: EVENT_WAIVED.into(),
                command_id: None,
                detail: serde_json::to_string(&detail)?,
                typology: None,
            },
        )?;
        tx.execute(
            "INSERT INTO vuln_waivers (site, source, base, advisory_ref, version, covered_ids,
                 reason, until, operator, created_at, audit_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                request.site,
                p.source.as_str(),
                request.base,
                request.advisory,
                p.version,
                serde_json::to_string(&p.group.ids)?,
                reason,
                request.until,
                operator,
                now,
                hash
            ],
        )?;
        ids.push(tx.last_insert_rowid());
    }
    tx.commit()?;
    Ok(ids)
}

/// Dérogation relue, motifs compris (affichés par la CLI seulement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: i64,
    pub source: Source,
    pub base: String,
    pub advisory_ref: String,
    pub version: String,
    pub covered_ids: BTreeSet<String>,
    pub reason: String,
    pub until: i64,
    pub operator: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
    pub audit_hash: String,
}

const ROW_COLUMNS: &str = "id, source, base, advisory_ref, version, covered_ids, reason, until,
    operator, created_at, revoked_at, revoke_reason, audit_hash";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let source: String = r.get(1)?;
    let covered: String = r.get(5)?;
    Ok(Row {
        id: r.get(0)?,
        // La contrainte CHECK de la colonne garantit `agent` ou `ci`.
        source: Source::from_name(&source).unwrap_or(Source::Agent),
        base: r.get(2)?,
        advisory_ref: r.get(3)?,
        version: r.get(4)?,
        covered_ids: serde_json::from_str(&covered).unwrap_or_default(),
        reason: r.get(6)?,
        until: r.get(7)?,
        operator: r.get(8)?,
        created_at: r.get(9)?,
        revoked_at: r.get(10)?,
        revoke_reason: r.get(11)?,
        audit_hash: r.get(12)?,
    })
}

/// Toutes les dérogations d'un site, retirées comprises, par id.
pub fn rows(store: &Store, site: &str) -> anyhow::Result<Vec<Row>> {
    let mut stmt = store.conn.prepare(&format!(
        "SELECT {ROW_COLUMNS} FROM vuln_waivers WHERE site = ?1 ORDER BY id"
    ))?;
    let rows = stmt.query_map([site], row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Retire une dérogation du site, motivée, avec son entrée d'audit.
pub fn revoke(
    store: &mut Store,
    signer: &SigningKey,
    site: &str,
    id: i64,
    reason: &str,
    operator: &str,
    now: i64,
) -> anyhow::Result<Row> {
    let n = reason.trim().chars().count();
    if n == 0 || n > waiver::MAX_REASON_CHARS {
        return Err(UsageError(format!(
            "motif obligatoire, {} caractères au plus (reçu : {n})",
            waiver::MAX_REASON_CHARS
        ))
        .into());
    }
    let reason = clean_reason(reason);
    let reason = reason.as_str();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = tx
        .query_row(
            &format!("SELECT {ROW_COLUMNS} FROM vuln_waivers WHERE site = ?1 AND id = ?2"),
            params![site, id],
            row,
        )
        .optional()?;
    let Some(current) = current else {
        return Err(UsageError(format!("aucune dérogation {id} pour {site}")).into());
    };
    if current.revoked_at.is_some() {
        return Err(UsageError(format!("dérogation {id} déjà retirée")).into());
    }
    let detail = AuditDetail {
        purl: current.base.clone(),
        advisory: current.advisory_ref.clone(),
        until: day(current.until),
        operator: operator.to_owned(),
        reason_sha256: sha256_hex(reason),
    };
    audit::append(
        &tx,
        signer,
        &Entry {
            site: site.to_owned(),
            at: now,
            event: EVENT_REVOKED.into(),
            command_id: None,
            detail: serde_json::to_string(&detail)?,
            typology: None,
        },
    )?;
    tx.execute(
        "UPDATE vuln_waivers SET revoked_at = ?3, revoke_reason = ?4 WHERE site = ?1 AND id = ?2",
        params![site, id, now, reason],
    )?;
    tx.commit()?;
    Ok(Row {
        revoked_at: Some(now),
        revoke_reason: Some(reason.to_owned()),
        ..current
    })
}
