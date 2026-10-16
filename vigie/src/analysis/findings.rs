//! Des agrégats aux constats : [`Analysis`] structurée, instantanés en base
//! et constats agrégés et bornés sous le contrôle [`CHECK`].
//!
//! `tick` calcule une `Analysis` par site qui a une source, à chaque passage.
//! Quand le passage a replié des entrées, les verdicts d'IP sont recalculés
//! sur les profils ([`analyse`]) et l'analyse est écrite en instantané
//! ([`persist`]) ; sinon les verdicts sont repris du dernier instantané
//! ([`refresh`]) : les profils n'ont pas bougé, la référence non plus.
//!
//! Instantanés : le dernier d'un site est toujours gardé ; les précédents
//! partent dès qu'ils ont plus de 15 minutes de moins que lui. Le résumé
//! (`log_analysis` : robots, règles, charge) ne contient aucune IP et vit
//! 30 jours ; les verdicts (`log_verdicts`, niveaux moyen et élevé seulement)
//! partent 48 heures après leur calcul, le dernier compris ([`purge`]).
//!
//! Constats : un par règle dépassée, un seul `suspicious-ips`,
//! `bots-ai-training` en information, `load`. La clé est l'identifiant de
//! la règle ou du constat, jamais une valeur lue dans un log ; tout le
//! détail est assaini à l'écriture ([`sanitize`]) et ne cite que
//! [`DETAIL_ITEMS`] IP ou chemins au plus. Un constat de fenêtre se résout
//! quand `now − référence` dépasse la fenêtre plus `agent_silence` : plus de
//! données, plus de pic.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::catalog::BotClass;
use super::load::{DEFAULT_THRESHOLD_US, HourLoad};
use super::profile::{HOUR_MS, hour_of};
use super::rules::{RuleSet, Scope};
use super::score::{Level, Reason};
use super::{shared, store as agg};
use crate::finding::{Finding, Severity};
use crate::store::Store;

/// Contrôle des constats de l'analyse de logs.
pub const CHECK: &str = "logs";
/// IP ou chemins cités au plus dans un détail.
pub const DETAIL_ITEMS: usize = 5;
/// Un chemin cité dans un détail est tronqué à ce nombre de caractères.
pub const DETAIL_PATH: usize = 100;
/// Un instantané part dès qu'il a plus de 15 minutes de moins que le
/// dernier.
pub const SNAPSHOT_OVERLAP_SECS: i64 = 15 * 60;
/// Verdicts d'IP gardés 48 heures (minimisation).
pub const VERDICT_RETENTION_SECS: i64 = 48 * 3600;
/// Résumés gardés, et détails des incidents `logs` clos masqués, après
/// 30 jours.
pub const SUMMARY_RETENTION_SECS: i64 = 30 * 86_400;
/// Fenêtre du constat `load` : l'heure qui finit à la référence.
pub const LOAD_WINDOW_SECS: u32 = 3600;
/// Fenêtre des profils et des robots : 24 heures.
pub const PROFILE_WINDOW_SECS: u32 = 24 * 3600;
/// Détail d'un incident `logs` clos depuis plus de 30 jours.
pub const MASKED: &str = "détail masqué après 30 jours";

/// Clés des constats qui ne viennent pas d'une règle.
pub const SUSPICIOUS_IPS: &str = "suspicious-ips";
pub const BOTS_AI_TRAINING: &str = "bots-ai-training";
pub const LOAD: &str = "load";

/// Robot du catalogue vu sur 24 h, avec ses métadonnées (#13 choisit entre
/// robots.txt, UA et IP sur elles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotSeen {
    pub name: String,
    pub publisher: String,
    pub purpose: String,
    pub robots_only: bool,
    pub honours_robots: bool,
    pub class: BotClass,
    /// Protégé des actions robots.txt et UA de #13.
    pub protected: bool,
    pub requests: u64,
}

/// Verdict d'une IP sur 24 h : niveaux moyen et élevé seulement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpVerdict {
    pub ip: IpAddr,
    /// Score, signature partagée comprise.
    pub score: u8,
    /// Score propre au site.
    pub own_score: u8,
    pub level: Level,
    /// Classe du premier robot vu, `Browser` sans robot.
    pub class: BotClass,
    pub bot: Option<String>,
    /// Requêtes observées.
    pub requests: u64,
    /// Un de ses UA porte une signature notée sur un autre site.
    pub shared: bool,
    pub reasons: Vec<Reason>,
}

/// Une règle sur sa fenêtre, finie à la référence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOutcome {
    pub rule: String,
    pub scope: Scope,
    pub severity: Severity,
    pub window_secs: u32,
    pub min_count: u32,
    pub min_ips: u32,
    /// Portée `site` : requêtes de la fenêtre ; portée `ip` : celles de
    /// l'IP la plus active.
    pub count: u64,
    /// Portée `site` : IP distinctes (exactes jusqu'au plus grand
    /// `min_ips`).
    pub distinct_ips: usize,
    /// Portée `ip` : IP au-dessus du seuil.
    pub keys_over: usize,
    pub exceeded: bool,
    /// Portée `site` : les premières IP, pour le détail. Jamais écrites dans
    /// le résumé (minimisation).
    #[serde(skip)]
    pub ips: Vec<IpAddr>,
    /// Portée `ip` : les IP les plus actives et leur compte, pour le détail.
    /// Jamais écrites dans le résumé.
    #[serde(skip)]
    pub keys: Vec<(IpAddr, u64)>,
}

/// Sortie structurée de l'analyse d'un site, lue par #13 et la console
/// (#5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    pub site: String,
    /// Heure du veilleur, en secondes.
    pub generated_at: i64,
    /// Heure de référence des fenêtres, en ms.
    pub reference_ms: i64,
    /// Robots du catalogue vus sur 24 h, du plus actif au moins actif.
    pub bots: Vec<BotSeen>,
    /// Verdicts moyens et élevés, du plus haut score au plus bas (puis par
    /// IP). Écrits dans `log_verdicts`, pas dans le résumé.
    #[serde(skip)]
    pub verdicts: Vec<IpVerdict>,
    /// IP notées.
    pub scored: u64,
    /// IP sans score : erreur héritée au-delà du dixième de leurs requêtes,
    /// ce qui n'est pas un verdict de trafic sain.
    pub unscored: u64,
    pub rules: Vec<RuleOutcome>,
    /// Charge des 24 heures, dans l'ordre.
    pub load: Vec<HourLoad>,
    pub load_threshold_us: u64,
}

/// Remplace les caractères qui pourraient tromper un lecteur ou un
/// terminal : contrôles C0, DEL, C1, séparateurs U+2028 et U+2029, et
/// contrôles bidirectionnels, par U+FFFD.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || is_bidi(c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

fn is_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Chemin cité dans un détail : sans query string, assaini, tronqué à
/// [`DETAIL_PATH`] caractères.
pub fn detail_path(path: &str) -> String {
    let path = sanitize(path.split_once('?').map_or(path, |(p, _)| p));
    if path.chars().count() <= DETAIL_PATH {
        return path;
    }
    let mut cut: String = path.chars().take(DETAIL_PATH - 1).collect();
    cut.push('…');
    cut
}

/// Robots, règles et charge, sans verdicts.
fn base(
    store: &Store,
    site: &str,
    rules: &RuleSet,
    reference_ms: i64,
    generated_at: i64,
) -> Result<Analysis> {
    let bots = agg::bots(store, site, reference_ms)?
        .into_iter()
        .map(|v| BotSeen {
            name: v.bot.name.to_string(),
            publisher: v.bot.publisher.to_string(),
            purpose: v.bot.purpose.to_string(),
            robots_only: v.bot.robots_only,
            honours_robots: v.bot.honours_robots,
            class: v.bot.class,
            protected: v.bot.protected(),
            requests: v.requests,
        })
        .collect();
    let rules = agg::rule_windows(store, site, rules, reference_ms)?
        .into_iter()
        .map(|w| RuleOutcome {
            distinct_ips: w.ips.len(),
            keys_over: w.keys.len(),
            ips: w.ips.into_iter().take(DETAIL_ITEMS).collect(),
            keys: w.keys.into_iter().take(DETAIL_ITEMS).collect(),
            rule: w.rule,
            scope: w.scope,
            severity: w.severity,
            window_secs: w.window_secs,
            min_count: w.min_count,
            min_ips: w.min_ips,
            count: w.count,
            exceeded: w.exceeded,
        })
        .collect();
    Ok(Analysis {
        site: site.to_string(),
        generated_at,
        reference_ms,
        bots,
        verdicts: Vec::new(),
        scored: 0,
        unscored: 0,
        rules,
        load: agg::load(store, site, reference_ms)?,
        load_threshold_us: DEFAULT_THRESHOLD_US,
    })
}

fn by_score(verdicts: &mut [IpVerdict]) {
    verdicts.sort_by(|a, b| b.score.cmp(&a.score).then(a.ip.cmp(&b.ip)));
}

/// Analyse complète, verdicts recalculés sur les profils. `elsewhere` : les
/// signatures notées par d'autres sites ([`shared::elsewhere`]). Rend aussi
/// les signatures que ce site doit noter : UA de robot d'une IP dont le
/// score **propre** est élevé, avec le plus haut de ces scores.
pub fn analyse(
    store: &Store,
    site: &str,
    rules: &RuleSet,
    reference_ms: i64,
    generated_at: i64,
    elsewhere: &HashSet<String>,
) -> Result<(Analysis, Vec<(String, u8)>)> {
    let mut analysis = base(store, site, rules, reference_ms, generated_at)?;
    let mut to_note: Vec<(String, u8)> = Vec::new();
    for profile in agg::profiles(store, site, reference_ms)? {
        let Some(mut verdict) = profile.verdict() else {
            analysis.unscored += 1;
            continue;
        };
        analysis.scored += 1;
        let signatures: Vec<String> = profile
            .stats
            .uas
            .iter()
            .filter_map(|ua| shared::signature(ua))
            .collect();
        if verdict.own_score >= super::score::LEVEL_HIGH {
            for signature in &signatures {
                match to_note.iter_mut().find(|(ua, _)| ua == signature) {
                    Some((_, score)) => *score = (*score).max(verdict.own_score),
                    None => to_note.push((signature.clone(), verdict.own_score)),
                }
            }
        }
        let shared =
            verdict.level != Level::Engine && signatures.iter().any(|s| elsewhere.contains(s));
        if shared {
            verdict = verdict.with_shared_signature();
        }
        if verdict.level < Level::Medium {
            continue;
        }
        analysis.verdicts.push(IpVerdict {
            ip: profile.ip,
            score: verdict.score,
            own_score: verdict.own_score,
            level: verdict.level,
            class: profile.class,
            bot: profile.bot.map(|b| b.name.to_string()),
            requests: profile.stats.requests,
            shared,
            reasons: verdict.reasons,
        });
    }
    by_score(&mut analysis.verdicts);
    to_note.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    to_note.truncate(shared::MAX_PER_SITE);
    Ok((analysis, to_note))
}

/// Analyse sans relire les profils : règles, robots et charge recalculés,
/// verdicts repris du dernier instantané. Pour un passage qui n'a rien
/// replié.
pub fn refresh(
    store: &Store,
    site: &str,
    rules: &RuleSet,
    reference_ms: i64,
    generated_at: i64,
) -> Result<Analysis> {
    let mut analysis = base(store, site, rules, reference_ms, generated_at)?;
    if let Some(latest) = latest(store, site)? {
        analysis.verdicts = latest.verdicts;
        analysis.scored = latest.scored;
        analysis.unscored = latest.unscored;
    }
    Ok(analysis)
}

/// Écrit l'instantané, puis retire ceux du site qui ont plus de 15 minutes
/// de moins que lui.
pub fn persist(store: &mut Store, analysis: &Analysis) -> Result<()> {
    let site = analysis.site.as_str();
    let at = analysis.generated_at;
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT OR REPLACE INTO log_analysis (site, generated_at, reference_ms, summary)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            site,
            at,
            analysis.reference_ms,
            serde_json::to_string(analysis)?
        ],
    )?;
    tx.execute(
        "DELETE FROM log_verdicts WHERE site = ?1 AND generated_at = ?2",
        params![site, at],
    )?;
    for v in &analysis.verdicts {
        tx.prepare_cached(
            "INSERT INTO log_verdicts (site, generated_at, ip, score, own_score, level, class,
               bot, requests, shared, reasons)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?
        .execute(params![
            site,
            at,
            v.ip.to_string(),
            v.score,
            v.own_score,
            v.level.as_str(),
            v.class.as_str(),
            v.bot,
            i64::try_from(v.requests).unwrap_or(i64::MAX),
            v.shared,
            serde_json::to_string(&v.reasons)?
        ])?;
    }
    let older = at - SNAPSHOT_OVERLAP_SECS;
    tx.execute(
        "DELETE FROM log_analysis WHERE site = ?1 AND generated_at < ?2",
        params![site, older],
    )?;
    tx.execute(
        "DELETE FROM log_verdicts WHERE site = ?1 AND generated_at < ?2",
        params![site, older],
    )?;
    tx.commit()?;
    Ok(())
}

/// Dernier instantané d'un site, verdicts compris (vides après 48 h).
pub fn latest(store: &Store, site: &str) -> Result<Option<Analysis>> {
    let row: Option<(i64, String)> = store
        .conn
        .query_row(
            "SELECT generated_at, summary FROM log_analysis WHERE site = ?1
             ORDER BY generated_at DESC LIMIT 1",
            [site],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((at, summary)) = row else {
        return Ok(None);
    };
    let mut analysis: Analysis =
        serde_json::from_str(&summary).context("résumé d'analyse illisible")?;
    let mut stmt = store.conn.prepare(
        "SELECT ip, score, own_score, level, class, bot, requests, shared, reasons
         FROM log_verdicts WHERE site = ?1 AND generated_at = ?2
         ORDER BY score DESC, ip",
    )?;
    let rows = stmt.query_map(params![site, at], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u8>(1)?,
            row.get::<_, u8>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, bool>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;
    for row in rows {
        let (ip, score, own_score, level, class, bot, requests, shared, reasons) = row?;
        let (Ok(ip), Some(class)) = (ip.parse(), BotClass::parse(&class)) else {
            continue;
        };
        let level = match level.as_str() {
            "eleve" => Level::High,
            "moyen" => Level::Medium,
            _ => continue,
        };
        analysis.verdicts.push(IpVerdict {
            ip,
            score,
            own_score,
            level,
            class,
            bot,
            requests: u64::try_from(requests).unwrap_or(0),
            shared,
            reasons: serde_json::from_str(&reasons).unwrap_or_default(),
        });
    }
    by_score(&mut analysis.verdicts);
    Ok(Some(analysis))
}

/// Purges de `tick`, pour tous les sites, y compris ceux qui n'ont plus de
/// source : verdicts de plus de 48 h, résumés de plus de 30 jours, et
/// détails des incidents `logs` clos depuis plus de 30 jours masqués.
pub fn purge(store: &mut Store, now: i64) -> Result<()> {
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM log_verdicts WHERE generated_at < ?1",
        [now - VERDICT_RETENTION_SECS],
    )?;
    tx.execute(
        "DELETE FROM log_analysis WHERE generated_at < ?1",
        [now - SUMMARY_RETENTION_SECS],
    )?;
    tx.execute(
        "UPDATE incidents SET detail = ?1
         WHERE check_name = ?2 AND closed_at IS NOT NULL AND closed_at < ?3 AND detail <> ?1",
        params![MASKED, CHECK, now - SUMMARY_RETENTION_SECS],
    )?;
    tx.commit()?;
    Ok(())
}

/// Plus de données depuis la fenêtre plus `agent_silence` : le constat de
/// fenêtre se résout.
pub fn stale(reference_ms: i64, now_ms: i64, window_secs: u32, agent_silence_ms: i64) -> bool {
    now_ms.saturating_sub(reference_ms) > i64::from(window_secs) * 1000 + agent_silence_ms
}

fn ip_list(ips: &[IpAddr]) -> String {
    ips.iter()
        .take(DETAIL_ITEMS)
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn minutes(secs: u32) -> u32 {
    secs.div_ceil(60)
}

fn percent(share: Option<f64>) -> i64 {
    // Une part est dans [0, 1].
    share.map_or(0, |s| (s * 100.0).round() as i64)
}

/// Constats d'une analyse à l'heure du veilleur `now_ms`.
pub fn findings(analysis: &Analysis, now_ms: i64, agent_silence_ms: i64) -> Vec<Finding> {
    let site = analysis.site.as_str();
    let reference = analysis.reference_ms;
    let mut found = Vec::new();
    let mut push = |severity: Severity, key: &str, detail: String| {
        found.push(Finding::new(site, CHECK, severity, key, sanitize(&detail)));
    };

    for rule in &analysis.rules {
        if !rule.exceeded || stale(reference, now_ms, rule.window_secs, agent_silence_ms) {
            continue;
        }
        let window = minutes(rule.window_secs);
        let detail = match rule.scope {
            Scope::Site => {
                let more = if rule.distinct_ips > DETAIL_ITEMS {
                    format!(" (sur {} au moins)", rule.distinct_ips)
                } else {
                    String::new()
                };
                format!(
                    "{} requête(s) en {window} min (seuil {}), {} IP distincte(s) : {}{more}",
                    rule.count,
                    rule.min_count,
                    rule.distinct_ips,
                    ip_list(&rule.ips)
                )
            }
            Scope::Ip => {
                let top: Vec<String> = rule
                    .keys
                    .iter()
                    .take(DETAIL_ITEMS)
                    .map(|(ip, n)| format!("{ip} ({n})"))
                    .collect();
                format!(
                    "{} IP à {} requête(s) ou plus en {window} min ; les plus actives : {}",
                    rule.keys_over,
                    rule.min_count,
                    top.join(", ")
                )
            }
        };
        push(rule.severity, &rule.rule, detail);
    }

    let profiles_live = !stale(reference, now_ms, PROFILE_WINDOW_SECS, agent_silence_ms);
    let high: Vec<&IpVerdict> = analysis
        .verdicts
        .iter()
        .filter(|v| v.level == Level::High)
        .collect();
    if profiles_live && !high.is_empty() {
        let worst: Vec<String> = high
            .iter()
            .take(DETAIL_ITEMS)
            .map(|v| format!("{} (score {}, {})", v.ip, v.score, v.class.label()))
            .collect();
        push(
            Severity::Warning,
            SUSPICIOUS_IPS,
            format!(
                "{} IP au score élevé sur 24 h ({} notée(s)) ; les pires : {}",
                high.len(),
                analysis.scored,
                worst.join(", ")
            ),
        );
    }

    let training: Vec<&BotSeen> = analysis
        .bots
        .iter()
        .filter(|b| b.class == BotClass::AiTraining && b.requests > 0)
        .collect();
    if profiles_live && !training.is_empty() {
        let list: Vec<String> = training
            .iter()
            .take(DETAIL_ITEMS)
            .map(|b| format!("{} ({}) : {}", b.name, b.publisher, b.requests))
            .collect();
        push(
            Severity::Info,
            BOTS_AI_TRAINING,
            format!(
                "requêtes de robots d'entraînement IA sur 24 h : {}",
                list.join(", ")
            ),
        );
    }

    if !stale(reference, now_ms, LOAD_WINDOW_SECS, agent_silence_ms) {
        let first = hour_of(reference - HOUR_MS);
        let worst = analysis
            .load
            .iter()
            .filter(|h| h.hour >= first && h.exceeds(analysis.load_threshold_us))
            .max_by_key(|h| (h.service_us, h.hour));
        if let Some(hour) = worst {
            push(
                Severity::Warning,
                LOAD,
                format!(
                    "{} s de service dans l'heure de {} (seuil {} s) ; facettes {} %, robots {} %",
                    hour.service_us / 1_000_000,
                    crate::iso_utc(hour.hour * 3600),
                    analysis.load_threshold_us / 1_000_000,
                    percent(hour.facets_share()),
                    percent(hour.bots_share())
                ),
            );
        }
    }
    found
}
