//! Partage entre sites : seulement des signatures d'UA de robots, jamais
//! d'IP (`decisions.md`, issue #8).
//!
//! Une signature est un UA normalisé (minuscules, numéros de version
//! retirés, blancs réduits) de classe `Seo`, `AiTraining`, ou `Unknown` avec
//! un jeton de robot (`bot`, `crawler`, `spider`, `scraper`). Un UA d'outil
//! générique (`curl`, `python-requests`, `wget`…) ne l'est jamais : il ne
//! désigne pas un robot mais n'importe qui. Un UA où il reste une adresse IP
//! après normalisation n'est pas partagé non plus.
//!
//! Un site note une signature quand le score **propre** d'une IP qui la
//! porte atteint le niveau élevé ; une signature notée par un autre site
//! ajoute [`SHARED_SIGNATURE_POINTS`](super::score::SHARED_SIGNATURE_POINTS)
//! points hors du score propre ([`super::score::Verdict::with_shared_signature`]) :
//! un bonus seul ne peut pas noter, rien ne s'entretient. 100 signatures au
//! plus par site ; chacune expire 30 jours après sa dernière note.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use rusqlite::{TransactionBehavior, params};

use super::catalog::{BotClass, classify, has_bot_token, is_generic_tool};
use crate::store::Store;

/// Signatures gardées au plus par site.
pub const MAX_PER_SITE: usize = 100;
/// Durée de vie d'une signature après sa dernière note, en secondes.
pub const TTL_SECS: i64 = 30 * 86_400;
/// Longueur maximale d'une signature, en caractères.
pub const MAX_SIGNATURE: usize = 256;

/// Signature partageable d'un UA, ou `None` s'il ne doit pas sortir du
/// site.
pub fn signature(user_agent: &str) -> Option<String> {
    let ua = user_agent.trim();
    if is_generic_tool(ua) {
        return None;
    }
    let lower = ua.to_lowercase();
    let shareable = match classify(ua).class {
        BotClass::Seo | BotClass::AiTraining => true,
        BotClass::Unknown => has_bot_token(&lower),
        _ => false,
    };
    if !shareable {
        return None;
    }
    let stripped = strip_versions(&lower);
    let normalized: String = stripped
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_SIGNATURE)
        .collect();
    (!normalized.is_empty() && !contains_ip(&normalized)).then_some(normalized)
}

/// Retire les numéros de version : une suite de chiffres, points et
/// soulignés qui commence par un chiffre, ni collée à une lettre qui la
/// précède (`x86_64`) ni à une lettre qui la suit (`360spider`).
fn strip_versions(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if !c.is_ascii_digit() {
            out.push(c);
            i += 1;
            continue;
        }
        let mut end = i;
        while end < chars.len() && (chars[end].is_ascii_digit() || matches!(chars[end], '.' | '_'))
        {
            end += 1;
        }
        let after_letter = i > 0 && chars[i - 1].is_alphabetic();
        let before_letter = chars.get(end).is_some_and(|n| n.is_alphabetic());
        if after_letter || before_letter {
            out.extend(&chars[i..end]);
        }
        i = end;
    }
    out
}

/// Il reste dans `text` un fragment qui se lit comme une adresse IP.
pub fn contains_ip(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .flat_map(|token| {
            [
                token,
                token.trim_matches(|c| c == '.' || c == ':'),
                token.trim_end_matches('.'),
            ]
        })
        .any(|token| token.len() >= 2 && token.parse::<IpAddr>().is_ok())
}

/// Note les signatures d'un site (UA normalisé, score propre), puis ne
/// garde que ses 100 plus récentes.
pub fn note(store: &mut Store, site: &str, signatures: &[(String, u8)], now: i64) -> Result<()> {
    if signatures.is_empty() {
        return Ok(());
    }
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (ua, score) in signatures {
        tx.prepare_cached(
            "INSERT INTO log_signatures (ua, site, score, seen_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (ua, site) DO UPDATE SET score = excluded.score,
               seen_at = excluded.seen_at, expires_at = excluded.expires_at",
        )?
        .execute(params![ua, site, score, now, now.saturating_add(TTL_SECS)])?;
    }
    tx.execute(
        "DELETE FROM log_signatures WHERE site = ?1 AND ua NOT IN (
           SELECT ua FROM log_signatures WHERE site = ?1
           ORDER BY seen_at DESC, score DESC, ua LIMIT ?2)",
        params![site, MAX_PER_SITE as i64],
    )?;
    tx.commit()?;
    Ok(())
}

/// Signatures notées par d'autres sites que `site`, non expirées.
pub fn elsewhere(store: &Store, site: &str, now: i64) -> Result<HashSet<String>> {
    let mut stmt = store
        .conn
        .prepare("SELECT DISTINCT ua FROM log_signatures WHERE site <> ?1 AND expires_at > ?2")?;
    let rows = stmt.query_map(params![site, now], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Signatures notées par `site`, de la plus récente à la plus ancienne.
pub fn noted(store: &Store, site: &str) -> Result<Vec<(String, u8)>> {
    let mut stmt = store.conn.prepare(
        "SELECT ua, score FROM log_signatures WHERE site = ?1 ORDER BY seen_at DESC, ua",
    )?;
    let rows = stmt.query_map([site], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Retire les signatures expirées ; rend leur nombre.
pub fn purge(store: &mut Store, now: i64) -> Result<usize> {
    Ok(store
        .conn
        .execute("DELETE FROM log_signatures WHERE expires_at <= ?1", [now])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_robot_uas_are_shared_lowercased_without_versions() {
        let cases = [
            (
                "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
                Some("mozilla/ (compatible; ahrefsbot/; +http://ahrefs.com/robot/)"),
            ),
            (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
                Some(
                    "mozilla/ applewebkit/ (khtml, like gecko; compatible; gptbot/; +https://openai.com/gptbot)",
                ),
            ),
            (
                "ExampleCrawler/2.4.1  (+https://crawler.example.org/)",
                Some("examplecrawler/ (+https://crawler.example.org/)"),
            ),
            // Outils génériques, navigateurs, moteurs, aperçus : jamais.
            ("curl/8.4.0", None),
            ("python-requests/2.31.0", None),
            ("Wget/1.21.4", None),
            ("", None),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
                None,
            ),
            (
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                None,
            ),
            ("facebookexternalhit/1.1", None),
            ("Mozilla/5.0 (Linux; Android 13; CUBOT X19) Mobile", None),
        ];
        for (ua, expected) in cases {
            assert_eq!(signature(ua).as_deref(), expected, "{ua}");
        }
        // Les versions changent, la signature reste.
        assert_eq!(
            signature("ExampleCrawler/2.4.1 (+https://crawler.example.org/)"),
            signature("ExampleCrawler/3.0 (+https://crawler.example.org/)")
        );
        // Un nom qui commence par des chiffres garde ses chiffres.
        assert_eq!(
            signature("Mozilla/5.0 (compatible; 360Spider)").as_deref(),
            None,
            "360Spider est un moteur protégé"
        );
        assert_eq!(
            signature("4seasonsbot/1.0").as_deref(),
            Some("4seasonsbot/")
        );
    }

    #[test]
    fn a_signature_never_carries_an_ip() {
        for ua in [
            "ExampleBot/1.0 (+http://192.0.2.7/bot)",
            "ExampleBot/1.0 from 198.51.100.23",
            "ExampleBot (ip203.0.113.9)",
            "ExampleBot/1.0 (2001:db8::1)",
            "ExampleBot/1.0 [2001:db8:0:0:0:0:0:7]",
        ] {
            if let Some(sig) = signature(ua) {
                assert!(!contains_ip(&sig), "{ua} → {sig}");
            }
        }
        assert_eq!(signature("ExampleBot (ip203.0.113.9)"), None);
        assert!(contains_ip("bot 192.0.2.1"));
        assert!(contains_ip("bot [2001:db8::1]"));
        assert!(!contains_ip("examplebot/ (+https://bot.example.org/)"));
    }
}
