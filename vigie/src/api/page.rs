//! Pagination par clé de `/api/v1` (`docs/api-console.md`) : `limit` de 1
//! à 100 (50 par défaut), `cursor` opaque en base64url, 256 caractères au
//! plus avant décodage. Toute valeur hors de ces règles est un 400
//! `bad_request` ; un curseur ne se décode que pour la liste qui l'a émis.
//!
//! Le curseur porte la clé du dernier élément servi, jamais un rang : une
//! page lue plus tard reprend juste après lui, sans doublon ni trou dû aux
//! éléments arrivés entre-temps. Il n'est ni signé ni chiffré : il ne porte
//! que des valeurs déjà servies à cet appareil, et un curseur forgé ne
//! donne accès à rien de plus que la liste elle-même.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use crate::error::ApiError;

/// Éléments par page sans `limit`.
pub const DEFAULT_LIMIT: usize = 50;
/// `limit` le plus grand accepté.
pub const MAX_LIMIT: usize = 100;
/// Longueur maximale d'un curseur, en caractères, avant décodage.
pub const MAX_CURSOR_CHARS: usize = 256;

/// Page d'une liste : ses éléments, et le curseur de la suivante, `null`
/// pour la dernière.
#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// Paramètres de pagination d'une requête, curseur encore opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageQuery {
    pub limit: usize,
    pub cursor: Option<String>,
}

impl PageQuery {
    /// Lit `limit` et `cursor` dans la query string ; les autres paramètres
    /// sont ignorés. 400 pour un `limit` hors de 1..=100 ou illisible, un
    /// curseur vide ou trop long, ou un paramètre répété.
    pub fn parse(query: Option<&str>) -> Result<Self, ApiError> {
        let mut limit = None;
        let mut cursor = None;
        for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "limit" => {
                    let parsed = value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=MAX_LIMIT).contains(n))
                        .ok_or(ApiError::BAD_REQUEST)?;
                    if limit.replace(parsed).is_some() {
                        return Err(ApiError::BAD_REQUEST);
                    }
                }
                "cursor" => {
                    if value.is_empty() || value.chars().count() > MAX_CURSOR_CHARS {
                        return Err(ApiError::BAD_REQUEST);
                    }
                    if cursor.replace(value.into_owned()).is_some() {
                        return Err(ApiError::BAD_REQUEST);
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            limit: limit.unwrap_or(DEFAULT_LIMIT),
            cursor,
        })
    }
}

/// Garde les `limit` premières lignes d'une lecture de `limit + 1` : `true`
/// s'il en restait au-delà, donc une page suivante.
pub fn split<R>(rows: &mut Vec<R>, limit: usize) -> bool {
    let more = rows.len() > limit;
    rows.truncate(limit);
    more
}

/// Charge utile en clair : étiquette de la liste, puis champs séparés par
/// `|` ; le dernier champ peut contenir `:` (IPv6).
fn encode(tag: &str, fields: &[String]) -> String {
    let mut plain = tag.to_owned();
    for field in fields {
        plain.push('|');
        plain.push_str(field);
    }
    URL_SAFE_NO_PAD.encode(plain)
}

/// Champs d'un curseur de l'étiquette `tag`, s'il en porte exactement `n`.
fn decode(tag: &str, cursor: &str, n: usize) -> Result<Vec<String>, ApiError> {
    if cursor.chars().count() > MAX_CURSOR_CHARS {
        return Err(ApiError::BAD_REQUEST);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| ApiError::BAD_REQUEST)?;
    let plain = String::from_utf8(bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    let mut parts = plain.splitn(n + 1, '|');
    if parts.next() != Some(tag) {
        return Err(ApiError::BAD_REQUEST);
    }
    let fields: Vec<String> = parts.map(str::to_owned).collect();
    if fields.len() != n {
        return Err(ApiError::BAD_REQUEST);
    }
    Ok(fields)
}

fn number<T: std::str::FromStr>(field: &str) -> Result<T, ApiError> {
    // `parse` accepte un `+` en tête : refusé, pour une seule écriture par
    // valeur.
    if field.starts_with('+') {
        return Err(ApiError::BAD_REQUEST);
    }
    field.parse().map_err(|_| ApiError::BAD_REQUEST)
}

/// Curseur des incidents clos d'un site : (`closed_at`, `id`) du dernier
/// incident servi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentCursor {
    pub closed_at: i64,
    pub id: i64,
}

impl IncidentCursor {
    const TAG: &str = "i1";

    pub fn encode(self) -> String {
        encode(
            Self::TAG,
            &[self.closed_at.to_string(), self.id.to_string()],
        )
    }

    pub fn decode(cursor: &str) -> Result<Self, ApiError> {
        let fields = decode(Self::TAG, cursor, 2)?;
        Ok(Self {
            closed_at: number(&fields[0])?,
            id: number(&fields[1])?,
        })
    }
}

/// Curseur des verdicts d'IP : instantané (`generated_at`), puis (`score`,
/// `ip`) du dernier verdict servi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictCursor {
    pub generated_at: i64,
    pub score: u8,
    /// Forme canonique de l'adresse, celle de `log_verdicts`.
    pub ip: String,
}

impl VerdictCursor {
    const TAG: &str = "v1";

    pub fn encode(&self) -> String {
        encode(
            Self::TAG,
            &[
                self.generated_at.to_string(),
                self.score.to_string(),
                self.ip.clone(),
            ],
        )
    }

    pub fn decode(cursor: &str) -> Result<Self, ApiError> {
        let fields = decode(Self::TAG, cursor, 3)?;
        let ip: IpAddr = fields[2].parse().map_err(|_| ApiError::BAD_REQUEST)?;
        Ok(Self {
            generated_at: number(&fields[0])?,
            score: number(&fields[1])?,
            ip: ip.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_defaults_to_50_and_stays_within_1_and_100() {
        assert_eq!(
            PageQuery::parse(None),
            Ok(PageQuery {
                limit: DEFAULT_LIMIT,
                cursor: None
            })
        );
        assert_eq!(PageQuery::parse(Some("limit=1")).map(|q| q.limit), Ok(1));
        assert_eq!(
            PageQuery::parse(Some("limit=100&autre=x")).map(|q| q.limit),
            Ok(100)
        );
        for bad in [
            "limit=0",
            "limit=101",
            "limit=-1",
            "limit=",
            "limit=abc",
            "limit=1e2",
            "limit=50&limit=50",
            "cursor=",
            "cursor=a&cursor=a",
        ] {
            assert_eq!(
                PageQuery::parse(Some(bad)),
                Err(ApiError::BAD_REQUEST),
                "{bad}"
            );
        }
        let long = "a".repeat(MAX_CURSOR_CHARS + 1);
        assert_eq!(
            PageQuery::parse(Some(&format!("cursor={long}"))),
            Err(ApiError::BAD_REQUEST)
        );
        let edge = "a".repeat(MAX_CURSOR_CHARS);
        assert_eq!(
            PageQuery::parse(Some(&format!("cursor={edge}"))).map(|q| q.cursor),
            Ok(Some(edge))
        );
    }

    #[test]
    fn a_cursor_decodes_only_for_its_own_list() {
        let incident = IncidentCursor {
            closed_at: 1_792_000_000,
            id: 42,
        };
        let text = incident.encode();
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_eq!(IncidentCursor::decode(&text), Ok(incident));
        assert_eq!(VerdictCursor::decode(&text), Err(ApiError::BAD_REQUEST));

        let verdict = VerdictCursor {
            generated_at: 1_792_000_000,
            score: 85,
            ip: "2001:db8::1".into(),
        };
        let text = verdict.encode();
        assert_eq!(VerdictCursor::decode(&text), Ok(verdict));
        assert_eq!(IncidentCursor::decode(&text), Err(ApiError::BAD_REQUEST));
    }

    #[test]
    fn a_forged_cursor_is_a_bad_request() {
        let forge = |plain: &str| URL_SAFE_NO_PAD.encode(plain);
        for bad in [
            "!!".to_owned(),
            "aGVsbG8=".to_owned(),
            forge("i1|1"),
            forge("i1|1|2|3"),
            forge("i1|+1|2"),
            forge("i1|x|2"),
            forge("i2|1|2"),
            forge(""),
            URL_SAFE_NO_PAD.encode([0xff, 0xfe]),
            "a".repeat(MAX_CURSOR_CHARS + 1),
        ] {
            assert_eq!(
                IncidentCursor::decode(&bad),
                Err(ApiError::BAD_REQUEST),
                "{bad}"
            );
        }
        for bad in [
            forge("v1|1|300|192.0.2.1"),
            forge("v1|1|85|pas-une-ip"),
            forge("v1|1|85"),
        ] {
            assert_eq!(
                VerdictCursor::decode(&bad),
                Err(ApiError::BAD_REQUEST),
                "{bad}"
            );
        }
    }

    #[test]
    fn split_keeps_the_page_and_says_if_more_follow() {
        let mut rows = vec![1, 2, 3];
        assert!(split(&mut rows, 2));
        assert_eq!(rows, [1, 2]);
        let mut rows = vec![1, 2];
        assert!(!split(&mut rows, 2));
        assert_eq!(rows, [1, 2]);
    }
}
