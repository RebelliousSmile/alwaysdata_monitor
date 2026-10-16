//! Contrat de l'analyse de logs (`docs/logs.md`, issue #7).
//!
//! L'acquisition est propre à chaque serveur ; l'analyse (#8) est invariante
//! et ne voit que des [`Entry`]. Entre les deux, un adaptateur découpe sa
//! ligne en [`RawFields`] (par exemple avec [`combined::split`]) et
//! [`normalize`] en fait une `Entry` : c'est la seule étape exposée aux octets
//! hostiles, écrite et fuzzée une fois.
//!
//! RGPD (`decisions.md`) : les valeurs de la query string ne sortent jamais
//! d'ici, seulement ses clés ; le referer est réduit à son hôte.

pub mod combined;
pub mod source;
pub mod time;

use std::fmt;
use std::net::IpAddr;

use jiff::tz::TimeZone;

/// Au-delà, une ligne est rejetée sans être lue : borne défensive du
/// veilleur. L'agent coupe déjà chaque ligne à 16 Kio (`docs/logs.md`).
pub const MAX_LINE: usize = 4 * 1024 * 1024;
pub const MAX_USER_AGENT: usize = 512;
pub const MAX_PATH: usize = 2048;
pub const MAX_HOST: usize = 253;
pub const MAX_METHOD: usize = 16;
pub const MAX_QUERY_KEYS: usize = 16;
pub const MAX_QUERY_KEY: usize = 32;
/// Une entrée datée de plus d'un jour après l'heure du veilleur est rejetée.
pub const MAX_FUTURE_MS: i64 = 86_400_000;
/// Marque d'un paramètre de requête écarté (sans `=`, clé longue ou
/// exotique : il peut porter un jeton).
pub const HIDDEN_QUERY_KEY: &str = "?";

/// Une requête HTTP lue dans un log, normalisée et bornée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Millisecondes UTC.
    pub timestamp_ms: i64,
    /// Hôte demandé, en minuscules, sans port ni point final.
    pub host: Option<String>,
    /// Adresse du client telle que le serveur l'a vue ; jamais tirée d'un
    /// en-tête comme `X-Forwarded-For`.
    pub ip: Option<IpAddr>,
    /// Lettres majuscules ASCII, 16 au plus ; `None` si la requête n'en a pas
    /// de lisible (`get`, octets TLS…).
    pub method: Option<String>,
    /// Cible sans la query string, ni décodée ni normalisée (`%2e`, `//` et
    /// `..` restent tels quels).
    pub path: String,
    /// Clés de la query string, dans l'ordre, sans doublon ; jamais leurs
    /// valeurs.
    pub query_keys: Vec<String>,
    pub status: u16,
    /// Octets envoyés ; `None` pour `-`.
    pub size: Option<u64>,
    /// Un referer était présent (ni vide ni `-`).
    pub referer_present: bool,
    /// Hôte du referer, normalisé comme `host`.
    pub referer_host: Option<String>,
    /// Tronqué à 512 octets, sur une frontière de caractère.
    pub user_agent: String,
    /// Durée de service, en microsecondes (format « Advanced » d'Alwaysdata).
    pub duration_us: Option<u64>,
}

impl Entry {
    /// Entrée minimale, le reste vide : pour les tests et `MemorySource`.
    pub fn new(timestamp_ms: i64, path: impl Into<String>, status: u16) -> Self {
        Self {
            timestamp_ms,
            host: None,
            ip: None,
            method: None,
            path: path.into(),
            query_keys: Vec::new(),
            status,
            size: None,
            referer_present: false,
            referer_host: None,
            user_agent: String::new(),
            duration_us: None,
        }
    }
}

/// Champs bruts d'une ligne, tranches de ses octets, avant normalisation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawFields<'a> {
    pub host: Option<&'a [u8]>,
    pub ip: Option<&'a [u8]>,
    pub timestamp: Option<&'a [u8]>,
    pub request: Option<&'a [u8]>,
    pub status: Option<&'a [u8]>,
    pub size: Option<&'a [u8]>,
    pub referer: Option<&'a [u8]>,
    pub user_agent: Option<&'a [u8]>,
    pub duration: Option<&'a [u8]>,
}

/// Motif du rejet d'une ligne : compté, jamais bloquant pour le lot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rejection {
    TooLong,
    Malformed,
    Timestamp,
    Future,
    Status,
}

impl Rejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLong => "too_long",
            Self::Malformed => "malformed",
            Self::Timestamp => "timestamp",
            Self::Future => "future",
            Self::Status => "status",
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `RawFields` → `Entry`. `source_tz` sert aux horodatages sans décalage
/// écrit ; `now_ms` vient de l'horloge injectée (`clock.rs`).
pub fn normalize(
    raw: &RawFields<'_>,
    source_tz: Option<&TimeZone>,
    now_ms: i64,
) -> Result<Entry, Rejection> {
    let timestamp_ms = raw
        .timestamp
        .and_then(|t| time::parse_apache(t, source_tz))
        .ok_or(Rejection::Timestamp)?;
    if timestamp_ms > now_ms.saturating_add(MAX_FUTURE_MS) {
        return Err(Rejection::Future);
    }
    let status = raw.status.and_then(parse_status).ok_or(Rejection::Status)?;
    let (method, target) = split_request(raw.request.unwrap_or_default());
    let (path, query) = match target.iter().position(|&b| b == b'?') {
        Some(at) => (&target[..at], Some(&target[at + 1..])),
        None => (target, None),
    };
    let referer = raw.referer.filter(|r| !r.is_empty() && *r != b"-");
    Ok(Entry {
        timestamp_ms,
        host: raw.host.and_then(normalize_host),
        ip: raw.ip.and_then(parse_ip),
        method,
        path: truncate_utf8(path, MAX_PATH),
        query_keys: query.map(query_keys).unwrap_or_default(),
        status,
        size: raw.size.and_then(parse_u64),
        referer_present: referer.is_some(),
        referer_host: referer.and_then(referer_host),
        user_agent: truncate_utf8(raw.user_agent.unwrap_or_default(), MAX_USER_AGENT),
        duration_us: raw.duration.and_then(parse_duration_us),
    })
}

/// UTF-8 avec remplacement des octets invalides (U+FFFD), coupé au dernier
/// caractère qui tient dans `max` octets.
pub fn truncate_utf8(bytes: &[u8], max: usize) -> String {
    // Une marge de 4 octets suffit : au-delà, rien ne serait gardé.
    let head = &bytes[..bytes.len().min(max.saturating_add(4))];
    let text = String::from_utf8_lossy(head);
    if text.len() <= max {
        return text.into_owned();
    }
    let cut = text
        .char_indices()
        .map(|(at, c)| at + c.len_utf8())
        .take_while(|&end| end <= max)
        .last()
        .unwrap_or(0);
    text[..cut].to_owned()
}

/// `METHOD SP cible [SP protocole]` ; méthode `None` si elle n'est pas en
/// majuscules ASCII, la cible gardée quand même (`get /.env` est un signal).
fn split_request(request: &[u8]) -> (Option<String>, &[u8]) {
    let parts: Vec<&[u8]> = request
        .split(|&b| b == b' ')
        .filter(|p| !p.is_empty())
        .collect();
    match parts.as_slice() {
        [method, target] | [method, target, _] => {
            let valid = (1..=MAX_METHOD).contains(&method.len())
                && method.iter().all(u8::is_ascii_uppercase);
            (
                valid.then(|| String::from_utf8_lossy(method).into_owned()),
                target,
            )
        }
        _ => (None, &[]),
    }
}

fn query_keys(query: &[u8]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for param in query.split(|&b| b == b'&').filter(|p| !p.is_empty()) {
        let key = match param.iter().position(|&b| b == b'=') {
            Some(at) if is_plain_key(&param[..at]) => {
                String::from_utf8_lossy(&param[..at]).into_owned()
            }
            _ => HIDDEN_QUERY_KEY.to_owned(),
        };
        if !keys.contains(&key) {
            if keys.len() == MAX_QUERY_KEYS {
                break;
            }
            keys.push(key);
        }
    }
    keys
}

/// Clé courante d'un formulaire : 1 à 32 caractères de `[A-Za-z0-9_.-]`,
/// crochets compris (`a[]`). Le reste peut être un jeton : écarté.
fn is_plain_key(key: &[u8]) -> bool {
    (1..=MAX_QUERY_KEY).contains(&key.len())
        && key
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'[' | b']'))
}

/// Minuscules, sans port ni point final ; `None` si vide ou hors
/// `[a-z0-9.-]` (une IPv6 entre crochets reste acceptée).
fn normalize_host(raw: &[u8]) -> Option<String> {
    let raw = if raw.first() == Some(&b'[') {
        let end = raw.iter().position(|&b| b == b']')?;
        &raw[..=end]
    } else {
        match raw.iter().rposition(|&b| b == b':') {
            Some(at) => &raw[..at],
            None => raw,
        }
    };
    let raw = raw.strip_suffix(b".").unwrap_or(raw);
    if raw.is_empty() || raw.len() > MAX_HOST || raw == b"-" {
        return None;
    }
    let ok = raw
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'));
    ok.then(|| String::from_utf8_lossy(raw).to_ascii_lowercase())
}

fn referer_host(referer: &[u8]) -> Option<String> {
    let rest = referer
        .windows(3)
        .position(|w| w == b"://")
        .map(|at| &referer[at + 3..])?;
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    // Identifiants éventuels (`user:pass@hôte`) : jamais gardés.
    let host = match authority.iter().rposition(|&b| b == b'@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    normalize_host(host)
}

fn parse_ip(raw: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(raw).ok()?.parse().ok()
}

fn parse_status(raw: &[u8]) -> Option<u16> {
    let status = u16::try_from(parse_u64(raw)?).ok()?;
    (100..=599).contains(&status).then_some(status)
}

fn parse_u64(raw: &[u8]) -> Option<u64> {
    if raw.is_empty() || raw.len() > 20 || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(raw).ok()?.parse().ok()
}

/// Secondes décimales (`0.123`) → microsecondes, arrondi à l'inférieur.
fn parse_duration_us(raw: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(raw).ok()?;
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole = parse_u64(whole.as_bytes())?;
    let micros = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(6)
        .fold(0u64, |acc, digit| acc * 10 + u64::from(digit - b'0'));
    whole.checked_mul(1_000_000)?.checked_add(micros)
}

#[cfg(test)]
mod tests;
