//! Bloc `# BEGIN vigie` du `.htaccess` (#13) : génération et validation.
//!
//! Un `.htaccess` libre donne l'exécution de code (`php_value`,
//! `AddHandler`, `auto_prepend_file`…) : le bloc ne suit qu'une grammaire
//! fermée, **par groupes**, vérifiée ici à la génération et de nouveau par
//! l'agent avant toute écriture (`vigie-agent.php`, `htaccess_validate`). Les
//! deux validateurs rendent le même verdict, au code de refus près, sur les
//! vecteurs de `tests/fixtures/htaccess/vectors.json` (`tests/htaccess.rs`).
//!
//! ```text
//! # BEGIN vigie
//! RewriteEngine On                                   une fois, en tête
//! RewriteCond %{HTTP_USER_AGENT} "MJ12bot" [NC,OR]   groupe d'UA : [NC,OR]…
//! RewriteCond %{HTTP_USER_AGENT} "Bytespider" [NC]   … sauf la dernière
//! RewriteCond %{TIME} <20261115120000                une fois, heure locale
//! RewriteRule ^ - [F,L]                              une fois
//! RewriteCond %{REMOTE_ADDR} "^203\.0\.113\.7$"      groupe d'IP : une ligne
//! RewriteCond %{TIME} <20261017120000
//! RewriteRule ^ - [F,L]
//! # END vigie
//! ```
//!
//! Les commentaires `# ` (ASCII imprimable, sans `\`, sans `BEGIN` ni `END`)
//! sont admis partout entre les deux lignes de bornes. Toute autre ligne fait
//! refuser le bloc entier. Le validateur lit des octets, dans un ordre fixe,
//! et rend le premier refus rencontré : c'est cet ordre que l'agent reproduit.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

use jiff::civil::DateTime;
use jiff::tz::TimeZone;

pub const BEGIN: &str = "# BEGIN vigie";
pub const END: &str = "# END vigie";
pub const ENGINE: &str = "RewriteEngine On";
pub const RULE: &str = "RewriteRule ^ - [F,L]";
const UA_PREFIX: &str = "RewriteCond %{HTTP_USER_AGENT} ";
const IP_PREFIX: &str = "RewriteCond %{REMOTE_ADDR} ";
const TIME_PREFIX: &str = "RewriteCond %{TIME} <";
/// En-tête écrit sous `# BEGIN vigie`.
pub const HEADER: &str = "# Gere par Vigie (vigie site recommend) : ne pas modifier a la main.";

/// Taille et nombre de lignes du bloc, bornes comprises.
pub const MAX_BYTES: usize = 16 * 1024;
pub const MAX_LINES: usize = 200;
/// Durée d'une règle d'IP : 24 h par défaut, bornée à 25 h.
pub const IP_TTL: i64 = 24 * 3600;
pub const IP_MAX_TTL: i64 = 25 * 3600;
/// Durée d'une règle d'UA : 30 jours par défaut, bornée à 31 jours.
pub const UA_TTL: i64 = 30 * 86_400;
pub const UA_MAX_TTL: i64 = 31 * 86_400;
/// Littéral d'UA : 3 à 64 caractères.
pub const LITERAL_MIN: usize = 3;
pub const LITERAL_MAX: usize = 64;

/// Corpus d'UA protégés : aucune condition d'UA ne doit en toucher un. Le
/// même texte est une constante de l'agent (`PROTECTED_UAS`), égale à ce
/// fichier par un test.
pub const PROTECTED_UAS: &str = include_str!("../../tests/fixtures/htaccess/protected-uas.txt");

/// Les UA du corpus, un par ligne non vide.
pub fn protected_uas() -> impl Iterator<Item = &'static str> {
    PROTECTED_UAS.lines().filter(|l| !l.is_empty())
}

/// Sorte d'un groupe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    UserAgent,
    Ip,
}

impl Kind {
    pub fn max_ttl(self) -> i64 {
        match self {
            Self::UserAgent => UA_MAX_TTL,
            Self::Ip => IP_MAX_TTL,
        }
    }
}

/// Cible d'un groupe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// Littéraux, dans l'ordre des lignes (« contient, sans casse »).
    UserAgents(Vec<String>),
    Ip(IpAddr),
}

impl Target {
    pub fn kind(&self) -> Kind {
        match self {
            Self::UserAgents(_) => Kind::UserAgent,
            Self::Ip(_) => Kind::Ip,
        }
    }
}

/// Un groupe : ses conditions, son expiration dans Apache et sa règle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub target: Target,
    /// `AAAAMMJJhhmmss`, heure locale du serveur web (fuseau du site).
    pub until: String,
    /// La même heure en secondes Unix (mode `compatible` de jiff).
    pub until_ts: i64,
}

impl Group {
    /// Groupe qui expire à `until_ts`, heure écrite dans le fuseau `tz`.
    pub fn new(target: Target, until_ts: i64, tz: &TimeZone) -> Option<Self> {
        let until = local_digits(until_ts, tz)?;
        let until_ts = to_unix(&until, tz)?;
        Some(Self {
            target,
            until,
            until_ts,
        })
    }
}

/// Refus de validation : un code stable (partagé avec l'agent) et la ligne
/// en cause (1 pour la première, 0 pour le bloc entier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub line: usize,
}

impl Refusal {
    fn at(code: &'static str, line: usize) -> Self {
        Self { code, line }
    }

    /// Libellé en français du code.
    pub fn label(self) -> &'static str {
        match self.code {
            "too-large" => "bloc de plus de 16 Kio",
            "cr" => "retour chariot (CR)",
            "tab" => "tabulation",
            "nul" => "octet nul",
            "byte" => "octet hors de l'ASCII imprimable",
            "final-newline" => "pas de fin de ligne finale",
            "too-many-lines" => "plus de 200 lignes",
            "continuation" => "ligne finissant par \\ (continuation Apache)",
            "begin" => "première ligne différente de « # BEGIN vigie »",
            "end" => "dernière ligne différente de « # END vigie »",
            "comment" => "commentaire mal formé (« # », sans \\, BEGIN ni END)",
            "directive" => "ligne hors de la liste fermée",
            "quote" => "guillemets absents ou non fermés",
            "flags" => "drapeaux d'une condition d'UA autres que [NC] ou [NC,OR]",
            "ua-pattern" => "motif d'UA hors de [A-Za-z0-9 _/-], \\. et \\+",
            "ua-literal" => "littéral d'UA de 3 à 64 caractères, premier alphanumérique",
            "protected-ua" => "condition d'UA qui touche un UA protégé",
            "ip-pattern" => "motif d'IP mal formé (\"^…$\" échappé)",
            "ip" => "IP non canonique, IPv4 mappée ou adresse en ::/96",
            "time-format" => "%{TIME} mal formé (AAAAMMJJhhmmss, années 2000 à 2999)",
            "time-past" => "%{TIME} déjà passé",
            "time-bound" => "%{TIME} au-delà de la borne (IP 25 h, UA 31 jours)",
            "engine" => "RewriteEngine On absent de la tête ou répété",
            "group" => "groupe mal formé",
            "or-last" => "[OR] sur la dernière condition d'UA d'un groupe",
            "or-chain" => "conditions d'UA non chaînées par [OR]",
            "no-time" => "groupe sans %{TIME}",
            _ => "refus",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "bloc refusé : {} ({})", self.label(), self.code)
        } else {
            write!(
                f,
                "bloc refusé, ligne {} : {} ({})",
                self.line,
                self.label(),
                self.code
            )
        }
    }
}

/// Mode de lecture : validation complète (bornes de `%{TIME}` contre `now`),
/// ou structure seulement (relire un bloc en place dont des groupes ont
/// expiré).
#[derive(Debug, Clone, Copy)]
enum Mode {
    Validate { now: i64 },
    Structure,
}

/// Validation complète, avec `now` injecté et le fuseau du serveur web.
pub fn validate(block: &[u8], now: i64, tz: &TimeZone) -> Result<Vec<Group>, Refusal> {
    check(block, tz, Mode::Validate { now })
}

/// Lecture d'un bloc déjà en place : grammaire complète, sans bornes de
/// temps.
pub fn parse(block: &[u8], tz: &TimeZone) -> Result<Vec<Group>, Refusal> {
    check(block, tz, Mode::Structure)
}

/// Une ligne reconnue.
enum Line {
    Engine,
    Ua { literal: String, or: bool },
    Ip(IpAddr),
    Time { digits: String, ts: i64 },
    Rule,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    GroupStart,
    /// Conditions d'UA, la dernière avec `[OR]`.
    UaConds,
    NeedTime(Kind),
    NeedRule,
}

fn check(block: &[u8], tz: &TimeZone, mode: Mode) -> Result<Vec<Group>, Refusal> {
    if block.len() > MAX_BYTES {
        return Err(Refusal::at("too-large", 0));
    }
    for (byte, code) in [(b'\r', "cr"), (b'\t', "tab"), (0u8, "nul")] {
        if block.contains(&byte) {
            return Err(Refusal::at(code, 0));
        }
    }
    if block
        .iter()
        .any(|&b| b != b'\n' && !(0x20..=0x7e).contains(&b))
    {
        return Err(Refusal::at("byte", 0));
    }
    if block.last() != Some(&b'\n') {
        return Err(Refusal::at("final-newline", 0));
    }
    // ASCII imprimable et \n seulement : la conversion ne peut pas échouer.
    let text =
        std::str::from_utf8(&block[..block.len() - 1]).map_err(|_| Refusal::at("byte", 0))?;
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() > MAX_LINES {
        return Err(Refusal::at("too-many-lines", 0));
    }
    if let Some(at) = lines.iter().position(|l| l.ends_with('\\')) {
        return Err(Refusal::at("continuation", at + 1));
    }
    if lines[0] != BEGIN {
        return Err(Refusal::at("begin", 1));
    }
    let last = lines.len() - 1;
    if last == 0 || lines[last] != END {
        return Err(Refusal::at("end", lines.len()));
    }

    let mut groups = Vec::new();
    let mut state = State::Start;
    let mut literals: Vec<String> = Vec::new();
    let mut ip: Option<IpAddr> = None;
    let mut until: Option<(String, i64)> = None;
    for (index, raw) in lines[1..last].iter().enumerate() {
        let number = index + 2;
        let refuse = |code| Err(Refusal::at(code, number));
        if raw.starts_with('#') {
            if !raw.starts_with("# ")
                || raw.contains("BEGIN")
                || raw.contains("END")
                || raw.contains('\\')
            {
                return refuse("comment");
            }
            continue;
        }
        let line = classify(raw, tz).map_err(|code| Refusal::at(code, number))?;
        state = match (state, line) {
            (State::Start, Line::Engine) => State::GroupStart,
            (State::Start, _) => return refuse("engine"),
            (_, Line::Engine) => return refuse("engine"),
            (State::GroupStart, Line::Ua { literal, or }) => {
                literals = vec![literal];
                if or {
                    State::UaConds
                } else {
                    State::NeedTime(Kind::UserAgent)
                }
            }
            (State::GroupStart, Line::Ip(addr)) => {
                ip = Some(addr);
                State::NeedTime(Kind::Ip)
            }
            (State::GroupStart, _) => return refuse("group"),
            (State::UaConds, Line::Ua { literal, or }) => {
                literals.push(literal);
                if or {
                    State::UaConds
                } else {
                    State::NeedTime(Kind::UserAgent)
                }
            }
            (State::UaConds, Line::Time { .. }) => return refuse("or-last"),
            (State::UaConds, _) => return refuse("group"),
            (State::NeedTime(kind), Line::Time { digits, ts }) => {
                if let Mode::Validate { now } = mode {
                    if ts <= now {
                        return refuse("time-past");
                    }
                    if ts > now + kind.max_ttl() {
                        return refuse("time-bound");
                    }
                }
                until = Some((digits, ts));
                State::NeedRule
            }
            (State::NeedTime(Kind::UserAgent), Line::Ua { .. }) => return refuse("or-chain"),
            (State::NeedTime(_), Line::Rule) => return refuse("no-time"),
            (State::NeedTime(_), _) => return refuse("group"),
            (State::NeedRule, Line::Rule) => {
                let target = match ip.take() {
                    Some(addr) => Target::Ip(addr),
                    None => Target::UserAgents(std::mem::take(&mut literals)),
                };
                let (until, until_ts) = until.take().unwrap_or_default();
                groups.push(Group {
                    target,
                    until,
                    until_ts,
                });
                State::GroupStart
            }
            (State::NeedRule, _) => return refuse("group"),
        };
    }
    match state {
        State::GroupStart => Ok(groups),
        State::Start => Err(Refusal::at("engine", lines.len())),
        _ => Err(Refusal::at("group", lines.len())),
    }
}

/// Reconnaît une ligne non commentée, ou rend le code de refus.
fn classify(raw: &str, tz: &TimeZone) -> Result<Line, &'static str> {
    if raw == ENGINE {
        return Ok(Line::Engine);
    }
    if raw == RULE {
        return Ok(Line::Rule);
    }
    if let Some(rest) = raw.strip_prefix(UA_PREFIX) {
        let rest = rest.strip_prefix('"').ok_or("quote")?;
        let close = rest.find('"').ok_or("quote")?;
        let (pattern, suffix) = (&rest[..close], &rest[close + 1..]);
        let or = match suffix {
            " [NC,OR]" => true,
            " [NC]" => false,
            _ => return Err("flags"),
        };
        let literal = unescape_ua(pattern).ok_or("ua-pattern")?;
        if !literal_ok(&literal) {
            return Err("ua-literal");
        }
        if touches_protected(&literal) {
            return Err("protected-ua");
        }
        return Ok(Line::Ua { literal, or });
    }
    if let Some(rest) = raw.strip_prefix(IP_PREFIX) {
        if rest.len() < 2 || !rest.starts_with('"') || !rest.ends_with('"') {
            return Err("quote");
        }
        let inner = &rest[1..rest.len() - 1];
        let core = inner
            .strip_prefix('^')
            .and_then(|c| c.strip_suffix('$'))
            .ok_or("ip-pattern")?;
        let text = unescape_ip(core).ok_or("ip-pattern")?;
        return canonical_ip(&text).map(Line::Ip).ok_or("ip");
    }
    if let Some(rest) = raw.strip_prefix(TIME_PREFIX) {
        let ts = to_unix(rest, tz).ok_or("time-format")?;
        return Ok(Line::Time {
            digits: rest.to_owned(),
            ts,
        });
    }
    Err("directive")
}

/// Motif d'UA → littéral : `[A-Za-z0-9 _/-]`, `\.` et `\+` seulement.
fn unescape_ua(pattern: &str) -> Option<String> {
    let mut out = String::with_capacity(pattern.len());
    let mut bytes = pattern.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'\\' => match bytes.next() {
                Some(c @ (b'.' | b'+')) => out.push(char::from(c)),
                _ => return None,
            },
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b' ' | b'_' | b'/' | b'-' => {
                out.push(char::from(b));
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `[A-Za-z0-9][A-Za-z0-9 _/.+-]{2,63}` : un premier caractère alphanumérique
/// (un motif commençant par `-` serait lu comme un opérateur).
pub fn literal_ok(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    (LITERAL_MIN..=LITERAL_MAX).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric() || matches!(b, b' ' | b'_' | b'/' | b'.' | b'+' | b'-')
        })
}

/// Le littéral s'écrit échappé : `.` → `\.`, `+` → `\+`.
pub fn escape_ua(literal: &str) -> String {
    literal.replace('.', "\\.").replace('+', "\\+")
}

/// Une condition d'UA vaut « contient, sans casse » : touche-t-elle un UA du
/// corpus protégé ?
pub fn touches_protected(literal: &str) -> bool {
    let needle = literal.to_ascii_lowercase();
    protected_uas().any(|ua| ua.to_ascii_lowercase().contains(&needle))
}

fn unescape_ip(core: &str) -> Option<String> {
    let mut out = String::with_capacity(core.len());
    let mut bytes = core.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'\\' => match bytes.next() {
                Some(c @ (b'.' | b':')) => out.push(char::from(c)),
                _ => return None,
            },
            b'0'..=b'9' | b'a'..=b'f' => out.push(char::from(b)),
            _ => return None,
        }
    }
    Some(out)
}

/// IP sous forme canonique (IPv4 décimale ; IPv6 compressée en minuscules,
/// RFC 5952), hors IPv4 mappée et hors `::/96` : leur écriture diffère d'une
/// bibliothèque à l'autre, et une IPv4 mappée rend la règle inerte.
fn canonical_ip(text: &str) -> Option<IpAddr> {
    if text.contains(':') {
        if text.contains('.') {
            return None;
        }
        let addr: Ipv6Addr = text.parse().ok()?;
        let octets = addr.octets();
        let mapped = octets[..10].iter().all(|&b| b == 0) && octets[10..12] == [0xff, 0xff];
        if mapped || octets[..12].iter().all(|&b| b == 0) {
            return None;
        }
        (addr.to_string() == text).then_some(IpAddr::V6(addr))
    } else {
        let addr: std::net::Ipv4Addr = text.parse().ok()?;
        (addr.to_string() == text).then_some(IpAddr::V4(addr))
    }
}

/// IP admise dans une règle (même contrôle que la validation).
pub fn ip_ok(ip: IpAddr) -> bool {
    canonical_ip(&ip.to_string()).is_some()
}

/// `^…$`, points et deux-points échappés.
pub fn escape_ip(ip: IpAddr) -> String {
    let text = ip.to_string().replace('.', "\\.").replace(':', "\\:");
    format!("^{text}$")
}

/// `AAAAMMJJhhmmss` → secondes Unix dans `tz`, années 2000 à 2999.
pub fn to_unix(digits: &str, tz: &TimeZone) -> Option<i64> {
    let bytes = digits.as_bytes();
    if bytes.len() != 14 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let field = |from: usize, to: usize| -> i32 {
        bytes[from..to]
            .iter()
            .fold(0, |acc, &b| acc * 10 + i32::from(b - b'0'))
    };
    let year = field(0, 4);
    if !(2000..=2999).contains(&year) {
        return None;
    }
    let civil = DateTime::new(
        i16::try_from(year).ok()?,
        i8::try_from(field(4, 6)).ok()?,
        i8::try_from(field(6, 8)).ok()?,
        i8::try_from(field(8, 10)).ok()?,
        i8::try_from(field(10, 12)).ok()?,
        i8::try_from(field(12, 14)).ok()?,
        0,
    )
    .ok()?;
    Some(tz.to_timestamp(civil).ok()?.as_second())
}

/// Secondes Unix → `AAAAMMJJhhmmss` dans `tz`.
pub fn local_digits(ts: i64, tz: &TimeZone) -> Option<String> {
    let zoned = jiff::Timestamp::from_second(ts).ok()?.to_zoned(tz.clone());
    Some(zoned.strftime("%Y%m%d%H%M%S").to_string())
}

/// `AAAA-MM-JJ hh:mm:ss` pour un commentaire ou un affichage.
pub fn readable(digits: &str) -> String {
    if digits.len() != 14 {
        return digits.to_owned();
    }
    format!(
        "{}-{}-{} {}:{}:{}",
        &digits[0..4],
        &digits[4..6],
        &digits[6..8],
        &digits[8..10],
        &digits[10..12],
        &digits[12..14]
    )
}

/// Lignes d'un groupe, commentaire compris.
pub fn group_lines(group: &Group) -> Vec<String> {
    let mut lines = Vec::new();
    match &group.target {
        Target::UserAgents(literals) => {
            lines.push(format!("# ua jusqu'au {}", readable(&group.until)));
            for (i, literal) in literals.iter().enumerate() {
                let flags = if i + 1 == literals.len() {
                    "[NC]"
                } else {
                    "[NC,OR]"
                };
                lines.push(format!("{UA_PREFIX}\"{}\" {flags}", escape_ua(literal)));
            }
        }
        Target::Ip(ip) => {
            lines.push(format!("# ip jusqu'au {}", readable(&group.until)));
            lines.push(format!("{IP_PREFIX}\"{}\"", escape_ip(*ip)));
        }
    }
    lines.push(format!("{TIME_PREFIX}{}", group.until));
    lines.push(RULE.to_owned());
    lines
}

/// Bloc complet, bornes comprises, fin de ligne finale.
pub fn render(groups: &[Group]) -> String {
    let mut lines = vec![BEGIN.to_owned(), HEADER.to_owned(), ENGINE.to_owned()];
    for group in groups {
        lines.extend(group_lines(group));
    }
    lines.push(END.to_owned());
    let mut block = lines.join("\n");
    block.push('\n');
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paris() -> TimeZone {
        TimeZone::get("Europe/Paris").unwrap()
    }

    /// 2026-06-15T10:00:00Z, loin des changements d'heure.
    const NOW: i64 = 1_781_517_600;

    #[test]
    fn literals_and_escapes() {
        assert!(literal_ok("Bytespider"));
        assert!(literal_ok("archive.org_bot"));
        assert!(literal_ok("Screaming Frog"));
        assert!(!literal_ok("-x-"));
        assert!(!literal_ok("ab"));
        assert!(!literal_ok(&"a".repeat(65)));
        assert!(!literal_ok("a\"b"));
        assert_eq!(escape_ua("a.b+c"), "a\\.b\\+c");
        assert_eq!(unescape_ua("a\\.b\\+c").as_deref(), Some("a.b+c"));
        assert_eq!(unescape_ua("a.b"), None);
        assert!(touches_protected("Googlebot"));
        assert!(touches_protected("chrome"));
        assert!(!touches_protected("Bytespider"));
    }

    #[test]
    fn ips_are_canonical() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(escape_ip(v4), "^203\\.0\\.113\\.7$");
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        assert_eq!(escape_ip(v6), "^2001\\:db8\\:\\:7$");
        assert!(canonical_ip("2001:db8:0:0::7").is_none());
        assert!(canonical_ip("2001:DB8::7").is_none());
        assert!(canonical_ip("::ffff:c000:207").is_none());
        assert!(canonical_ip("::102:304").is_none());
        assert!(canonical_ip("01.2.3.4").is_none());
        assert!(canonical_ip("192.0.2.1").is_some());
    }

    #[test]
    fn times_follow_the_site_time_zone() {
        let tz = paris();
        // 12:00 à Paris en juin = 10:00 UTC.
        assert_eq!(to_unix("20260615120000", &tz), Some(NOW));
        assert_eq!(local_digits(NOW, &tz).as_deref(), Some("20260615120000"));
        assert_eq!(to_unix("20260230120000", &tz), None);
        assert_eq!(to_unix("19990615120000", &tz), None);
        assert_eq!(to_unix("2026061512000", &tz), None);
    }

    #[test]
    fn a_rendered_block_validates() {
        let tz = paris();
        let groups = vec![
            Group::new(
                Target::UserAgents(vec!["Bytespider".into(), "MJ12bot".into()]),
                NOW + UA_TTL,
                &tz,
            )
            .unwrap(),
            Group::new(
                Target::Ip("203.0.113.7".parse().unwrap()),
                NOW + IP_TTL,
                &tz,
            )
            .unwrap(),
        ];
        let block = render(&groups);
        assert_eq!(validate(block.as_bytes(), NOW, &tz).unwrap(), groups);
        assert_eq!(
            validate(block.as_bytes(), NOW + IP_TTL, &tz)
                .unwrap_err()
                .code,
            "time-past"
        );
        assert_eq!(parse(block.as_bytes(), &tz).unwrap(), groups);
        let empty = render(&[]);
        assert_eq!(validate(empty.as_bytes(), NOW, &tz).unwrap(), Vec::new());
    }
}
