//! Découpeur du format Apache « combined », tel qu'Alwaysdata l'écrit :
//!
//! ```text
//! [hôte] ip ident user [date] "requête" statut taille "referer" "user-agent" [queue…]
//! ```
//!
//! - l'hôte en tête (`{request_hostname}` d'Alwaysdata) est facultatif ; il
//!   est repéré par la forme des jetons avant le `[` de la date : si le premier
//!   est une IP ou `-`, pas d'hôte ; sinon, si le deuxième l'est, le premier
//!   est l'hôte. L'utilisateur (`%u`) prend tout jusqu'au `[`, espaces
//!   comprises, et n'est jamais rendu ;
//! - dans un champ entre guillemets, `\"` et `\\` ne ferment pas le champ ;
//!   les octets sont rendus tels quels, échappements compris ;
//! - une ligne coupée après le statut reste valide : un champ entre
//!   guillemets non fermé se clôt en fin de ligne et les champs suivants
//!   manquent (l'agent coupe chaque ligne à 16 Kio, `docs/logs.md`) ;
//! - en queue (format « Advanced » : protocole puis durée), un dernier jeton
//!   décimal est la durée en secondes ; le reste est ignoré.
//!
//! Aucune allocation : les champs sont des tranches de la ligne.

use super::{MAX_LINE, RawFields, Rejection};

pub fn split(line: &[u8]) -> Result<RawFields<'_>, Rejection> {
    if line.len() > MAX_LINE {
        return Err(Rejection::TooLong);
    }
    let line = trim_end(line);
    // Le `[` de la date suit une espace et précède un chiffre : un hôte IPv6
    // entre crochets, en tête, ne le trompe pas.
    let open = line
        .windows(3)
        .position(|w| w[0] == b' ' && w[1] == b'[' && w[2].is_ascii_digit())
        .map(|at| at + 1)
        .ok_or(Rejection::Malformed)?;
    let mut head = tokens(&line[..open]);
    let first = head.next().ok_or(Rejection::Malformed)?;
    let (host, ip) = if is_client(first) {
        (None, first)
    } else {
        match head.next() {
            Some(second) if is_client(second) => (Some(first), second),
            _ => return Err(Rejection::Malformed),
        }
    };
    // Ident puis utilisateur : au moins un jeton chacun.
    if head.count() < 2 {
        return Err(Rejection::Malformed);
    }
    let close = line[open..]
        .iter()
        .position(|&b| b == b']')
        .map(|at| open + at)
        .ok_or(Rejection::Malformed)?;
    let timestamp = &line[open + 1..close];

    let mut cursor = Cursor {
        line,
        at: close + 1,
    };
    let request = cursor.quoted().ok_or(Rejection::Malformed)?;
    let status = cursor.token().ok_or(Rejection::Malformed)?;
    let size = cursor.token();
    let referer = cursor.quoted();
    let user_agent = cursor.quoted();
    let duration = cursor.rest_tokens().last().filter(|t| is_decimal(t));

    Ok(RawFields {
        host,
        ip: Some(ip),
        timestamp: Some(timestamp),
        request: Some(request),
        status: Some(status),
        size,
        referer,
        user_agent,
        duration,
    })
}

struct Cursor<'a> {
    line: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn skip_spaces(&mut self) {
        while self.line.get(self.at) == Some(&b' ') {
            self.at += 1;
        }
    }

    /// Prochain jeton entre guillemets, sans eux ; `None` si le prochain
    /// jeton n'en est pas un ou si la ligne est finie.
    fn quoted(&mut self) -> Option<&'a [u8]> {
        self.skip_spaces();
        if self.line.get(self.at) != Some(&b'"') {
            return None;
        }
        let start = self.at + 1;
        let mut i = start;
        while i < self.line.len() {
            match self.line[i] {
                b'\\' => i += 2,
                b'"' => {
                    self.at = i + 1;
                    return Some(&self.line[start..i]);
                }
                _ => i += 1,
            }
        }
        // Guillemet non fermé : ligne coupée, le champ va jusqu'au bout.
        self.at = self.line.len();
        Some(&self.line[start..])
    }

    /// Prochain jeton nu (sans guillemet en tête).
    fn token(&mut self) -> Option<&'a [u8]> {
        self.skip_spaces();
        if self.at >= self.line.len() || self.line[self.at] == b'"' {
            return None;
        }
        let start = self.at;
        while self.at < self.line.len() && self.line[self.at] != b' ' {
            self.at += 1;
        }
        Some(&self.line[start..self.at])
    }

    fn rest_tokens(&self) -> impl Iterator<Item = &'a [u8]> {
        tokens(&self.line[self.at.min(self.line.len())..])
    }
}

fn tokens(raw: &[u8]) -> impl Iterator<Item = &[u8]> {
    raw.split(|&b| b == b' ').filter(|t| !t.is_empty())
}

/// Champ client : une IP ou `-`.
fn is_client(token: &[u8]) -> bool {
    token == b"-" || std::str::from_utf8(token).is_ok_and(|t| t.parse::<std::net::IpAddr>().is_ok())
}

fn trim_end(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn is_decimal(token: &[u8]) -> bool {
    let mut dots = 0;
    !token.is_empty()
        && token.iter().all(|&b| {
            if b == b'.' {
                dots += 1;
                true
            } else {
                b.is_ascii_digit()
            }
        })
        && dots <= 1
        && token[0] != b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(raw: Option<&[u8]>) -> Option<&str> {
        raw.map(|b| std::str::from_utf8(b).expect("utf8"))
    }

    #[test]
    fn an_alwaysdata_standard_line_has_a_host() {
        let line = br#"site-a.example.org 192.0.2.10 - - [12/Apr/2026:14:32:10 +0200] "GET /p?q=x HTTP/2.0" 200 12345 "https://www.example.org/" "Mozilla/5.0 (X11)""#;
        let raw = split(line).expect("valide");
        assert_eq!(s(raw.host), Some("site-a.example.org"));
        assert_eq!(s(raw.ip), Some("192.0.2.10"));
        assert_eq!(s(raw.timestamp), Some("12/Apr/2026:14:32:10 +0200"));
        assert_eq!(s(raw.request), Some("GET /p?q=x HTTP/2.0"));
        assert_eq!(s(raw.status), Some("200"));
        assert_eq!(s(raw.size), Some("12345"));
        assert_eq!(s(raw.referer), Some("https://www.example.org/"));
        assert_eq!(s(raw.user_agent), Some("Mozilla/5.0 (X11)"));
        assert_eq!(raw.duration, None);
    }

    #[test]
    fn a_plain_apache_line_has_no_host() {
        let line = br#"2001:db8::7 - frank [12/Apr/2026:14:32:10 +0000] "GET / HTTP/1.1" 304 - "-" "curl/8.0""#;
        let raw = split(line).expect("valide");
        assert_eq!(raw.host, None);
        assert_eq!(s(raw.ip), Some("2001:db8::7"));
        assert_eq!(s(raw.status), Some("304"));
        assert_eq!(s(raw.size), Some("-"));
    }

    #[test]
    fn a_user_with_a_space_does_not_shift_the_fields() {
        for line in [
            &br#"192.0.2.9 - john doe [12/Apr/2026:14:32:10 +0200] "GET / HTTP/1.1" 401 0 "-" "ua""#[..],
            br#"site-a.example.org 192.0.2.9 - john doe [12/Apr/2026:14:32:10 +0200] "GET / HTTP/1.1" 401 0 "-" "ua""#,
        ] {
            let raw = split(line).expect("valide");
            assert_eq!(s(raw.ip), Some("192.0.2.9"));
            assert_eq!(s(raw.status), Some("401"));
        }
    }

    #[test]
    fn the_advanced_tail_gives_the_duration() {
        let line = br#"h 198.51.100.4 - - [12/Apr/2026:14:32:10 +0200] "GET / HTTP/2.0" 200 5 "-" "ua" HTTP/2.0 0.123"#;
        assert_eq!(s(split(line).expect("valide").duration), Some("0.123"));
        let line = br#"h 198.51.100.4 - - [12/Apr/2026:14:32:10 +0200] "GET / HTTP/2.0" 200 5 "-" "ua" HTTP/2.0"#;
        assert_eq!(split(line).expect("valide").duration, None);
    }

    #[test]
    fn escaped_quotes_stay_inside_the_field() {
        let line = br#"h 192.0.2.1 - - [12/Apr/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "-" "a \"b\" c\\" 0.5"#;
        let raw = split(line).expect("valide");
        assert_eq!(s(raw.user_agent), Some(r#"a \"b\" c\\"#));
        assert_eq!(s(raw.duration), Some("0.5"));
    }

    #[test]
    fn a_line_cut_in_the_user_agent_is_still_read() {
        let line = br#"h 192.0.2.1 - - [12/Apr/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0 (tronqu"#;
        let raw = split(line).expect("valide");
        assert_eq!(s(raw.user_agent), Some("Mozilla/5.0 (tronqu"));
        let line = br#"h 192.0.2.1 - - [12/Apr/2026:14:32:10 +0200] "GET / HTTP/1.1" 200"#;
        let raw = split(line).expect("valide");
        assert_eq!(raw.size, None);
        assert_eq!(raw.user_agent, None);
    }

    #[test]
    fn broken_structures_are_malformed() {
        for line in [
            &b""[..],
            b"pas une ligne de log",
            b"a b c d e [12/Apr/2026:14:32:10 +0200] \"GET /\" 200 1",
            b"192.0.2.1 - [12/Apr/2026:14:32:10 +0200] \"GET /\" 200 1",
            b"h 192.0.2.1 - [12/Apr/2026:14:32:10 +0200] \"GET /\" 200 1",
            b"h 192.0.2.1 - - [12/Apr/2026:14:32:10 +0200",
            b"h 192.0.2.1 - - [12/Apr/2026:14:32:10 +0200] GET / 200 1",
            b"h 192.0.2.1 - - [12/Apr/2026:14:32:10 +0200] \"GET / HTTP/1.1\"",
        ] {
            assert_eq!(
                split(line).map(|_| ()),
                Err(Rejection::Malformed),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        assert_eq!(
            split(&vec![b'a'; MAX_LINE + 1]).map(|_| ()),
            Err(Rejection::TooLong)
        );
    }
}
