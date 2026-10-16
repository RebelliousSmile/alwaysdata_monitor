use super::*;

/// 2026-10-16T00:00:00Z.
const NOW: i64 = 1_792_108_800_000;

fn entry(line: &[u8]) -> Result<Entry, Rejection> {
    normalize(&combined::split(line)?, None, NOW)
}

fn line(request: &str, ua: &str) -> Vec<u8> {
    format!(
        r#"site-a.example.org 192.0.2.10 - - [15/Oct/2026:14:32:10 +0200] "{request}" 200 512 "https://www.example.org/p?x=1" "{ua}" HTTP/2.0 0.123"#
    )
    .into_bytes()
}

#[test]
fn an_alwaysdata_line_becomes_an_entry() {
    let e = entry(&line("GET /a/b HTTP/2.0", "Mozilla/5.0")).expect("entrée");
    assert_eq!(e.timestamp_ms, 1_792_067_530_000);
    assert_eq!(e.host.as_deref(), Some("site-a.example.org"));
    assert_eq!(e.ip, Some("192.0.2.10".parse().unwrap()));
    assert_eq!(e.method.as_deref(), Some("GET"));
    assert_eq!(e.path, "/a/b");
    assert!(e.query_keys.is_empty());
    assert_eq!(e.status, 200);
    assert_eq!(e.size, Some(512));
    assert!(e.referer_present);
    assert_eq!(e.referer_host.as_deref(), Some("www.example.org"));
    assert_eq!(e.user_agent, "Mozilla/5.0");
    assert_eq!(e.duration_us, Some(123_000));
}

#[test]
fn query_values_never_leave_the_contract() {
    let e = entry(&line("GET /a?token=s3cr3t&q=x&q=y&a[]=1 HTTP/1.1", "ua")).unwrap();
    assert_eq!(e.path, "/a");
    assert_eq!(e.query_keys, ["token", "q", "a[]"]);
    let e = entry(&line("GET /reset?AbC123jetonLong&ok=1 HTTP/1.1", "ua")).unwrap();
    assert_eq!(e.query_keys, [HIDDEN_QUERY_KEY, "ok"]);
    let long_key = format!("GET /x?{}=1 HTTP/1.1", "k".repeat(MAX_QUERY_KEY + 1));
    assert_eq!(
        entry(&line(&long_key, "ua")).unwrap().query_keys,
        [HIDDEN_QUERY_KEY]
    );
    for secret in ["s3cr3t", "AbC123jetonLong"] {
        let e = entry(&line(&format!("GET /r?t={secret}&{secret} HTTP/1.1"), "ua")).unwrap();
        assert!(!format!("{e:?}").contains(secret), "{e:?}");
    }
    let many: String = (0..40).map(|i| format!("k{i}=v&")).collect();
    let e = entry(&line(&format!("GET /m?{many} HTTP/1.1"), "ua")).unwrap();
    assert_eq!(e.query_keys.len(), MAX_QUERY_KEYS);
}

#[test]
fn requests_of_every_shape_are_read() {
    let e = entry(&line("GET /", "ua")).unwrap();
    assert_eq!((e.method.as_deref(), e.path.as_str()), (Some("GET"), "/"));
    let e = entry(&line("get /.env HTTP/1.1", "ua")).unwrap();
    assert_eq!((e.method.as_deref(), e.path.as_str()), (None, "/.env"));
    let e = entry(&line(
        "\\x16\\x03\\x01\\x02\\x00\\x01\\x00\\x01\\xfc\\x03\\x03",
        "ua",
    ))
    .unwrap();
    assert_eq!((e.method, e.path.as_str()), (None, ""));
    let e = entry(&line("", "ua")).unwrap();
    assert_eq!((e.method, e.path.as_str()), (None, ""));
    let e = entry(&line("GET /%2e%2e//etc/passwd HTTP/1.1", "ua")).unwrap();
    assert_eq!(e.path, "/%2e%2e//etc/passwd");
}

#[test]
fn hostile_fields_are_bounded_and_valid_utf8() {
    // UA de 1 Mo, multi-octets : coupé sur une frontière de caractère.
    let ua = "é".repeat(512 * 1024);
    let e = entry(&line("GET / HTTP/1.1", &ua)).unwrap();
    assert!(e.user_agent.len() <= MAX_USER_AGENT);
    assert_eq!(e.user_agent.len(), 512);
    assert!(e.user_agent.chars().all(|c| c == 'é'));

    // Octets invalides dans le chemin et l'UA.
    let mut raw = line("GET /a\u{1}b HTTP/1.1", "ua\u{2}x");
    let at = raw.windows(4).position(|w| w == b"/a\x01b").unwrap();
    raw[at + 2] = 0xff;
    let at = raw.windows(4).position(|w| w == b"ua\x02x").unwrap();
    raw[at + 2] = 0xc3;
    let e = entry(&raw).unwrap();
    assert_eq!(e.path, "/a\u{fffd}b");
    assert_eq!(e.user_agent, "ua\u{fffd}x");

    let path = format!("GET /{} HTTP/1.1", "a".repeat(10_000));
    assert_eq!(entry(&line(&path, "ua")).unwrap().path.len(), MAX_PATH);
}

#[test]
fn hosts_are_normalized() {
    let raw = |host: &str| {
        format!(
            r#"{host} 192.0.2.1 - - [15/Oct/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "-" "ua""#
        )
        .into_bytes()
    };
    assert_eq!(
        entry(&raw("Site-A.Example.ORG:443"))
            .unwrap()
            .host
            .as_deref(),
        Some("site-a.example.org")
    );
    assert_eq!(
        entry(&raw("site-a.example.org.")).unwrap().host.as_deref(),
        Some("site-a.example.org")
    );
    assert_eq!(
        entry(&raw("[2001:db8::1]:8443")).unwrap().host.as_deref(),
        Some("[2001:db8::1]")
    );
    assert_eq!(entry(&raw("évil<script>")).unwrap().host, None);
    let e = entry(&raw("h")).unwrap();
    assert!(!e.referer_present);
    assert_eq!(e.referer_host, None);
}

#[test]
fn the_referer_keeps_only_its_host() {
    let raw = r#"h 192.0.2.1 - - [15/Oct/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "https://user:pass@WWW.Example.org:8080/p?jeton=x" "ua""#;
    let e = entry(raw.as_bytes()).unwrap();
    assert_eq!(e.referer_host.as_deref(), Some("www.example.org"));
    assert!(!format!("{e:?}").contains("pass"));
    let raw = r#"h 192.0.2.1 - - [15/Oct/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "android-app://x" "ua""#;
    assert_eq!(
        entry(raw.as_bytes()).unwrap().referer_host.as_deref(),
        Some("x")
    );
    let raw =
        r#"h 192.0.2.1 - - [15/Oct/2026:14:32:10 +0200] "GET / HTTP/1.1" 200 1 "pas une url" "ua""#;
    let e = entry(raw.as_bytes()).unwrap();
    assert!(e.referer_present);
    assert_eq!(e.referer_host, None);
}

#[test]
fn rejections_carry_their_reason() {
    let at = |stamp: &str, status: &str| {
        format!(r#"h 192.0.2.1 - - [{stamp}] "GET / HTTP/1.1" {status} 1 "-" "ua""#).into_bytes()
    };
    assert_eq!(
        entry(&at("15/Oct/2026:14:32:10", "200")),
        Err(Rejection::Timestamp)
    );
    assert_eq!(
        entry(&at("18/Oct/2026:14:32:10 +0000", "200")),
        Err(Rejection::Future)
    );
    assert!(entry(&at("16/Oct/2026:23:59:00 +0000", "200")).is_ok());
    assert_eq!(
        entry(&at("15/Oct/2026:14:32:10 +0200", "999")),
        Err(Rejection::Status)
    );
    assert_eq!(
        entry(&at("15/Oct/2026:14:32:10 +0200", "abc")),
        Err(Rejection::Status)
    );
    assert_eq!(entry(b"rien"), Err(Rejection::Malformed));
    // Avec un fuseau de source, l'horodatage sans décalage passe.
    let paris = TimeZone::get("Europe/Paris").unwrap();
    let raw = at("15/Oct/2026:14:32:10", "200");
    let e = normalize(&combined::split(&raw).unwrap(), Some(&paris), NOW).unwrap();
    assert_eq!(e.timestamp_ms, 1_792_067_530_000);
}

#[test]
fn durations_and_sizes() {
    for (raw, expected) in [
        ("0.123", Some(123_000)),
        ("2", Some(2_000_000)),
        ("1.5", Some(1_500_000)),
        ("0.0000019", Some(1)),
        ("1.", Some(1_000_000)),
        ("abc", None),
        ("1.2.3", None),
        ("-1", None),
        (".5", None),
    ] {
        assert_eq!(parse_duration_us(raw.as_bytes()), expected, "{raw}");
    }
    assert_eq!(parse_u64(b"-"), None);
    assert_eq!(parse_u64(b"99999999999999999999999"), None);
}

#[test]
fn truncation_never_splits_a_character() {
    assert_eq!(truncate_utf8("aé".as_bytes(), 2), "a");
    assert_eq!(truncate_utf8("aé".as_bytes(), 3), "aé");
    assert_eq!(truncate_utf8(b"abc", 0), "");
    assert_eq!(truncate_utf8("😀😀".as_bytes(), 5), "😀");
}

/// Générateur xorshift à graine fixe : le fuzz est reproductible sans
/// dépendance.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn assert_bounded(e: &Entry) {
    assert!(e.user_agent.len() <= MAX_USER_AGENT);
    assert!(e.path.len() <= MAX_PATH);
    assert!(e.host.as_ref().is_none_or(|h| h.len() <= MAX_HOST));
    assert!(e.method.as_ref().is_none_or(|m| m.len() <= MAX_METHOD));
    assert!(e.query_keys.len() <= MAX_QUERY_KEYS);
    assert!(
        e.query_keys
            .iter()
            .all(|k| k == HIDDEN_QUERY_KEY || k.len() <= MAX_QUERY_KEY)
    );
    assert!((100..=599).contains(&e.status));
    assert!(e.timestamp_ms <= NOW + MAX_FUTURE_MS);
}

#[test]
fn fuzz_never_panics_and_stays_bounded() {
    let mut rng = XorShift(0x5eed_1234_abcd_0001);
    let alphabet: &[u8] = b" \"[]\\/:?=&.-+0123456789aGET HTTP%\xff\xc3\x00\t";
    let base = line("GET /a?b=c HTTP/1.1", "Mozilla/5.0 (compatible)");
    let mut accepted = 0;
    for round in 0..20_000 {
        let candidate: Vec<u8> = if round % 2 == 0 {
            let len = rng.below(300);
            (0..len)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect()
        } else {
            let mut mutated = base.clone();
            for _ in 0..1 + rng.below(6) {
                let at = rng.below(mutated.len());
                match rng.below(3) {
                    0 => mutated[at] = alphabet[rng.below(alphabet.len())],
                    1 => {
                        mutated.remove(at);
                    }
                    _ => mutated.insert(at, alphabet[rng.below(alphabet.len())]),
                }
            }
            mutated
        };
        if let Ok(raw) = combined::split(&candidate)
            && let Ok(e) = normalize(&raw, None, NOW)
        {
            assert_bounded(&e);
            accepted += 1;
        }
    }
    // Les mutations légères doivent souvent rester lisibles.
    assert!(accepted > 1_000, "{accepted}");
}
