//! Bloc `# BEGIN vigie` (#13) : fichiers de référence de la génération, cas
//! de refus de la grammaire, et vecteurs partagés avec l'agent PHP.
//!
//! `tests/fixtures/htaccess/vectors.json` porte des blocs écrits à la main
//! et un fuzz différentiel à graine fixe (une ligne d'un bloc de référence
//! dont un octet est changé, inséré ou supprimé), chacun avec le verdict du
//! validateur Rust ; `agent/php/tests/AgentTest.php` rejoue chaque vecteur
//! et doit rendre le même verdict, au code de refus près.
//!
//! `VIGIE_WRITE_VECTORS=1 cargo test --test htaccess` régénère les vecteurs
//! et les fichiers de référence ; sans la variable, les fichiers committés
//! doivent être identiques à ce que le générateur produit.

use std::path::{Path, PathBuf};

use jiff::tz::TimeZone;
use serde_json::{Value, json};

use vigie::recommend::htaccess::{self, Group, Target};
use vigie::recommend::{self, Proposal};

/// 2026-06-15T10:00:00Z : aucun changement d'heure à Paris dans les
/// 31 jours qui suivent.
const NOW: i64 = 1_781_517_600;
const TZ: &str = "Europe/Paris";
const SEED: u64 = 0x5eed_0013_d1ff_f00d;
const FUZZ: usize = 800;

fn tz() -> TimeZone {
    TimeZone::get(TZ).unwrap()
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/htaccess")
}

fn writing() -> bool {
    std::env::var_os("VIGIE_WRITE_VECTORS").is_some()
}

fn ua(bot: &str) -> Proposal {
    Proposal::UserAgent {
        bot: bot.into(),
        literal: bot.into(),
    }
}

fn ip(addr: &str) -> Proposal {
    Proposal::Ip {
        ip: addr.parse().unwrap(),
        rdns: "vps-1.hosting.example.net".into(),
        own_score: 80,
    }
}

/// Fichiers de référence : nom → bloc généré.
fn goldens() -> Vec<(&'static str, String)> {
    let tz = tz();
    let plan = |current: &[Group], proposals: &[Proposal], now: i64| {
        recommend::plan(current, proposals, now, &tz).unwrap()
    };
    let ua_only = plan(
        &[],
        &[ua("Bytespider"), ua("SEOkicks"), ua("Screaming Frog")],
        NOW,
    );
    let ips = plan(&[], &[ip("203.0.113.7"), ip("2001:db8::7")], NOW);
    // Bloc cumulatif : un groupe d'UA posé dix jours plus tôt, une IP posée
    // la veille et expirée ; une nouvelle IP et un nouveau robot.
    let earlier = plan(
        &[],
        &[ua("Bytespider"), ip("198.51.100.20")],
        NOW - 10 * 86_400,
    );
    let cumulative = plan(
        &earlier.groups,
        &[ua("Bytespider"), ua("MauiBot"), ip("192.0.2.44")],
        NOW,
    );
    assert_eq!(cumulative.kept.len(), 1);
    assert_eq!(cumulative.expired.len(), 1);
    vec![
        ("ua.htaccess", ua_only.block()),
        ("ip.htaccess", ips.block()),
        ("cumulative.htaccess", cumulative.block()),
        ("empty.htaccess", htaccess::render(&[])),
    ]
}

#[test]
fn generated_blocks_match_the_golden_files_byte_for_byte() {
    for (name, block) in goldens() {
        let path = fixtures().join(name);
        if writing() {
            std::fs::write(&path, &block).unwrap();
        }
        let committed = std::fs::read_to_string(&path).expect(name);
        assert_eq!(
            committed, block,
            "{name} à régénérer (VIGIE_WRITE_VECTORS=1)"
        );
        htaccess::validate(block.as_bytes(), NOW, &tz()).expect(name);
    }
    let ua = std::fs::read_to_string(fixtures().join("ua.htaccess")).unwrap();
    // Ordre stable, littéraux échappés, %{TIME} à l'heure de Paris (UTC+2).
    assert!(ua.contains("RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC,OR]\n"));
    assert!(ua.contains("RewriteCond %{HTTP_USER_AGENT} \"Screaming Frog\" [NC]\n"));
    assert!(ua.contains("RewriteCond %{TIME} <20260715120000\n"), "{ua}");
    let ip = std::fs::read_to_string(fixtures().join("ip.htaccess")).unwrap();
    assert!(ip.contains("RewriteCond %{REMOTE_ADDR} \"^203\\.0\\.113\\.7$\"\n"));
    assert!(ip.contains("RewriteCond %{REMOTE_ADDR} \"^2001\\:db8\\:\\:7$\"\n"));
    assert!(ip.contains("RewriteCond %{TIME} <20260616120000\n"), "{ip}");
}

/// Bloc d'un groupe d'UA valide autour de `lines`.
fn wrap(lines: &[&str]) -> String {
    let mut block = vec![htaccess::BEGIN, htaccess::ENGINE];
    block.extend_from_slice(lines);
    block.push(htaccess::END);
    block.join("\n") + "\n"
}

const UA_OK: &str = "RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC]";
const TIME_OK: &str = "RewriteCond %{TIME} <20260620120000";
const RULE: &str = "RewriteRule ^ - [F,L]";

/// Vecteurs écrits à la main : nom, bloc, verdict.
fn handwritten() -> Vec<(String, String, &'static str)> {
    let mut v: Vec<(String, String, &'static str)> = Vec::new();
    let mut add = |name: &str, block: String, verdict: &'static str| {
        v.push((name.to_owned(), block, verdict));
    };
    add("groupe d'UA valide", wrap(&[UA_OK, TIME_OK, RULE]), "valid");
    for directive in [
        "php_value auto_prepend_file /tmp/x.php",
        "php_flag engine on",
        "AddHandler application/x-httpd-php .jpg",
        "SetHandler application/x-httpd-php",
        "AddType application/x-httpd-php .png",
        "Action php-script /cgi-bin/php",
        "Include /etc/passwd",
        "auto_prepend_file x",
        "allow_url_include On",
        "Options +ExecCGI",
        "<Files \"x.jpg\">",
        "RewriteRule ^ /shell.php [L]",
        "RewriteCond %{QUERY_STRING} x",
    ] {
        add(
            directive,
            wrap(&[directive, UA_OK, TIME_OK, RULE]),
            "directive",
        );
    }
    add(
        "espaces bizarres",
        wrap(&[
            "RewriteCond  %{HTTP_USER_AGENT} \"Bytespider\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "directive",
    );
    add(
        "espace en tête",
        wrap(&[
            " RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "directive",
    );
    add(
        "espace après les drapeaux",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC] ",
            TIME_OK,
            RULE,
        ]),
        "flags",
    );
    add(
        "guillemet non fermé",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"Bytespider [NC]",
            TIME_OK,
            RULE,
        ]),
        "quote",
    );
    add(
        "littéral trop long",
        wrap(&[
            &format!(
                "RewriteCond %{{HTTP_USER_AGENT}} \"{}\" [NC]",
                "a".repeat(65)
            ),
            TIME_OK,
            RULE,
        ]),
        "ua-literal",
    );
    add(
        "littéral commençant par -",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"-Bytespider\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "ua-literal",
    );
    add(
        "# END vigie imbriqué",
        wrap(&[UA_OK, TIME_OK, RULE, "# END vigie", UA_OK, TIME_OK, RULE]),
        "comment",
    );
    add(
        "ligne finissant par \\",
        wrap(&["# commentaire \\", UA_OK, TIME_OK, RULE]),
        "continuation",
    );
    add(
        "CR",
        wrap(&[UA_OK, TIME_OK, RULE]).replace('\n', "\r\n"),
        "cr",
    );
    add(
        "tabulation",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT}\t\"Bytespider\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "tab",
    );
    add(
        ". non échappé",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"archive.org_bot\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "ua-pattern",
    );
    add(
        ". échappé",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"archive\\.org_bot\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "valid",
    );
    add(
        "expression régulière",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"(.*)\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "ua-pattern",
    );
    add("groupe sans %{TIME}", wrap(&[UA_OK, RULE]), "no-time");
    add(
        "[OR] sur la dernière condition",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC,OR]",
            TIME_OK,
            RULE,
        ]),
        "or-last",
    );
    add(
        "conditions non chaînées",
        wrap(&[
            UA_OK,
            "RewriteCond %{HTTP_USER_AGENT} \"MauiBot\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "or-chain",
    );
    add(
        "UA et IP mêlées",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"Bytespider\" [NC,OR]",
            "RewriteCond %{REMOTE_ADDR} \"^203\\.0\\.113\\.7$\"",
            TIME_OK,
            RULE,
        ]),
        "group",
    );
    add(
        "deux %{TIME}",
        wrap(&[UA_OK, TIME_OK, TIME_OK, RULE]),
        "group",
    );
    add(
        "deux RewriteRule",
        wrap(&[UA_OK, TIME_OK, RULE, RULE]),
        "group",
    );
    add(
        "%{TIME} passé",
        wrap(&[UA_OK, "RewriteCond %{TIME} <20260615115959", RULE]),
        "time-past",
    );
    add(
        "%{TIME} à 31 jours pile",
        wrap(&[UA_OK, "RewriteCond %{TIME} <20260716120000", RULE]),
        "valid",
    );
    add(
        "%{TIME} d'UA au-delà de 31 jours",
        wrap(&[UA_OK, "RewriteCond %{TIME} <20260716120001", RULE]),
        "time-bound",
    );
    add(
        "%{TIME} d'IP au-delà de 25 h",
        wrap(&[
            "RewriteCond %{REMOTE_ADDR} \"^203\\.0\\.113\\.7$\"",
            "RewriteCond %{TIME} <20260616130001",
            RULE,
        ]),
        "time-bound",
    );
    add(
        "%{TIME} d'IP à 25 h pile",
        wrap(&[
            "RewriteCond %{REMOTE_ADDR} \"^203\\.0\\.113\\.7$\"",
            "RewriteCond %{TIME} <20260616130000",
            RULE,
        ]),
        "valid",
    );
    add(
        "%{TIME} impossible",
        wrap(&[UA_OK, "RewriteCond %{TIME} <20260631120000", RULE]),
        "time-format",
    );
    add(
        "littéral qui touche Googlebot",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"googlebot\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "protected-ua",
    );
    add(
        "littéral qui touche un navigateur",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"Firefox\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "protected-ua",
    );
    add(
        "littéral générique",
        wrap(&[
            "RewriteCond %{HTTP_USER_AGENT} \"curl\" [NC]",
            TIME_OK,
            RULE,
        ]),
        "protected-ua",
    );
    add(
        "IP non canonique",
        wrap(&[
            "RewriteCond %{REMOTE_ADDR} \"^2001\\:0db8\\:\\:7$\"",
            TIME_OK.replace("20260620", "20260616").as_str(),
            RULE,
        ]),
        "ip",
    );
    add(
        "IPv4 mappée",
        wrap(&[
            "RewriteCond %{REMOTE_ADDR} \"^\\:\\:ffff\\:c000\\:22c$\"",
            "RewriteCond %{TIME} <20260616120000",
            RULE,
        ]),
        "ip",
    );
    add(
        "IP sans ancres",
        wrap(&[
            "RewriteCond %{REMOTE_ADDR} \"203\\.0\\.113\\.7\"",
            "RewriteCond %{TIME} <20260616120000",
            RULE,
        ]),
        "ip-pattern",
    );
    add(
        "RewriteEngine répété",
        wrap(&[htaccess::ENGINE, UA_OK, TIME_OK, RULE]),
        "engine",
    );
    add(
        "sans RewriteEngine",
        format!(
            "{}\n{UA_OK}\n{TIME_OK}\n{RULE}\n{}\n",
            htaccess::BEGIN,
            htaccess::END
        ),
        "engine",
    );
    add(
        "commentaire sans espace",
        wrap(&["#x", UA_OK, TIME_OK, RULE]),
        "comment",
    );
    add("ligne vide", wrap(&["", UA_OK, TIME_OK, RULE]), "directive");
    add(
        "sans fin de ligne finale",
        wrap(&[UA_OK, TIME_OK, RULE]).trim_end().to_owned(),
        "final-newline",
    );
    add(
        "octet non ASCII",
        wrap(&["# é", UA_OK, TIME_OK, RULE]),
        "byte",
    );
    add(
        "trop de lignes",
        wrap(&vec!["# x"; htaccess::MAX_LINES]),
        "too-many-lines",
    );
    add(
        "trop gros",
        wrap(&[&format!("# {}", "x".repeat(htaccess::MAX_BYTES))]),
        "too-large",
    );
    add("groupe inachevé", wrap(&[UA_OK, TIME_OK]), "group");
    add(
        "première ligne",
        wrap(&[UA_OK, TIME_OK, RULE]).replacen("# BEGIN vigie", "# BEGIN Vigie", 1),
        "begin",
    );
    v
}

/// xorshift64* : graine fixe, reproductible des deux côtés.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

const OPS: [&str; 3] = ["replace", "insert", "delete"];

/// Octets du fuzz : l'ASCII qui compte pour la grammaire, et quelques octets
/// interdits.
fn alphabet() -> Vec<u8> {
    let mut bytes: Vec<u8> =
        b" !\"#$%+,-./0123456789:<>?[\\]^_{|}~ABCDEFNORTUVWZabcdefnortuvwz".to_vec();
    bytes.extend_from_slice(&[b'\r', b'\t', 0, 0x80, 0xff, b'\n']);
    bytes
}

/// Applique une mutation (même code côté PHP).
fn mutate(base: &[u8], op: &str, at: usize, byte: u8) -> Vec<u8> {
    let mut out = base.to_vec();
    match op {
        "replace" => out[at] = byte,
        "insert" => out.insert(at, byte),
        "delete" => {
            out.remove(at);
        }
        _ => unreachable!(),
    }
    out
}

fn verdict(block: &[u8]) -> &'static str {
    match htaccess::validate(block, NOW, &tz()) {
        Ok(_) => "valid",
        Err(refusal) => refusal.code,
    }
}

fn generate() -> Value {
    let bases: Vec<String> = goldens().into_iter().map(|(_, b)| b).collect();
    let vectors: Vec<Value> = handwritten()
        .into_iter()
        .map(|(name, block, expected)| {
            let got = verdict(block.as_bytes());
            assert_eq!(got, expected, "{name}");
            json!({"name": name, "block": block, "verdict": got})
        })
        .collect();
    let alphabet = alphabet();
    let mut rng = Rng(SEED);
    let mut fuzz = Vec::new();
    for _ in 0..FUZZ {
        let base_index = rng.below(bases.len());
        let base = bases[base_index].as_bytes();
        // Une ligne, puis une position dans la ligne, fin de ligne comprise.
        let starts: Vec<usize> = std::iter::once(0)
            .chain(
                base.iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'\n')
                    .map(|(i, _)| i + 1),
            )
            .filter(|&i| i < base.len())
            .collect();
        // Le plus souvent une ligne de directive : c'est là que la grammaire
        // se joue.
        let directives: Vec<usize> = starts
            .iter()
            .copied()
            .filter(|&i| base[i] != b'#' && base[i..].starts_with(b"Rewrite"))
            .collect();
        let start = if rng.below(100) < 85 {
            directives[rng.below(directives.len())]
        } else {
            starts[rng.below(starts.len())]
        };
        let end = base[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(base.len() - 1, |p| start + p);
        let op = OPS[rng.below(OPS.len())];
        // Surtout la fin de la ligne : motif, IP, heure, drapeaux.
        let from = if rng.below(100) < 75 {
            start + (end - start) / 2
        } else {
            start
        };
        let at = from + rng.below(end - from + 1);
        let byte = if rng.below(100) < 35 {
            b'0' + u8::try_from(rng.below(10)).unwrap()
        } else {
            alphabet[rng.below(alphabet.len())]
        };
        let mutated = mutate(base, op, at, byte);
        fuzz.push(json!({
            "base": base_index, "op": op, "at": at, "byte": byte, "verdict": verdict(&mutated)
        }));
    }
    let goldens: Vec<Value> = goldens().into_iter().map(|(name, _)| json!(name)).collect();
    json!({
        "comment": "Vecteurs de la grammaire du bloc # BEGIN vigie (#13), verdicts du validateur Rust ; l'agent PHP doit rendre les mêmes.",
        "now": NOW,
        "tz": TZ,
        "goldens": goldens,
        "bases": bases,
        "vectors": vectors,
        "fuzz": fuzz,
    })
}

#[test]
fn the_committed_vectors_match_the_generator() {
    let path = fixtures().join("vectors.json");
    let generated = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    if writing() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path).expect("vectors.json");
    assert_eq!(
        committed, generated,
        "vecteurs à régénérer (VIGIE_WRITE_VECTORS=1)"
    );
    // Le fuzz garde une part de blocs acceptés et couvre de nombreux codes.
    let value: Value = serde_json::from_str(&committed).unwrap();
    let verdicts: Vec<&str> = value["fuzz"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["verdict"].as_str().unwrap())
        .collect();
    let valid = verdicts.iter().filter(|v| **v == "valid").count();
    assert!(valid > 10 && valid < FUZZ / 2, "{valid} acceptés");
    let mut codes = verdicts.clone();
    codes.sort_unstable();
    codes.dedup();
    assert!(codes.len() >= 12, "{codes:?}");
}

#[test]
fn every_golden_block_parses_back_to_its_groups() {
    for (name, block) in goldens() {
        let groups = htaccess::parse(block.as_bytes(), &tz()).expect(name);
        assert_eq!(htaccess::render(&groups), block, "{name}");
    }
}

#[test]
fn ip_rules_and_ua_rules_have_their_own_bounds() {
    let tz = tz();
    let at = |offset: i64, target: Target| {
        let group = Group::new(target, NOW + offset, &tz).unwrap();
        htaccess::validate(htaccess::render(&[group]).as_bytes(), NOW, &tz).map(|_| ())
    };
    let ip = || Target::Ip("203.0.113.7".parse().unwrap());
    let ua = || Target::UserAgents(vec!["Bytespider".into()]);
    assert!(at(htaccess::IP_MAX_TTL, ip()).is_ok());
    assert_eq!(
        at(htaccess::IP_MAX_TTL + 1, ip()).unwrap_err().code,
        "time-bound"
    );
    assert!(at(htaccess::UA_MAX_TTL, ua()).is_ok());
    assert_eq!(
        at(htaccess::UA_MAX_TTL + 1, ua()).unwrap_err().code,
        "time-bound"
    );
    assert_eq!(at(0, ua()).unwrap_err().code, "time-past");
}
