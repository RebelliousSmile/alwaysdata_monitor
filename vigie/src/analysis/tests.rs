use std::path::Path;
use std::time::{Duration, Instant};

use super::catalog::{self, BotClass, classify, is_generic_tool};
use super::glob::{Glob, GlobError, MAX_PATTERN};
use super::rules::{self, CompiledRule, DEFAULT_IDS, Rule, Scope, defaults};
use crate::config::{self, Config, ConfigError};
use crate::finding::Severity;
use crate::logs::{Entry, MAX_PATH};

// --- Catalogue -------------------------------------------------------------

fn class(ua: &str) -> BotClass {
    classify(ua).class
}

fn bot_name(ua: &str) -> Option<&'static str> {
    classify(ua).bot.map(|b| b.name)
}

#[test]
fn search_engines_and_other_engines() {
    let google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    assert_eq!(class(google), BotClass::SearchEngine);
    assert_eq!(bot_name(google), Some("Googlebot"));
    for ua in [
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15 (Applebot/0.1)",
        "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    ] {
        assert_eq!(class(ua), BotClass::SearchEngine, "{ua}");
    }
    let yandex = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)";
    assert_eq!(class(yandex), BotClass::OtherEngine);
    for ua in [
        "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
        "Mozilla/5.0 (compatible; SeznamBot/4.0; +https://o-seznam.cz/)",
        "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
        "Mozilla/5.0 (compatible; 360Spider)",
        "Mozilla/5.0 (Linux; Android 7.0;) (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
    ] {
        assert_eq!(class(ua), BotClass::OtherEngine, "{ua}");
    }
    // Les quatre moteurs du bénéfice du doute, et eux seuls.
    let engines: Vec<_> = catalog::catalog()
        .iter()
        .filter(|b| b.class == BotClass::SearchEngine)
        .map(|b| b.name.to_ascii_lowercase())
        .collect();
    assert_eq!(engines, ["googlebot", "bingbot", "applebot", "duckduckbot"]);
}

#[test]
fn the_longest_name_wins() {
    let extended = "Mozilla/5.0 (compatible; Applebot-Extended/0.1)";
    assert_eq!(bot_name(extended), Some("Applebot-Extended"));
    assert_eq!(class(extended), BotClass::AiTraining);
    assert_eq!(bot_name("Applebot/0.1"), Some("Applebot"));
    assert_eq!(
        bot_name("Mozilla/5.0 (compatible; Claude-SearchBot/1.0)"),
        Some("Claude-SearchBot")
    );
    assert_eq!(
        bot_name("cohere-training-data-crawler/1.0"),
        Some("cohere-training-data-crawler")
    );
    assert_eq!(bot_name("SemrushBot-SA/0.01"), Some("SemrushBot"));
}

#[test]
fn ai_bots_carry_the_php_metadata() {
    let gpt = classify(
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    );
    let bot = gpt.bot.expect("GPTBot");
    assert_eq!(gpt.class, BotClass::AiTraining);
    assert_eq!(bot.publisher, "OpenAI");
    assert!(bot.honours_robots);
    assert!(!bot.robots_only);
    assert!(!gpt.protected());

    let bytespider = classify(
        "Mozilla/5.0 (Linux; Android 5.0) (compatible; Bytespider; spider-feedback@bytedance.com)",
    );
    assert_eq!(bytespider.class, BotClass::AiTraining);
    assert!(!bytespider.bot.unwrap().honours_robots);

    for (name, robots_only) in [("Google-Extended", true), ("GPTBot", false)] {
        assert_eq!(catalog::find(name).unwrap().robots_only, robots_only);
    }
    assert_eq!(class("ChatGPT-User/1.0"), BotClass::AiUser);
    assert!(classify("ChatGPT-User/1.0").protected());
    assert_eq!(class("PerplexityBot/1.0"), BotClass::AiSearch);
    assert_eq!(class("facebookexternalhit/1.1"), BotClass::SocialPreview);
    assert_eq!(class("ahrefsbot/7.0"), BotClass::Seo);
    assert_eq!(bot_name("ahrefsbot/7.0"), Some("AhrefsBot"));
    // Écarts relus au PHP : ni la recherche IA ni l'entraînement ne sont des
    // moteurs ; `find` lit sans casse.
    assert_eq!(catalog::find(" gptbot ").unwrap().name, "GPTBot");
    assert!(catalog::find("<script>").is_none());
}

#[test]
fn tools_browsers_and_unknown_bots() {
    for ua in [
        "",
        "  ",
        "-",
        "curl/8.5.0",
        "Wget/1.21.4",
        "python-requests/2.31.0",
        "Go-http-client/1.1",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0 Safari/537.36",
    ] {
        assert_eq!(class(ua), BotClass::Tool, "{ua:?}");
        assert!(is_generic_tool(ua), "{ua:?}");
    }
    for ua in [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        // Modèle de téléphone en « …bot » : pas un robot.
        "Mozilla/5.0 (Linux; Android 9; CUBOT X19) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
    ] {
        assert_eq!(class(ua), BotClass::Browser, "{ua}");
        assert!(classify(ua).protected());
        assert!(!is_generic_tool(ua), "{ua}");
    }
    for ua in [
        "Mozilla/5.0 (compatible; FooBot/1.0; +https://bot.example.org/)",
        "ExampleCrawler/2.0",
        "my-spider",
        "Acme Scraper 3",
        "NotABrowser/1.0",
    ] {
        let c = classify(ua);
        assert_eq!((c.bot, c.class), (None, BotClass::Unknown), "{ua}");
        assert!(!c.protected());
    }
    // Un outil n'est jamais un « robot » partageable, même avec un jeton.
    assert!(!is_generic_tool("ExampleCrawler/2.0"));
}

#[test]
fn the_catalog_is_well_formed() {
    let mut seen = std::collections::HashSet::new();
    for bot in catalog::catalog() {
        assert!(seen.insert(bot.name.to_ascii_lowercase()), "{}", bot.name);
        assert!(
            bot.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._- ".contains(&b)),
            "{}",
            bot.name
        );
        assert!(!bot.publisher.is_empty() && !bot.purpose.is_empty());
        // Un nom du catalogue se classe lui-même.
        assert_eq!(classify(bot.name).bot, Some(bot), "{}", bot.name);
        assert_eq!(bot.protected(), bot.class.protected());
    }
    for class in BotClass::ALL {
        assert_eq!(BotClass::parse(class.as_str()), Some(class));
    }
    let protected: Vec<_> = BotClass::ALL
        .into_iter()
        .filter(|c| c.protected())
        .collect();
    assert_eq!(
        protected,
        [
            BotClass::SearchEngine,
            BotClass::OtherEngine,
            BotClass::SocialPreview,
            BotClass::AiUser,
            BotClass::Browser,
        ]
    );
}

// --- Glob ------------------------------------------------------------------

fn glob(pattern: &str) -> Glob {
    Glob::new(pattern).unwrap_or_else(|err| panic!("{pattern} : {err}"))
}

#[test]
fn glob_truth_table() {
    let table: &[(&str, &str, bool)] = &[
        ("/**/x*/y", "/x1/z/x2/y", true),
        ("/**/x*/y", "/x/y", true),
        ("/**/x*/y", "/x1/z/y", false),
        ("/**/.env", "/.env", true),
        ("/**/.env", "/app/.env", true),
        ("/**/.env", "/a/b/c/.env", true),
        ("/**/.env", "/.env.bak", false),
        ("/**/.env", "/x.env", false),
        ("/**/.git/**", "/.git/config", true),
        ("/**/.git/**", "/sub/.git/HEAD", true),
        ("/**/.git/**", "/.git/", true),
        ("/**/.git/**", "/.git", false),
        ("/**/.git/**", "/.gitignore", false),
        ("/**/wp-config.php.*", "/wp-config.php.bak", true),
        ("/**/wp-config.php.*", "/blog/wp-config.php.old", true),
        ("/**/wp-config.php.*", "/wp-config.php", false),
        ("/**/*.sql", "/dump.sql", true),
        ("/**/*.sql", "/backup/db/dump.sql", true),
        ("/**/*.sql", "/dump.sql.gz", false),
        ("/**/*.bak", "/index.php.bak", true),
        ("/**/phpinfo.php", "/phpinfo.php", true),
        ("/**/phpinfo.php", "/x/phpinfo.php", true),
        ("/**/phpinfo.php", "/myphpinfo.php", false),
        ("/server-status", "/server-status", true),
        ("/server-status", "/server-status/", false),
        ("/server-status", "/Server-Status", false),
        ("/wp-login.php", "/wp-login.php", true),
        ("/a/*", "/a/b", true),
        ("/a/*", "/a/", true),
        ("/a/*", "/a/b/c", false),
        ("/a/**", "/a/b/c", true),
        ("/a/**", "/a", false),
        ("/a/?", "/a/b", true),
        ("/a/?", "/a/", false),
        ("/a/?", "/a//", false),
        ("/a?c", "/abc", true),
        ("/a?c", "/a/c", false),
        ("/**", "/", true),
        ("/**", "/n/i/m/p/o/r/t/e", true),
        ("/*", "/", true),
        ("/*", "/a/", false),
        ("/a/**/b", "/a/b", true),
        ("/a/**/b", "/a/x/y/b", true),
        ("/a/**/b", "/a/xb", false),
        ("/a**b", "/a/x/b", true),
        ("/*.php", "/index.php", true),
        ("/*.php", "/a/index.php", false),
        ("/admin*/**", "/admin123/index.php", true),
        ("/admin*/**", "/admin/", true),
        ("/x", "", false),
    ];
    for &(pattern, path, expected) in table {
        assert_eq!(glob(pattern).matches(path), expected, "{pattern} ~ {path}");
    }
}

#[test]
fn glob_refuses_bad_patterns() {
    assert_eq!(Glob::new(""), Err(GlobError::Empty));
    assert!(matches!(Glob::new("*.env"), Err(GlobError::NotAbsolute(_))));
    assert!(matches!(Glob::new("/a b"), Err(GlobError::Control(_))));
    assert!(matches!(Glob::new("/a\n"), Err(GlobError::Control(_))));
    assert!(matches!(Glob::new("/a/***"), Err(GlobError::Stars(_))));
    let long = format!("/{}", "a".repeat(MAX_PATTERN));
    assert_eq!(Glob::new(&long), Err(GlobError::TooLong(MAX_PATTERN + 1)));
    assert!(Glob::new(&long[..MAX_PATTERN]).is_ok());
    // Les caractères comptent, pas les octets.
    assert!(Glob::new(&format!("/{}", "é".repeat(MAX_PATTERN - 1))).is_ok());
}

#[test]
fn glob_reads_only_the_bounded_start_of_a_long_path() {
    let long = format!("/{}", "a".repeat(10 * MAX_PATH));
    assert!(glob("/**").matches(&long));
    assert!(glob("/a*").matches(&long));
    let tail = format!("{long}.env");
    assert!(
        !glob("/**/*.env").matches(&tail),
        "la queue au-delà de 2 Kio est ignorée"
    );
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

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Correspondance de référence, récursive et sans borne : sert d'oracle sur
/// de petites entrées.
fn naive(pattern: &[u8], text: &[u8]) -> bool {
    if let Some(rest) = pattern.strip_prefix(b"/**/") {
        // `/`, ou `/…/`.
        return text.first() == Some(&b'/')
            && (1..=text.len()).any(|j| text[j - 1] == b'/' && naive(rest, &text[j..]));
    }
    if let Some(rest) = pattern.strip_prefix(b"**") {
        return (0..=text.len()).any(|i| naive(rest, &text[i..]));
    }
    match pattern.first() {
        None => text.is_empty(),
        Some(b'*') => (0..=text.len())
            .take_while(|&i| i == 0 || text[i - 1] != b'/')
            .any(|i| naive(&pattern[1..], &text[i..])),
        Some(b'?') => text.first().is_some_and(|&c| c != b'/') && naive(&pattern[1..], &text[1..]),
        Some(&c) => text.first() == Some(&c) && naive(&pattern[1..], &text[1..]),
    }
}

#[test]
fn glob_matches_the_naive_oracle() {
    let mut rng = XorShift(0x9105_0000_0000_0001);
    let atoms: &[&str] = &["/", "a", "b", "*", "**", "?", "/**/", "."];
    let chars: &[u8] = b"/ab.";
    for _ in 0..20_000 {
        let mut pattern = String::from("/");
        for _ in 0..rng.below(6) {
            pattern.push_str(atoms[rng.below(atoms.len())]);
        }
        let Ok(g) = Glob::new(&pattern) else {
            continue;
        };
        let len = rng.below(9);
        let path: Vec<u8> = (0..len).map(|_| *rng.pick(chars)).collect();
        let path = String::from_utf8(path).unwrap();
        assert_eq!(
            g.matches(&path),
            naive(pattern.as_bytes(), path.as_bytes()),
            "{pattern} ~ {path}"
        );
    }
}

#[test]
fn glob_fuzz_never_panics_and_stays_fast() {
    let mut rng = XorShift(0x5eed_6106_0000_0002);
    let atoms: &[&str] = &["/", "a", "b", "*", "**", "?", "/**/", ".", "é", "%2e"];
    let chars: &[&str] = &["/", "a", "b", ".", "é", "%", "\u{0}"];
    let mut slowest = Duration::ZERO;
    for round in 0..3_000 {
        let mut pattern = String::from("/");
        let atoms_len = if round % 10 == 0 { 200 } else { rng.below(20) };
        for _ in 0..atoms_len {
            pattern.push_str(atoms[rng.below(atoms.len())]);
        }
        let Ok(g) = Glob::new(&pattern) else {
            continue;
        };
        let len = if round % 10 == 0 {
            3000
        } else {
            rng.below(200)
        };
        let path: String = (0..len).map(|_| *rng.pick(chars)).collect();
        let start = Instant::now();
        let _ = g.matches(&path);
        slowest = slowest.max(start.elapsed());
    }
    // Pire cas voulu : 256 étoiles contre 2 Kio de `a`.
    let worst = glob(&format!("/{}", "*a".repeat(127)));
    let path = format!("/{}", "a".repeat(4 * MAX_PATH));
    let start = Instant::now();
    let _ = worst.matches(&path);
    slowest = slowest.max(start.elapsed());
    assert!(
        slowest < Duration::from_millis(50),
        "correspondance la plus lente : {slowest:?}"
    );
}

// --- Règles ----------------------------------------------------------------

fn entry(method: &str, path: &str, status: u16) -> Entry {
    Entry {
        method: Some(method.to_string()),
        ..Entry::new(0, path, status)
    }
}

fn compiled(id: &str) -> CompiledRule {
    let rule = defaults().into_iter().find(|r| r.id == id).expect(id);
    CompiledRule::compile(&rule).expect(id)
}

#[test]
fn the_default_rules_are_those_of_the_plan() {
    let all = rules::compile_rules(&[], &[], &[]).expect("défauts");
    let ids: Vec<_> = all.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, DEFAULT_IDS);
    let get = |id: &str| all.iter().find(|r| r.id == id).unwrap();
    for (id, scope, min_count, min_ips, severity) in [
        ("spike-404", Scope::Site, 100, 1, Severity::Warning),
        ("spike-403", Scope::Site, 100, 1, Severity::Warning),
        ("errors-5xx", Scope::Site, 10, 1, Severity::Critical),
        ("sensitive-path", Scope::Site, 1, 1, Severity::Info),
        ("sensitive-path-many", Scope::Site, 5, 5, Severity::Warning),
        ("brute-force", Scope::Ip, 30, 1, Severity::Warning),
        ("repeated-ip", Scope::Ip, 600, 1, Severity::Warning),
    ] {
        let r = get(id);
        assert_eq!(
            (r.scope, r.min_count, r.min_ips, r.window_secs, r.severity),
            (scope, min_count, min_ips, 600, severity),
            "{id}"
        );
    }
}

#[test]
fn default_rules_match_their_entries() {
    let spike = compiled("spike-404");
    assert!(spike.matches(&entry("GET", "/x", 404)));
    assert!(!spike.matches(&entry("GET", "/x", 403)));
    let errors = compiled("errors-5xx");
    for status in [500, 503, 599] {
        assert!(errors.matches(&entry("GET", "/", status)));
    }
    assert!(!errors.matches(&entry("GET", "/", 499)));
    let sensitive = compiled("sensitive-path");
    for path in [
        "/.env",
        "/shop/.git/config",
        "/backup.sql",
        "/server-status",
    ] {
        assert!(sensitive.matches(&entry("GET", path, 404)), "{path}");
    }
    assert!(!sensitive.matches(&entry("GET", "/index.php", 200)));
    // Un 404 sur `/.env` nourrit le pic et le chemin sensible.
    let env = entry("GET", "/.env", 404);
    assert!(spike.matches(&env) && sensitive.matches(&env));
    let brute = compiled("brute-force");
    assert!(brute.matches(&entry("POST", "/wp-login.php", 200)));
    assert!(brute.matches(&entry("POST", "/connexion", 302)));
    assert!(!brute.matches(&entry("GET", "/wp-login.php", 200)));
    assert!(
        !brute.matches(&Entry::new(0, "/wp-login.php", 200)),
        "sans méthode"
    );
    assert!(!brute.matches(&entry("POST", "/wp-login.php.bak", 200)));
    let repeated = compiled("repeated-ip");
    assert!(repeated.matches(&Entry::new(0, "", 101)));
}

fn rule(id: &str) -> Rule {
    Rule {
        id: id.into(),
        path: Default::default(),
        methods: Vec::new(),
        statuses: Default::default(),
        scope: Scope::Site,
        min_count: 10,
        min_ips: 1,
        window_secs: 600,
        severity: Severity::Warning,
    }
}

#[test]
fn invalid_rules_are_refused() {
    let bad: Vec<Rule> = vec![
        rule(""),
        rule("Majuscule"),
        rule("a b"),
        rule(&"x".repeat(65)),
        Rule {
            window_secs: 59,
            ..rule("r")
        },
        Rule {
            window_secs: 3601,
            ..rule("r")
        },
        Rule {
            min_count: 0,
            ..rule("r")
        },
        Rule {
            min_count: rules::MAX_COUNT + 1,
            ..rule("r")
        },
        Rule {
            min_ips: 0,
            ..rule("r")
        },
        Rule {
            min_ips: 11,
            ..rule("r")
        },
        Rule {
            scope: Scope::Ip,
            min_ips: 2,
            ..rule("r")
        },
        Rule {
            path: vec!["relatif".to_string()].into(),
            ..rule("r")
        },
        Rule {
            methods: vec!["get".into()],
            ..rule("r")
        },
        Rule {
            statuses: vec![rules::StatusSpec::Code(99)].into(),
            ..rule("r")
        },
        Rule {
            statuses: vec![rules::StatusSpec::Range("599-500".into())].into(),
            ..rule("r")
        },
        Rule {
            statuses: vec![rules::StatusSpec::Range("5xx".into())].into(),
            ..rule("r")
        },
    ];
    for r in bad {
        assert!(CompiledRule::compile(&r).is_err(), "{r:?}");
    }
    // Doublons, et `disable` d'une règle inconnue.
    assert!(rules::compile_rules(&[], &[rule("spike-404")], &[]).is_err());
    assert!(rules::compile_rules(&[], &[rule("a")], &[rule("a")]).is_err());
    assert!(rules::compile_rules(&["inconnue".into()], &[], &[]).is_err());
    let many: Vec<_> = (0..=rules::MAX_RULES)
        .map(|i| rule(&format!("r{i}")))
        .collect();
    assert!(rules::compile_rules(&[], &many, &[]).is_err());
}

#[test]
fn disable_removes_a_default_rule_which_may_then_be_redefined() {
    let set = rules::compile_rules(&["repeated-ip".into()], &[], &[]).unwrap();
    assert!(set.iter().all(|r| r.id != "repeated-ip"));
    assert_eq!(set.len(), DEFAULT_IDS.len() - 1);
    let replaced = Rule {
        scope: Scope::Ip,
        min_count: 1200,
        ..rule("repeated-ip")
    };
    let set = rules::compile_rules(&["repeated-ip".into()], &[replaced], &[]).unwrap();
    let r = set.last().unwrap();
    assert_eq!((r.id.as_str(), r.min_count), ("repeated-ip", 1200));
}

// --- Configuration ---------------------------------------------------------

const BASE: &str = r#"
database = "/home/veilleur/vigie/vigie.db"

[alerts]
to = "alertes@example.org"
from = "vigie@example.org"
smtp_host = "smtp.example.org"
password_file = "/home/veilleur/vigie/smtp-password"
"#;

const SITE: &str = r#"
[[sites]]
id = "site-a"
url = "https://site-a.example.org/"
"#;

fn parse(raw: &str) -> Result<Config, ConfigError> {
    config::parse(Path::new("config.toml"), raw)
}

#[test]
fn config_reads_logs_and_site_logs() {
    let raw = format!(
        r#"{BASE}
[logs]
disable = ["spike-403"]

[[logs.rules]]
id = "admin-404"
path = "/admin*/**"
statuses = [404, "500-599"]
scope = "site"
min_count = 20
severity = "info"
{SITE}
[sites.logs]
behind_proxy = true
exclude = ["/admin123/**"]

[[sites.logs.rules]]
id = "checkout-errors"
path = ["/commande", "/panier"]
methods = ["POST"]
statuses = "500-599"
scope = "site"
min_count = 3
min_ips = 2
window_secs = 300
severity = "critical"
"#
    );
    let config = parse(&raw).expect("valide");
    assert_eq!(config.logs.disable, ["spike-403"]);
    assert_eq!(config.logs.rules[0].severity, Severity::Info);
    assert_eq!(config.logs.rules[0].window_secs, rules::DEFAULT_WINDOW);
    let site = &config.sites[0];
    let set = rules::for_site(&config, site).expect("règles");
    assert!(set.behind_proxy);
    assert!(set.excluded("/admin123/index.php"));
    assert!(!set.excluded("/index.php"));
    let ids: Vec<_> = set.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "spike-404",
            "errors-5xx",
            "sensitive-path",
            "sensitive-path-many",
            "brute-force",
            "repeated-ip",
            "admin-404",
            "checkout-errors"
        ]
    );
    let active: Vec<_> = set.active().map(|r| r.id.as_str()).collect();
    assert!(!active.contains(&"brute-force") && !active.contains(&"repeated-ip"));
    let checkout = set.rules.last().unwrap();
    assert!(checkout.matches(&entry("POST", "/panier", 502)));
    assert!(!checkout.matches(&entry("GET", "/panier", 502)));

    // Sans section, les défauts.
    let plain = parse(&format!("{BASE}{SITE}")).expect("valide");
    assert!(plain.sites[0].logs.is_none());
    let set = rules::for_site(&plain, &plain.sites[0]).unwrap();
    assert_eq!(set.rules.len(), DEFAULT_IDS.len());
    assert!(!set.behind_proxy && set.exclude.is_empty());
}

#[test]
fn an_invalid_rule_is_a_configuration_error() {
    let rule =
        |body: &str| format!("{BASE}\n[[logs.rules]]\nid = \"r\"\nscope = \"site\"\n{body}\n");
    for body in [
        "min_count = 10\nwindow_secs = 30",
        "min_count = 10\npath = \"relatif\"",
        "min_count = 0",
        "min_count = 10\nseverity = \"grave\"",
        "min_count = 10\nstatuses = \"5xx\"",
        "min_count = 10\ninconnu = 1",
        "min_count = -1",
        "scope_typo = 1\nmin_count = 1",
    ] {
        let err = parse(&rule(body)).expect_err(body);
        assert!(
            matches!(err, ConfigError::Invalid { .. } | ConfigError::Parse { .. }),
            "{body} : {err}"
        );
    }
    let err = parse(&format!("{BASE}[logs]\ndisable = [\"spike-500\"]\n")).unwrap_err();
    assert!(err.to_string().contains("spike-500"), "{err}");
    let err = parse(&format!(
        "{BASE}{SITE}[sites.logs]\nexclude = [\"admin\"]\n"
    ))
    .unwrap_err();
    assert!(err.to_string().contains("site-a"), "{err}");
    let err = parse(&format!(
        "{BASE}{SITE}[[sites.logs.rules]]\nid = \"spike-404\"\nscope = \"site\"\nmin_count = 1\n"
    ))
    .unwrap_err();
    assert!(err.to_string().contains("deux fois"), "{err}");
    assert!(parse(&format!("{BASE}{SITE}[sites.logs]\nsource = \"x\"\n")).is_err());
}

#[test]
fn rule_loading_fuzz_never_panics() {
    let mut rng = XorShift(0x5eed_4e1e_0000_0003);
    let ids: &[&str] = &["\"r\"", "\"spike-404\"", "\"R\"", "\"\"", "\"a-1\"", "1"];
    let paths: &[&str] = &[
        "\"/**/.env\"",
        "[\"/a\", \"/b/*\"]",
        "\"a\"",
        "\"/***\"",
        "[]",
        "\"/é?\"",
        "42",
    ];
    let methods: &[&str] = &["[\"POST\"]", "[\"get\"]", "[]", "\"POST\"", "[\"\"]"];
    let statuses: &[&str] = &[
        "404",
        "[404, \"500-599\"]",
        "\"500-599\"",
        "\"599-500\"",
        "[99]",
        "70000",
        "\"abc\"",
        "[]",
    ];
    let scopes: &[&str] = &["\"ip\"", "\"site\"", "\"monde\""];
    let numbers: &[&str] = &[
        "0",
        "1",
        "5",
        "60",
        "600",
        "3600",
        "3601",
        "-1",
        "99999999999",
    ];
    let severities: &[&str] = &["\"info\"", "\"warning\"", "\"critical\"", "\"grave\""];
    let mut accepted = 0;
    for _ in 0..3_000 {
        let mut body = String::new();
        let mut field = |name: &str, values: &[&str], rng: &mut XorShift| {
            if rng.below(4) != 0 {
                body.push_str(&format!("{name} = {}\n", rng.pick(values)));
            }
        };
        field("id", ids, &mut rng);
        field("path", paths, &mut rng);
        field("methods", methods, &mut rng);
        field("statuses", statuses, &mut rng);
        field("scope", scopes, &mut rng);
        field("min_count", numbers, &mut rng);
        field("min_ips", numbers, &mut rng);
        field("window_secs", numbers, &mut rng);
        field("severity", severities, &mut rng);
        let disable = if rng.below(3) == 0 {
            "[logs]\ndisable = [\"repeated-ip\", \"spike-404\"]\n"
        } else {
            ""
        };
        let raw = format!("{BASE}{disable}\n[[logs.rules]]\n{body}");
        if let Ok(config) = parse(&raw) {
            accepted += 1;
            let rule = &config.logs.rules[0];
            assert!(config::is_valid_id(&rule.id));
            assert!((rules::MIN_WINDOW..=rules::MAX_WINDOW).contains(&rule.window_secs));
            assert!(rule.min_count >= 1 && rule.min_ips >= 1);
            assert!(rule.min_ips <= rule.min_count);
            assert!(rules::compile_rules(&config.logs.disable, &config.logs.rules, &[]).is_ok());
        }
    }
    assert!(
        accepted > 0,
        "le fuzz doit aussi produire des règles valides"
    );
}
