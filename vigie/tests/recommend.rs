//! Analyse → propositions (#13) : gradation et protections, sur des
//! analyses construites à la main, et bloc cumulatif.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use jiff::tz::TimeZone;

use vigie::analysis::catalog::{self, BotClass};
use vigie::analysis::findings::{Analysis, BotSeen, IpVerdict};
use vigie::analysis::fold::is_vigie_traffic;
use vigie::analysis::score::Level;
use vigie::logs::Entry;
use vigie::recommend::htaccess::{self, Group, Target};
use vigie::recommend::{self, Inputs, Proposal};

const NOW: i64 = 1_781_517_600;

fn tz() -> TimeZone {
    TimeZone::get("Europe/Paris").unwrap()
}

fn seen(name: &str) -> BotSeen {
    let bot = catalog::find(name).expect(name);
    BotSeen {
        name: bot.name.into(),
        publisher: bot.publisher.into(),
        purpose: bot.purpose.into(),
        robots_only: bot.robots_only,
        honours_robots: bot.honours_robots,
        class: bot.class,
        protected: bot.protected(),
        requests: 500,
    }
}

fn verdict(ip: &str, own_score: u8, class: BotClass, bot: Option<&str>) -> IpVerdict {
    IpVerdict {
        ip: ip.parse().unwrap(),
        score: own_score,
        own_score,
        level: Level::of(own_score),
        class,
        bot: bot.map(str::to_owned),
        requests: 5000,
        shared: false,
        reasons: Vec::new(),
    }
}

fn analysis(bots: &[&str], verdicts: Vec<IpVerdict>) -> Analysis {
    Analysis {
        site: "site-a".into(),
        generated_at: NOW,
        reference_ms: NOW * 1000,
        bots: bots.iter().map(|b| seen(b)).collect(),
        verdicts,
        scored: 0,
        unscored: 0,
        rules: Vec::new(),
        load: Vec::new(),
        load_threshold_us: 0,
    }
}

/// Reverse DNS de test : `hosting` → hébergeur, `isp` → FAI.
fn names(ip: &IpAddr) -> Option<String> {
    let text = ip.to_string();
    if text.ends_with(".7") || text.ends_with("::7") {
        Some("vps-7.hosting.example.net".into())
    } else if text.ends_with(".8") {
        Some("abo-8.dsl.example.net".into())
    } else {
        None
    }
}

fn run(
    analysis: &Analysis,
    tz: Option<&TimeZone>,
    behind_proxy: bool,
    protected: &[&str],
) -> Vec<Proposal> {
    let protected: BTreeSet<IpAddr> = protected.iter().map(|p| p.parse().unwrap()).collect();
    let inputs = Inputs {
        analysis,
        tz,
        behind_proxy,
        protected_ips: &protected,
    };
    let mut asked = Vec::new();
    let proposals = recommend::recommend(&inputs, &mut |ips: &[IpAddr]| {
        asked.extend_from_slice(ips);
        ips.iter()
            .map(|ip| (*ip, names(ip)))
            .collect::<HashMap<_, _>>()
    });
    assert!(asked.len() <= recommend::rdns::MAX_IPS);
    proposals
}

#[test]
fn engines_previews_browsers_and_assistants_get_nothing() {
    let tz = tz();
    let a = analysis(
        &[
            "Googlebot",
            "YandexBot",
            "facebookexternalhit",
            "ChatGPT-User",
        ],
        vec![
            verdict("203.0.113.7", 90, BotClass::Browser, None),
            verdict(
                "203.0.113.17",
                95,
                BotClass::SearchEngine,
                Some("Googlebot"),
            ),
            verdict("2001:db8::7", 90, BotClass::AiUser, Some("ChatGPT-User")),
        ],
    );
    assert_eq!(run(&a, Some(&tz), false, &[]), Vec::new());
}

#[test]
fn gradation_robots_then_user_agent_then_ip() {
    let tz = tz();
    let a = analysis(
        &["GPTBot", "Bytespider", "Google-Extended", "archive.org_bot"],
        vec![
            verdict("192.0.2.7", 85, BotClass::Tool, None),
            // Score élevé mais reverse DNS de FAI ou absent : rien.
            verdict("192.0.2.8", 85, BotClass::Tool, None),
            verdict("192.0.2.9", 85, BotClass::Tool, None),
            // Score moyen : rien.
            verdict("198.51.100.7", 60, BotClass::Tool, None),
        ],
    );
    let proposals = run(&a, Some(&tz), false, &[]);
    assert_eq!(
        proposals,
        [
            Proposal::Robots {
                bot: "Google-Extended".into(),
                publisher: "Google".into()
            },
            Proposal::Robots {
                bot: "GPTBot".into(),
                publisher: "OpenAI".into()
            },
            // archive.org_bot : Unknown, ne respecte pas robots.txt, pas de
            // règle d'UA.
            Proposal::UserAgent {
                bot: "Bytespider".into(),
                literal: "Bytespider".into()
            },
            Proposal::Ip {
                ip: "192.0.2.7".parse().unwrap(),
                rdns: "vps-7.hosting.example.net".into(),
                own_score: 85
            },
        ]
    );
    assert_eq!(
        recommend::robots_txt(&proposals),
        "User-agent: Google-Extended\nDisallow: /\n\nUser-agent: GPTBot\nDisallow: /\n"
    );
}

#[test]
fn without_time_zone_only_robots_txt() {
    let a = analysis(
        &["GPTBot", "Bytespider"],
        vec![verdict("192.0.2.7", 85, BotClass::Tool, None)],
    );
    let proposals = run(&a, None, false, &[]);
    assert_eq!(proposals.len(), 1);
    assert!(matches!(proposals[0], Proposal::Robots { .. }));
}

#[test]
fn protected_ips_and_proxied_sites_get_no_ip_rule() {
    let tz = tz();
    let a = analysis(&[], vec![verdict("192.0.2.7", 85, BotClass::Tool, None)]);
    // IP du veilleur, adresse source des retraits ou protect_ips.
    assert_eq!(run(&a, Some(&tz), false, &["192.0.2.7"]), Vec::new());
    assert_eq!(run(&a, Some(&tz), true, &[]), Vec::new());
    assert_eq!(run(&a, Some(&tz), false, &[]).len(), 1);
}

#[test]
fn the_watcher_traffic_and_webhooks_are_never_targeted() {
    // Le trafic du veilleur et du bac à sable est retiré de l'analyse.
    let mut entry = Entry::new(NOW * 1000, "/", 200);
    entry.user_agent = "vigie/0.3.0".into();
    assert!(is_vigie_traffic(&entry));
    entry.user_agent = "vigie-agent-php/0.4.0".into();
    assert!(is_vigie_traffic(&entry));
    let mut sandbox = Entry::new(NOW * 1000, "/vigie-essai-0a1b-a/temoin.txt", 200);
    sandbox.user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1)".into();
    assert!(is_vigie_traffic(&sandbox));
    let mut visitor = Entry::new(NOW * 1000, "/vigie", 200);
    visitor.user_agent = "Mozilla/5.0".into();
    assert!(!is_vigie_traffic(&visitor));
    // Aucun jeton générique ni UA de webhook ne devient un littéral.
    for ua in [
        "curl",
        "python-requests",
        "Java",
        "Go-http-client",
        "Wget",
        "Stripe",
        "WordPress",
        "vigie",
    ] {
        assert!(!recommend::ua_rule_allowed(ua), "{ua}");
        assert!(htaccess::touches_protected(ua), "{ua}");
    }
    // Un robot Unknown n'a pas de règle d'UA ; Nutch (Tool) non plus.
    for name in ["archive.org_bot", "TikTokSpider", "AionBot", "Nutch"] {
        assert!(!recommend::ua_rule_allowed(name), "{name}");
    }
    assert!(recommend::ua_rule_allowed("Bytespider"));
    // Le veilleur à score élevé, mais protégé : rien.
    let tz = tz();
    let a = analysis(&[], vec![verdict("192.0.2.7", 95, BotClass::Tool, None)]);
    assert_eq!(run(&a, Some(&tz), false, &["192.0.2.7"]), Vec::new());
}

#[test]
fn at_most_ten_ips_are_resolved() {
    let tz = tz();
    let verdicts = (1..=15)
        .map(|i| verdict(&format!("192.0.2.{}", 100 + i), 90, BotClass::Tool, None))
        .collect();
    let a = analysis(&[], verdicts);
    run(&a, Some(&tz), false, &[]);
}

#[test]
fn the_cumulative_block_keeps_valid_groups_and_drops_expired_ones() {
    let tz = tz();
    let old = vec![
        Group::new(
            Target::UserAgents(vec!["Bytespider".into()]),
            NOW + 5 * 86_400,
            &tz,
        )
        .unwrap(),
        Group::new(Target::Ip("192.0.2.9".parse().unwrap()), NOW - 60, &tz).unwrap(),
        // Expire dans moins d'une heure : retiré aussi.
        Group::new(Target::Ip("192.0.2.10".parse().unwrap()), NOW + 600, &tz).unwrap(),
    ];
    let proposals = [
        Proposal::UserAgent {
            bot: "Bytespider".into(),
            literal: "Bytespider".into(),
        },
        Proposal::UserAgent {
            bot: "SEOkicks".into(),
            literal: "SEOkicks".into(),
        },
        Proposal::Ip {
            ip: "192.0.2.7".parse().unwrap(),
            rdns: "h".into(),
            own_score: 80,
        },
    ];
    let plan = recommend::plan(&old, &proposals, NOW, &tz).unwrap();
    assert_eq!(plan.kept, old[..1]);
    assert_eq!(plan.expired, old[1..]);
    assert_eq!(plan.added.len(), 2);
    assert_eq!(
        plan.added[0].target,
        Target::UserAgents(vec!["SEOkicks".into()])
    );
    assert!(plan.changes());
    htaccess::validate(plan.block().as_bytes(), NOW, &tz).unwrap();
    // Rien de neuf et rien d'expiré : aucun changement.
    let same = recommend::plan(&plan.groups, &proposals, NOW, &tz).unwrap();
    assert!(!same.changes());
    assert_eq!(same.block(), plan.block());
}
