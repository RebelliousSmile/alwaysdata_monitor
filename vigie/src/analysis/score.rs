//! Score de suspicion d'une IP, porté d'`IpSuspicionScorer.php` : mêmes
//! poids, mêmes seuils (élevé ≥ 70, moyen ≥ 40), mêmes raisons.
//!
//! Aucun signal n'est fiable seul : l'IP d'un opérateur mobile (CGNAT) porte
//! des centaines de vrais clients et beaucoup d'UA, quand un scraper derrière
//! un proxy résidentiel ressemble à une connexion domestique. Le score
//! additionne donc des signaux pondérés et retire des points pour un réseau
//! grand public, où bloquer une IP toucherait le plus d'innocents.
//!
//! V1 sans reverse DNS : l'appelant passe `rdns = None` (réseau « inconnu »,
//! +5 comme en PHP) ; le paramètre est gardé pour porter les cas du module
//! tels quels. Seuls les quatre moteurs du PHP ont le bénéfice du doute ;
//! les autres robots déclarés prennent +20.
//!
//! Le score se calcule sur les seuls compteurs observés d'une IP
//! (`profile.rs`), jamais sur la borne d'erreur de Space-Saving.

use std::fmt;

/// Score à partir duquel le niveau est « élevé ».
pub const LEVEL_HIGH: u8 = 70;
/// Score à partir duquel le niveau est « moyen ».
pub const LEVEL_MEDIUM: u8 = 40;
/// Points d'une signature d'UA notée sur un autre site (phase 3), ajoutés
/// hors du score propre.
pub const SHARED_SIGNATURE_POINTS: i32 = 15;

/// Noms d'hébergeurs, cherchés avant ceux des FAI : ils sont précis, ceux
/// des FAI en partie génériques.
const HOSTING_PATTERNS: &[&str] = &[
    "amazonaws",
    "compute.amazon",
    "googleusercontent",
    "cloudapp",
    "azure",
    "ovh",
    "kimsufi",
    "hetzner",
    "your-server.de",
    "digitalocean",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "contabo",
    "scaleway",
    "online.net",
    "poneytelecom",
    "alibaba",
    "aliyun",
    "tencent",
    "huaweicloud",
    "oraclecloud",
    "leaseweb",
    "hostinger",
    "ionos",
    "m247",
    "datacamp",
    "colocrossing",
    "psychz",
    "hosting",
    "vps",
    "server",
    "dedicated",
    "cloud",
];

const ISP_PATTERNS: &[&str] = &[
    "orange",
    "wanadoo",
    "free.fr",
    "proxad",
    "sfr",
    "neufbox",
    "numericable",
    "bbox",
    "bouyguestelecom",
    "bytel",
    "skynet",
    "proximus",
    "swisscom",
    "telenet",
    "vodafone",
    "telekom",
    "t-ipconnect",
    "btcentralplus",
    "virginm",
    "comcast",
    "verizon",
    "dsl",
    "dyn",
    "cable",
    "fibre",
    "fiber",
    "mobile",
    "pool",
    "ftth",
];

/// Moteur → domaines vers lesquels ses vrais robots se résolvent.
const SEARCH_ENGINES: &[(&str, &[&str])] = &[
    ("googlebot", &["googlebot.com", "google.com"]),
    ("bingbot", &["search.msn.com"]),
    ("applebot", &["applebot.apple.com"]),
    ("duckduckbot", &["duckduckgo.com"]),
];

/// `NON_BROWSER_UA` du PHP : UA vide, ou l'un de ces fragments, sans casse.
const NON_BROWSER_UA: &[&str] = &[
    "curl",
    "wget",
    "python",
    "go-http",
    "java/",
    "libwww",
    "scrapy",
    "httpclient",
    "axios",
    "node-fetch",
    "okhttp",
    "guzzle",
    "headless",
];

/// Comportement observé d'une IP sur la fenêtre (24 h glissantes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub requests: u64,
    /// Ressources statiques (CSS, JS, images…).
    pub statics: u64,
    /// Requêtes à facettes (`?q=`).
    pub facets: u64,
    /// Requêtes refusées (403) : jamais notées, comme en PHP.
    pub refused: u64,
    /// Pages (non statiques) demandées sans referer.
    pub empty_referer_pages: u64,
    /// UA distincts, dans l'ordre où ils ont été vus.
    pub uas: Vec<String>,
    /// Pic de requêtes en une minute (approché : `profile.rs`).
    pub peak_minute: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Moteur de recherche du bénéfice du doute : ne pas bloquer.
    Engine,
    Low,
    Medium,
    High,
}

impl Level {
    /// Valeurs du PHP.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Engine => "moteur",
            Self::Low => "faible",
            Self::Medium => "moyen",
            Self::High => "eleve",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Engine => "moteur de recherche",
            Self::Low => "faible",
            Self::Medium => "moyen",
            Self::High => "élevé",
        }
    }

    fn of(score: u8) -> Self {
        if score >= LEVEL_HIGH {
            Self::High
        } else if score >= LEVEL_MEDIUM {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Réseau d'après le reverse DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Hosting,
    Isp,
    Unknown,
}

impl Network {
    /// Valeurs du PHP.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hosting => "hebergeur",
            Self::Isp => "fai",
            Self::Unknown => "inconnu",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub points: i32,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// 0 à 100, signature partagée comprise.
    pub score: u8,
    /// Score propre au site, sans signature partagée : seul lui peut noter
    /// une signature (phase 3), pour qu'un bonus ne s'entretienne pas.
    pub own_score: u8,
    pub level: Level,
    pub network: Network,
    /// Du plus lourd au plus léger ; l'ordre d'ajout départage.
    pub reasons: Vec<Reason>,
}

impl Verdict {
    /// Ajoute les points d'une signature d'UA notée sur un autre site, hors
    /// du score propre. Sans effet sur un moteur du bénéfice du doute.
    pub fn with_shared_signature(mut self) -> Self {
        if self.level == Level::Engine {
            return self;
        }
        self.reasons.push(Reason {
            points: SHARED_SIGNATURE_POINTS,
            label: "user-agent de robot noté suspect sur un autre site".to_string(),
        });
        self.score = clamp(self.reasons.iter().map(|r| r.points).sum());
        self.level = Level::of(self.score);
        self.reasons.sort_by(|a, b| b.points.cmp(&a.points));
        self
    }
}

fn clamp(points: i32) -> u8 {
    u8::try_from(points.clamp(0, 100)).unwrap_or(100)
}

/// `hebergeur`, `fai` ou `inconnu`, comme `IpSuspicionScorer::network`.
pub fn network(rdns: Option<&str>) -> Network {
    let Some(rdns) = rdns else {
        return Network::Unknown;
    };
    let host = rdns.to_lowercase();
    if HOSTING_PATTERNS.iter().any(|p| host.contains(p)) {
        Network::Hosting
    } else if ISP_PATTERNS.iter().any(|p| host.contains(p)) {
        Network::Isp
    } else {
        Network::Unknown
    }
}

fn host_ends_with(host: &str, domains: &[&str]) -> bool {
    let host = host.trim_end_matches('.').to_lowercase();
    domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fn is_non_browser(ua: &str) -> bool {
    let lower = ua.to_lowercase();
    lower.is_empty() || NON_BROWSER_UA.iter().any(|p| lower.contains(p))
}

/// `mb_strimwidth($ua, 0, 40, '…')` : 40 caractères au plus, marque
/// comprise.
fn strimwidth(text: &str) -> String {
    if text.chars().count() <= 40 {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(39).collect();
    cut.push('…');
    cut
}

/// `round()` de PHP sur une part, en pour cent.
fn percent(share: f64) -> i64 {
    // Une part est dans [0, 1] : la conversion ne déborde pas.
    (share * 100.0).round() as i64
}

/// Score d'une IP : `rdns` est son reverse DNS (`None` : non résolu),
/// `bot` le nom du robot déclaré reconnu dans son UA.
pub fn score(stats: &Stats, rdns: Option<&str>, bot: Option<&str>) -> Verdict {
    let requests = stats.requests.max(1) as f64;
    let pages = stats.requests.saturating_sub(stats.statics);
    let network = network(rdns);
    let mut reasons: Vec<Reason> = Vec::new();
    let mut add = |points: i32, label: String| reasons.push(Reason { points, label });

    let engine = bot.and_then(|b| {
        let lower = b.to_lowercase();
        SEARCH_ENGINES
            .iter()
            .find(|(name, _)| *name == lower)
            .map(|(_, domains)| *domains)
    });
    match (bot, engine) {
        (Some(bot), Some(domains)) => match rdns {
            Some(rdns) if !host_ends_with(rdns, domains) => add(
                60,
                format!("se présente comme {bot} mais le reverse DNS ({rdns}) n'est pas le sien"),
            ),
            // Non résolu : bénéfice du doute, bloquer un vrai moteur coûte
            // du référencement.
            _ => {
                return Verdict {
                    score: 0,
                    own_score: 0,
                    level: Level::Engine,
                    network,
                    reasons: vec![Reason {
                        points: 0,
                        label: format!(
                            "moteur de recherche {bot}{} : ne pas bloquer",
                            if rdns.is_some() { " (vérifié)" } else { "" }
                        ),
                    }],
                };
            }
        },
        (Some(bot), None) => add(20, format!("bot déclaré ({bot}) : aucun visiteur derrière")),
        (None, _) => {}
    }

    let facet_share = stats.facets as f64 / requests;
    if facet_share >= 0.8 {
        add(
            25,
            format!(
                "{} % de ses requêtes sont des facettes ?q=",
                percent(facet_share)
            ),
        );
    } else if facet_share >= 0.4 {
        add(
            15,
            format!(
                "{} % de ses requêtes sont des facettes ?q=",
                percent(facet_share)
            ),
        );
    }

    // Un navigateur charge CSS, JS et images ; un scraper, le HTML seul.
    if pages >= 20 && stats.statics == 0 {
        add(
            20,
            "aucune ressource statique chargée (CSS, JS, images)".to_string(),
        );
    }

    // Les 403 ne sont pas notés : ils mesurent nos propres règles, pas le
    // comportement de l'IP (une IP bloquée hier se noterait elle-même).

    if pages >= 20 && stats.empty_referer_pages as f64 / pages as f64 >= 0.9 {
        add(10, "pages demandées sans referer".to_string());
    }

    if let Some(ua) = stats.uas.iter().find(|ua| is_non_browser(ua)) {
        add(
            20,
            format!(
                "user-agent d'outil, pas de navigateur ({})",
                if ua.is_empty() {
                    "vide".to_string()
                } else {
                    strimwidth(ua)
                }
            ),
        );
    }

    let ua_count = stats.uas.len();
    if ua_count >= 5 && network != Network::Isp {
        add(
            15,
            format!("{ua_count} user-agents différents hors réseau grand public (rotation)"),
        );
    }

    if stats.peak_minute >= 60 {
        add(
            15,
            format!("pic de {} requêtes en une minute", stats.peak_minute),
        );
    } else if stats.peak_minute >= 20 {
        add(
            5,
            format!("pic de {} requêtes en une minute", stats.peak_minute),
        );
    }

    match (network, rdns) {
        (Network::Hosting, Some(rdns)) => {
            add(25, format!("IP d'hébergeur ({rdns}) : pas un internaute"))
        }
        (Network::Isp, Some(rdns)) => add(
            -25,
            format!("FAI grand public ({rdns}) : IP possiblement partagée par de vrais clients"),
        ),
        (_, None) => add(5, "aucun reverse DNS".to_string()),
        _ => {}
    }

    let score = clamp(reasons.iter().map(|r| r.points).sum());
    // Tri stable, comme `usort` en PHP 8.
    reasons.sort_by(|a, b| b.points.cmp(&a.points));
    Verdict {
        score,
        own_score: score,
        level: Level::of(score),
        network,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    //! Cas de `tests/Service/IpSuspicionScorerTest.php`, portés tels quels.

    use super::*;

    fn stats() -> Stats {
        Stats {
            requests: 100,
            statics: 60,
            facets: 0,
            refused: 0,
            empty_referer_pages: 0,
            uas: vec!["Mozilla/5.0 Firefox".to_string()],
            peak_minute: 5,
        }
    }

    fn points(verdict: &Verdict) -> Vec<i32> {
        verdict.reasons.iter().map(|r| r.points).collect()
    }

    #[test]
    fn hosted_facet_scraper_scores_high() {
        let r = score(
            &Stats {
                statics: 0,
                facets: 95,
                refused: 90,
                empty_referer_pages: 100,
                peak_minute: 80,
                ..stats()
            },
            Some("ec2-192-0-2-1.compute.amazonaws.com"),
            None,
        );
        assert_eq!(r.score, 95);
        assert_eq!(r.level, Level::High);
        assert_eq!(r.level.as_str(), "eleve");
        assert_eq!(r.network, Network::Hosting);
        assert_eq!(r.network.as_str(), "hebergeur");
    }

    #[test]
    fn refused_requests_do_not_change_the_score() {
        let open = score(
            &Stats {
                facets: 90,
                ..stats()
            },
            None,
            None,
        );
        let refused = score(
            &Stats {
                facets: 90,
                refused: 100,
                ..stats()
            },
            None,
            None,
        );
        assert_eq!(open.score, refused.score);
    }

    #[test]
    fn browser_on_consumer_isp_scores_zero() {
        let r = score(&stats(), Some("lfbn-idf1-1-2-3.w90-1.abo.wanadoo.fr"), None);
        assert_eq!(r.score, 0);
        assert_eq!(r.level, Level::Low);
        assert_eq!(r.level.as_str(), "faible");
        assert_eq!(r.network, Network::Isp);
    }

    #[test]
    fn consumer_isp_lowers_score_of_shared_ip() {
        let scraping = Stats {
            statics: 0,
            facets: 50,
            empty_referer_pages: 100,
            ..stats()
        };
        let on_isp = score(&scraping, Some("bouyguestelecom.fr"), None);
        let unknown = score(&scraping, Some("host.example"), None);
        assert_eq!(i32::from(unknown.score) - 25, i32::from(on_isp.score));
    }

    #[test]
    fn ua_rotation_ignored_on_consumer_network() {
        let uas = Stats {
            uas: ["a", "b", "c", "d", "e"].map(String::from).to_vec(),
            ..stats()
        };
        let isp = score(&uas, Some("x.proxad.net"), None);
        let hosted = score(&uas, Some("x.hetzner.com"), None);
        assert!(!points(&isp).contains(&15));
        assert!(points(&hosted).contains(&15));
    }

    #[test]
    fn genuine_search_engine_is_never_suspicious() {
        let r = score(
            &Stats {
                statics: 0,
                peak_minute: 200,
                ..stats()
            },
            Some("crawl-192-0-2-1.googlebot.com"),
            Some("Googlebot"),
        );
        assert_eq!(r.score, 0);
        assert_eq!(r.level, Level::Engine);
        assert_eq!(r.level.as_str(), "moteur");
        assert_eq!(
            r.reasons[0].label,
            "moteur de recherche Googlebot (vérifié) : ne pas bloquer"
        );
        // Sans reverse DNS (V1) : bénéfice du doute.
        let unresolved = score(&stats(), None, Some("bingbot"));
        assert_eq!(unresolved.level, Level::Engine);
    }

    #[test]
    fn fake_googlebot_is_flagged() {
        let r = score(&stats(), Some("vps.contabo.net"), Some("Googlebot"));
        assert!(r.score >= LEVEL_HIGH);
        assert!(r.reasons[0].label.contains("Googlebot"), "{:?}", r.reasons);
    }

    #[test]
    fn tool_user_agent_adds_points() {
        let r = score(
            &Stats {
                uas: vec!["curl/8.4.0".to_string()],
                ..stats()
            },
            None,
            None,
        );
        assert_eq!(r.score, 25);
    }

    // --- Au-delà du PHP --------------------------------------------------

    #[test]
    fn other_declared_bots_take_twenty_points() {
        let r = score(&stats(), None, Some("YandexBot"));
        assert_eq!(r.score, 25);
        assert_eq!(
            r.reasons[0].label,
            "bot déclaré (YandexBot) : aucun visiteur derrière"
        );
    }

    #[test]
    fn labels_follow_the_php_wording() {
        let r = score(
            &Stats {
                facets: 45,
                uas: vec![String::new(), "x".repeat(60)],
                peak_minute: 25,
                ..stats()
            },
            None,
            None,
        );
        let labels: Vec<_> = r.reasons.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "user-agent d'outil, pas de navigateur (vide)",
                "45 % de ses requêtes sont des facettes ?q=",
                "pic de 25 requêtes en une minute",
                "aucun reverse DNS",
            ]
        );
        assert_eq!(r.score, 45);
        assert_eq!(r.level, Level::Medium);
        let long = score(
            &Stats {
                uas: vec![format!("python-requests/{}", "9".repeat(40))],
                ..stats()
            },
            None,
            None,
        );
        let label = &long.reasons[0].label;
        assert!(label.ends_with("9…)"), "{label}");
        assert_eq!(
            label
                .trim_start_matches("user-agent d'outil, pas de navigateur (")
                .trim_end_matches(')')
                .chars()
                .count(),
            40
        );
    }

    #[test]
    fn a_shared_signature_adds_fifteen_points_outside_the_own_score() {
        let own = score(&stats(), None, Some("SemrushBot"));
        assert_eq!(own.score, 25);
        let shared = own.clone().with_shared_signature();
        assert_eq!(shared.score, 40);
        assert_eq!(shared.own_score, 25);
        assert_eq!(shared.level, Level::Medium);
        assert_eq!(shared.reasons[0].points, 20);
        // Un moteur du bénéfice du doute n'en prend pas.
        let engine = score(&stats(), None, Some("Googlebot")).with_shared_signature();
        assert_eq!(engine.score, 0);
    }
}
