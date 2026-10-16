//! Catalogue des robots et classement d'un user-agent.
//!
//! Porté du module PrestaShop : métadonnées d'`AiBotCatalog.php` (éditeur,
//! finalité, `robots_only`, `honours_robots`), liste de
//! `CrawlerAnalyserService.php` complétée par celle de
//! `LoadDiagnosticService.php`, et les quatre moteurs du bénéfice du doute
//! d'`IpSuspicionScorer.php`. Comme `buildBotMatcher`, la correspondance est
//! insensible à la casse et retient le nom **le plus long** : un UA
//! « Applebot-Extended » n'est jamais lu « Applebot ».
//!
//! Le catalogue est fermé et codé en dur : ajouter un robot est un changement
//! de code relu, jamais une valeur de configuration.

use std::fmt;
use std::sync::OnceLock;

/// Famille d'un user-agent, qui décide de ce que #13 peut proposer contre lui.
/// Sérialisée comme [`BotClass::as_str`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BotClass {
    /// Les quatre moteurs du bénéfice du doute du PHP (Googlebot, bingbot,
    /// Applebot, DuckDuckBot) : jamais pénalisés au score.
    SearchEngine,
    /// Autres moteurs (Yandex, Baidu, Seznam, Sogou, 360Spider, PetalBot…) :
    /// +20 au score comme en PHP, mais jamais bloqués.
    OtherEngine,
    /// Aperçu de lien d'un réseau social ou d'une messagerie.
    SocialPreview,
    /// Collecte pour entraîner des modèles : aucun visiteur derrière.
    AiTraining,
    /// Moteur de réponses IA qui renvoie vers le site.
    AiSearch,
    /// Page lue parce qu'une personne l'a demandée à un assistant.
    AiUser,
    /// Robot d'audit SEO ou de données commerciales.
    Seo,
    /// Client HTTP générique (`curl`, `wget`, `python-requests`…) ou UA vide.
    Tool,
    /// Navigateur courant, sans jeton de robot.
    Browser,
    /// Robot sans classe dédiée : jeton `bot`, `crawler`, `spider` ou
    /// `scraper` hors catalogue, ou robot catalogué inclassable (archivage).
    Unknown,
}

impl BotClass {
    pub const ALL: [Self; 10] = [
        Self::SearchEngine,
        Self::OtherEngine,
        Self::SocialPreview,
        Self::AiTraining,
        Self::AiSearch,
        Self::AiUser,
        Self::Seo,
        Self::Tool,
        Self::Browser,
        Self::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SearchEngine => "search_engine",
            Self::OtherEngine => "other_engine",
            Self::SocialPreview => "social_preview",
            Self::AiTraining => "ai_training",
            Self::AiSearch => "ai_search",
            Self::AiUser => "ai_user",
            Self::Seo => "seo",
            Self::Tool => "tool",
            Self::Browser => "browser",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == value)
    }

    /// Libellé des e-mails et de `status`.
    pub fn label(self) -> &'static str {
        match self {
            Self::SearchEngine => "moteur de recherche",
            Self::OtherEngine => "autre moteur",
            Self::SocialPreview => "aperçu de lien",
            Self::AiTraining => "entraînement IA",
            Self::AiSearch => "recherche IA",
            Self::AiUser => "assistant IA pour une personne",
            Self::Seo => "robot SEO",
            Self::Tool => "outil",
            Self::Browser => "navigateur",
            Self::Unknown => "robot inconnu",
        }
    }

    /// Protégé des actions robots.txt et UA de #13 : un moteur, un aperçu
    /// social, un navigateur ou un assistant qui agit pour une personne
    /// (`AiUser` : écart au PHP, où il n'a aucune protection). La protection
    /// porte sur l'action, pas sur le verdict : une IP à UA de navigateur
    /// peut rester suspecte.
    pub fn protected(self) -> bool {
        matches!(
            self,
            Self::SearchEngine
                | Self::OtherEngine
                | Self::SocialPreview
                | Self::Browser
                | Self::AiUser
        )
    }
}

impl fmt::Display for BotClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Robot du catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bot {
    /// Jeton tel que l'éditeur l'écrit, cherché sans casse dans l'UA.
    pub name: &'static str,
    pub publisher: &'static str,
    /// Finalité, en clair.
    pub purpose: &'static str,
    /// Jeton de robots.txt seulement (Google-Extended, Applebot-Extended) :
    /// l'éditeur explore avec son robot ordinaire, une règle d'UA ne
    /// toucherait rien.
    pub robots_only: bool,
    /// L'éditeur dit respecter robots.txt.
    pub honours_robots: bool,
    pub class: BotClass,
}

impl Bot {
    pub fn protected(&self) -> bool {
        self.class.protected()
    }
}

const TRAINING: &str = "entraînement de modèles";
const AI_SEARCH: &str = "moteur de réponses IA";
const AI_USER: &str = "page demandée par une personne";
const INDEXING: &str = "indexation";
const PREVIEW: &str = "aperçu de lien";
const SEO: &str = "audit SEO";
const ARCHIVE: &str = "archivage";
const COMMERCIAL: &str = "données commerciales";
const CRAWL: &str = "exploration générique";

const fn bot(
    name: &'static str,
    publisher: &'static str,
    class: BotClass,
    purpose: &'static str,
    robots_only: bool,
    honours_robots: bool,
) -> Bot {
    Bot {
        name,
        publisher,
        purpose,
        robots_only,
        honours_robots,
        class,
    }
}

use BotClass::{
    AiSearch, AiTraining, AiUser, OtherEngine, SearchEngine, Seo, SocialPreview, Tool, Unknown,
};

/// Le catalogue. `honours_robots` reprend `AiBotCatalog.php` pour les robots
/// d'IA ; ailleurs, `false` quand l'éditeur ne l'affirme pas.
static BOTS: &[Bot] = &[
    // Les quatre moteurs du bénéfice du doute (`IpSuspicionScorer.php`).
    bot("Googlebot", "Google", SearchEngine, INDEXING, false, true),
    bot("bingbot", "Microsoft", SearchEngine, INDEXING, false, true),
    bot("Applebot", "Apple", SearchEngine, INDEXING, false, true),
    bot(
        "DuckDuckBot",
        "DuckDuckGo",
        SearchEngine,
        INDEXING,
        false,
        true,
    ),
    // Autres moteurs.
    bot("YandexBot", "Yandex", OtherEngine, INDEXING, false, true),
    bot("Baiduspider", "Baidu", OtherEngine, INDEXING, false, true),
    bot("SeznamBot", "Seznam", OtherEngine, INDEXING, false, true),
    bot("Sogou", "Sogou", OtherEngine, INDEXING, false, false),
    bot(
        "360Spider",
        "Qihoo 360",
        OtherEngine,
        INDEXING,
        false,
        false,
    ),
    bot("PetalBot", "Huawei", OtherEngine, INDEXING, false, true),
    bot("Exabot", "Exalead", OtherEngine, INDEXING, false, true),
    // IA : entraînement (`AiBotCatalog.php`).
    bot("GPTBot", "OpenAI", AiTraining, TRAINING, false, true),
    bot("ClaudeBot", "Anthropic", AiTraining, TRAINING, false, true),
    bot(
        "anthropic-ai",
        "Anthropic",
        AiTraining,
        TRAINING,
        false,
        true,
    ),
    bot(
        "Google-Extended",
        "Google",
        AiTraining,
        TRAINING,
        true,
        true,
    ),
    bot(
        "Applebot-Extended",
        "Apple",
        AiTraining,
        TRAINING,
        true,
        true,
    ),
    bot(
        "meta-externalagent",
        "Meta",
        AiTraining,
        TRAINING,
        false,
        true,
    ),
    bot("CCBot", "Common Crawl", AiTraining, TRAINING, false, true),
    bot(
        "Bytespider",
        "ByteDance",
        AiTraining,
        TRAINING,
        false,
        false,
    ),
    bot("Amazonbot", "Amazon", AiTraining, TRAINING, false, true),
    bot("cohere-ai", "Cohere", AiTraining, TRAINING, false, true),
    bot(
        "cohere-training-data-crawler",
        "Cohere",
        AiTraining,
        TRAINING,
        false,
        true,
    ),
    bot(
        "AI2Bot",
        "Allen Institute",
        AiTraining,
        TRAINING,
        false,
        true,
    ),
    bot("Diffbot", "Diffbot", AiTraining, TRAINING, false, true),
    bot("PanguBot", "Huawei", AiTraining, TRAINING, false, true),
    bot("Timpibot", "Timpi", AiTraining, TRAINING, false, true),
    bot(
        "ImagesiftBot",
        "ImageSift",
        AiTraining,
        TRAINING,
        false,
        true,
    ),
    bot("omgili", "Webz.io", AiTraining, TRAINING, false, true),
    // IA : recherche.
    bot("OAI-SearchBot", "OpenAI", AiSearch, AI_SEARCH, false, true),
    bot(
        "Claude-SearchBot",
        "Anthropic",
        AiSearch,
        AI_SEARCH,
        false,
        true,
    ),
    bot(
        "PerplexityBot",
        "Perplexity",
        AiSearch,
        AI_SEARCH,
        false,
        true,
    ),
    bot("YouBot", "You.com", AiSearch, AI_SEARCH, false, true),
    // IA : pour une personne.
    bot("ChatGPT-User", "OpenAI", AiUser, AI_USER, false, false),
    bot("Claude-User", "Anthropic", AiUser, AI_USER, false, false),
    bot(
        "Perplexity-User",
        "Perplexity",
        AiUser,
        AI_USER,
        false,
        false,
    ),
    bot(
        "meta-externalfetcher",
        "Meta",
        AiUser,
        AI_USER,
        false,
        false,
    ),
    // Aperçus de liens.
    bot(
        "facebookexternalhit",
        "Meta",
        SocialPreview,
        PREVIEW,
        false,
        false,
    ),
    bot("Facebot", "Meta", SocialPreview, PREVIEW, false, false),
    bot("Twitterbot", "X", SocialPreview, PREVIEW, false, true),
    bot(
        "LinkedInBot",
        "LinkedIn",
        SocialPreview,
        PREVIEW,
        false,
        false,
    ),
    bot(
        "Pinterest",
        "Pinterest",
        SocialPreview,
        PREVIEW,
        false,
        false,
    ),
    bot("Slackbot", "Slack", SocialPreview, PREVIEW, false, false),
    bot(
        "TelegramBot",
        "Telegram",
        SocialPreview,
        PREVIEW,
        false,
        false,
    ),
    bot("WhatsApp", "Meta", SocialPreview, PREVIEW, false, false),
    bot(
        "Discordbot",
        "Discord",
        SocialPreview,
        PREVIEW,
        false,
        false,
    ),
    // SEO et données commerciales.
    bot("AhrefsBot", "Ahrefs", Seo, SEO, false, true),
    bot("SemrushBot", "Semrush", Seo, SEO, false, true),
    bot("DotBot", "Moz", Seo, SEO, false, true),
    bot("rogerbot", "Moz", Seo, SEO, false, true),
    bot("MJ12bot", "Majestic", Seo, SEO, false, true),
    bot("DataForSeoBot", "DataForSEO", Seo, SEO, false, true),
    bot("BLEXBot", "WebMeUp", Seo, SEO, false, true),
    bot("linkdexbot", "Linkdex", Seo, SEO, false, false),
    bot("serpstatbot", "Serpstat", Seo, SEO, false, true),
    bot("SEOkicks", "SEOkicks", Seo, SEO, false, false),
    bot("MegaIndex", "MegaIndex", Seo, SEO, false, false),
    bot("seoscanners", "seoscanners", Seo, SEO, false, false),
    bot("SurdotlyBot", "Surdotly", Seo, SEO, false, false),
    bot("MauiBot", "inconnu", Seo, SEO, false, false),
    bot("Barkrowler", "Babbar", Seo, SEO, false, true),
    bot("Screaming Frog", "Screaming Frog", Seo, SEO, false, false),
    bot("ZoominfoBot", "ZoomInfo", Seo, COMMERCIAL, false, false),
    // Archivage et divers : catalogués pour leur éditeur, sans classe dédiée.
    bot("ia_archiver", "Alexa", Unknown, ARCHIVE, false, true),
    bot(
        "archive.org_bot",
        "Internet Archive",
        Unknown,
        ARCHIVE,
        false,
        false,
    ),
    bot("TikTokSpider", "ByteDance", Unknown, CRAWL, false, false),
    bot("AionBot", "inconnu", Unknown, CRAWL, false, false),
    bot("Nutch", "Apache", Tool, CRAWL, false, true),
];

/// Tout le catalogue, dans l'ordre déclaré.
pub fn catalog() -> &'static [Bot] {
    BOTS
}

/// Robot du catalogue par son nom, sans casse.
pub fn find(name: &str) -> Option<&'static Bot> {
    BOTS.iter()
        .find(|b| b.name.eq_ignore_ascii_case(name.trim()))
}

/// Noms en minuscules, du plus long au plus court (puis par nom, pour un
/// ordre déterministe) : le premier trouvé est le plus long.
fn matcher() -> &'static [(String, &'static Bot)] {
    static MATCHER: OnceLock<Vec<(String, &'static Bot)>> = OnceLock::new();
    MATCHER.get_or_init(|| {
        let mut names: Vec<(String, &'static Bot)> = BOTS
            .iter()
            .map(|b| (b.name.to_ascii_lowercase(), b))
            .collect();
        names.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        names
    })
}

/// Résultat du classement d'un UA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// Robot du catalogue reconnu, s'il y en a un.
    pub bot: Option<&'static Bot>,
    pub class: BotClass,
}

impl Classification {
    pub fn protected(&self) -> bool {
        self.class.protected()
    }
}

/// Débuts d'UA des clients HTTP génériques, en minuscules.
const TOOL_PREFIXES: &[&str] = &[
    "curl/",
    "wget/",
    "python-requests/",
    "python-urllib/",
    "python-httpx/",
    "python/",
    "aiohttp/",
    "httpx/",
    "go-http-client/",
    "libwww-perl/",
    "lwp::simple",
    "java/",
    "okhttp/",
    "apache-httpclient/",
    "axios/",
    "node-fetch",
    "undici",
    "got ",
    "guzzlehttp/",
    "php/",
    "ruby",
    "scrapy/",
    "httpie/",
    "powershell/",
    "winhttp",
];

/// Marques d'un navigateur piloté par un script, cherchées partout.
const TOOL_MARKERS: &[&str] = &["headlesschrome", "phantomjs", "puppeteer", "playwright"];

/// Jetons d'un robot hors catalogue.
const BOT_TOKENS: &[&str] = &["bot", "crawler", "spider", "scraper"];

/// UA d'un outil générique : vide, `-`, client HTTP connu ou navigateur sans
/// tête. Ces UA ne sont jamais partagés entre sites (phase 3) : ils ne
/// désignent pas un robot mais n'importe qui.
pub fn is_generic_tool(user_agent: &str) -> bool {
    let ua = user_agent.trim();
    if ua.is_empty() || ua == "-" {
        return true;
    }
    let lower = ua.to_ascii_lowercase();
    TOOL_PREFIXES.iter().any(|p| lower.starts_with(p))
        || TOOL_MARKERS.iter().any(|m| lower.contains(m))
}

/// Un jeton de robot (`bot`, `crawler`, `spider`, `scraper`) en fin de mot.
/// Dans un UA `Mozilla/…`, il faut aussi `compatible` ou une URL : sinon un
/// modèle de téléphone (« CUBOT X19 ») passerait pour un robot. `lower` est
/// en minuscules.
pub fn has_bot_token(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let found = BOT_TOKENS.iter().any(|token| {
        lower.match_indices(token).any(|(at, _)| {
            let end = at + token.len();
            bytes.get(end).is_none_or(|b| !b.is_ascii_alphabetic())
        })
    });
    found
        && (!lower.starts_with("mozilla/")
            || lower.contains("compatible")
            || lower.contains("http"))
}

/// Classe un UA : robot du catalogue (correspondance la plus longue, sans
/// casse), sinon outil générique, sinon robot inconnu (jeton de robot), sinon
/// navigateur (`Mozilla/…`, `Opera/…`), sinon inconnu.
pub fn classify(user_agent: &str) -> Classification {
    let ua = user_agent.trim();
    if ua.is_empty() || ua == "-" {
        return Classification {
            bot: None,
            class: BotClass::Tool,
        };
    }
    let lower = ua.to_ascii_lowercase();
    if let Some((_, bot)) = matcher().iter().find(|(name, _)| lower.contains(name)) {
        return Classification {
            bot: Some(bot),
            class: bot.class,
        };
    }
    let class = if is_generic_tool(ua) {
        BotClass::Tool
    } else if has_bot_token(&lower) {
        BotClass::Unknown
    } else if lower.starts_with("mozilla/") || lower.starts_with("opera/") {
        BotClass::Browser
    } else {
        BotClass::Unknown
    };
    Classification { bot: None, class }
}
