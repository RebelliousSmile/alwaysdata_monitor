//! Règles déclaratives de l'analyse : chemin (globs), méthodes, statuts,
//! portée, seuils, fenêtre, gravité. Aucune expression ni regex.
//!
//! Les règles par défaut sont codées ici ; `[logs]` de `config.toml` peut en
//! désactiver (`disable`) ou en ajouter (`rules`), et `[sites.logs]` en
//! ajouter pour un site. Toute règle est validée et compilée au chargement de
//! la configuration : une règle invalide est une erreur de configuration,
//! jamais une surprise au passage de `tick`.
//!
//! La clé d'un constat sera l'identifiant de la règle, jamais une valeur vue
//! dans un log (phase 3).

use std::collections::HashSet;
use std::fmt;
use std::ops::RangeInclusive;

use serde::Deserialize;

use super::glob::{Glob, GlobError};
use crate::config::{Config, Site};
use crate::finding::Severity;
use crate::logs::{Entry, MAX_METHOD};

/// Bornes de la fenêtre d'une règle, en secondes.
pub const MIN_WINDOW: u32 = 60;
pub const MAX_WINDOW: u32 = 3600;
/// Seuil de requêtes au plus.
pub const MAX_COUNT: u32 = 1_000_000;
/// IP distinctes au plus : borne la colonne d'IP des seaux (phase 2).
pub const MAX_IPS: u32 = 1000;
/// Bornes de taille d'une règle et d'un ensemble de règles.
pub const MAX_ID: usize = 64;
pub const MAX_PATHS: usize = 32;
pub const MAX_METHODS: usize = 16;
pub const MAX_STATUSES: usize = 32;
pub const MAX_RULES: usize = 64;
pub const MAX_EXCLUDES: usize = 32;
/// Fenêtre par défaut d'une règle de la configuration.
pub const DEFAULT_WINDOW: u32 = 600;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RuleError(pub String);

impl RuleError {
    fn rule(id: &str, reason: impl fmt::Display) -> Self {
        Self(format!("règle « {id} » : {reason}"))
    }
}

/// Ce que l'on compte : par IP ou pour tout le site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Ip,
    Site,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Site => "site",
        }
    }
}

/// Un statut (`404`) ou une plage (`"500-599"`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum StatusSpec {
    Code(u16),
    Range(String),
}

impl StatusSpec {
    fn range(&self) -> Option<RangeInclusive<u16>> {
        let (lo, hi) = match self {
            Self::Code(code) => (*code, *code),
            Self::Range(text) => {
                let (lo, hi) = text.split_once('-')?;
                let parse = |s: &str| {
                    let s = s.trim();
                    (s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
                        .then(|| s.parse::<u16>().ok())
                        .flatten()
                };
                (parse(lo)?, parse(hi)?)
            }
        };
        ((100..=599).contains(&lo) && (100..=599).contains(&hi) && lo <= hi).then_some(lo..=hi)
    }
}

impl fmt::Display for StatusSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(code) => write!(f, "{code}"),
            Self::Range(text) => write!(f, "{text:?}"),
        }
    }
}

/// Une valeur seule ou une liste, pour `path` et `statuses`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(values: Vec<T>) -> Self {
        Self::Many(values)
    }
}

/// Règle telle qu'écrite dans `config.toml` (`[[logs.rules]]`,
/// `[[sites.logs.rules]]`). Un champ de filtre vide ne filtre rien.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `[a-z0-9-]`, 64 caractères au plus, unique : clé du constat.
    pub id: String,
    /// Globs de chemin (`glob.rs`) ; l'un d'eux suffit.
    #[serde(default)]
    pub path: OneOrMany<String>,
    /// Méthodes HTTP, en majuscules ; l'une d'elles suffit.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Statuts et plages (`[404, "500-599"]`) ; l'un d'eux suffit.
    #[serde(default)]
    pub statuses: OneOrMany<StatusSpec>,
    pub scope: Scope,
    /// Requêtes dans la fenêtre, au moins.
    pub min_count: u32,
    /// IP distinctes dans la fenêtre, au moins (portée `site` seulement).
    #[serde(default = "default_min_ips")]
    pub min_ips: u32,
    #[serde(default = "default_window")]
    pub window_secs: u32,
    #[serde(default = "default_severity", deserialize_with = "severity")]
    pub severity: Severity,
}

fn default_min_ips() -> u32 {
    1
}

fn default_window() -> u32 {
    DEFAULT_WINDOW
}

fn default_severity() -> Severity {
    Severity::Warning
}

fn severity<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Severity, D::Error> {
    let value = String::deserialize(deserializer)?;
    Severity::parse(&value).ok_or_else(|| {
        serde::de::Error::custom(format!(
            "gravité inconnue « {value} » : info, warning ou critical"
        ))
    })
}

/// Chemins sensibles : un seul accès vaut information, cinq IP un
/// avertissement.
pub const SENSITIVE_PATHS: [&str; 7] = [
    "/**/.env",
    "/**/.git/**",
    "/**/wp-config.php.*",
    "/**/*.sql",
    "/**/*.bak",
    "/**/phpinfo.php",
    "/server-status",
];

/// Pages de connexion visées par la force brute.
pub const LOGIN_PATHS: [&str; 3] = ["/wp-login.php", "/connexion", "/xmlrpc.php"];

/// Identifiants des règles par défaut, dans l'ordre.
pub const DEFAULT_IDS: [&str; 7] = [
    "spike-404",
    "spike-403",
    "errors-5xx",
    "sensitive-path",
    "sensitive-path-many",
    "brute-force",
    "repeated-ip",
];

/// Les règles par défaut, dans l'ordre de [`DEFAULT_IDS`].
pub fn defaults() -> Vec<Rule> {
    let rule = |id: &str, scope, min_count, severity| Rule {
        id: id.to_string(),
        path: OneOrMany::default(),
        methods: Vec::new(),
        statuses: OneOrMany::default(),
        scope,
        min_count,
        min_ips: 1,
        window_secs: 600,
        severity,
    };
    let paths = |list: &[&str]| -> OneOrMany<String> {
        list.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .into()
    };
    vec![
        Rule {
            statuses: OneOrMany::One(StatusSpec::Code(404)),
            ..rule("spike-404", Scope::Site, 100, Severity::Warning)
        },
        Rule {
            statuses: OneOrMany::One(StatusSpec::Code(403)),
            ..rule("spike-403", Scope::Site, 100, Severity::Warning)
        },
        Rule {
            statuses: OneOrMany::One(StatusSpec::Range("500-599".into())),
            ..rule("errors-5xx", Scope::Site, 10, Severity::Critical)
        },
        Rule {
            path: paths(&SENSITIVE_PATHS),
            ..rule("sensitive-path", Scope::Site, 1, Severity::Info)
        },
        Rule {
            path: paths(&SENSITIVE_PATHS),
            min_ips: 5,
            ..rule("sensitive-path-many", Scope::Site, 5, Severity::Warning)
        },
        Rule {
            path: paths(&LOGIN_PATHS),
            methods: vec!["POST".into()],
            ..rule("brute-force", Scope::Ip, 30, Severity::Warning)
        },
        rule("repeated-ip", Scope::Ip, 600, Severity::Warning),
    ]
}

/// Règle validée, prête à compter des entrées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub id: String,
    paths: Vec<Glob>,
    methods: Vec<String>,
    statuses: Vec<RangeInclusive<u16>>,
    pub scope: Scope,
    pub min_count: u32,
    pub min_ips: u32,
    pub window_secs: u32,
    pub severity: Severity,
}

impl CompiledRule {
    pub fn compile(rule: &Rule) -> Result<Self, RuleError> {
        let id = &rule.id;
        if !crate::config::is_valid_id(id) || id.len() > MAX_ID {
            return Err(RuleError(format!(
                "identifiant de règle invalide « {} » : [a-z0-9-], {MAX_ID} caractères au plus",
                id.escape_debug()
            )));
        }
        let paths = rule.path.as_slice();
        if paths.len() > MAX_PATHS {
            return Err(RuleError::rule(id, format!("{MAX_PATHS} chemins au plus")));
        }
        let paths = paths
            .iter()
            .map(|p| Glob::new(p))
            .collect::<Result<Vec<_>, GlobError>>()
            .map_err(|err| RuleError::rule(id, err))?;
        if rule.methods.len() > MAX_METHODS {
            return Err(RuleError::rule(
                id,
                format!("{MAX_METHODS} méthodes au plus"),
            ));
        }
        let mut methods = Vec::with_capacity(rule.methods.len());
        for method in &rule.methods {
            if method.is_empty()
                || method.len() > MAX_METHOD
                || !method.bytes().all(|b| b.is_ascii_uppercase())
            {
                return Err(RuleError::rule(
                    id,
                    format!(
                        "méthode invalide « {} » : lettres majuscules, {MAX_METHOD} au plus",
                        method.escape_debug()
                    ),
                ));
            }
            if !methods.contains(method) {
                methods.push(method.clone());
            }
        }
        let statuses = rule.statuses.as_slice();
        if statuses.len() > MAX_STATUSES {
            return Err(RuleError::rule(
                id,
                format!("{MAX_STATUSES} statuts au plus"),
            ));
        }
        let statuses = statuses
            .iter()
            .map(|s| {
                s.range().ok_or_else(|| {
                    RuleError::rule(
                        id,
                        format!("statut invalide {s} : 100 à 599, ou plage \"500-599\""),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !(1..=MAX_COUNT).contains(&rule.min_count) {
            return Err(RuleError::rule(
                id,
                format!("min_count de 1 à {MAX_COUNT} (reçu : {})", rule.min_count),
            ));
        }
        if !(1..=MAX_IPS).contains(&rule.min_ips) {
            return Err(RuleError::rule(
                id,
                format!("min_ips de 1 à {MAX_IPS} (reçu : {})", rule.min_ips),
            ));
        }
        if rule.scope == Scope::Ip && rule.min_ips != 1 {
            return Err(RuleError::rule(id, "min_ips n'a de sens qu'en portée site"));
        }
        if rule.min_ips > rule.min_count {
            return Err(RuleError::rule(
                id,
                format!(
                    "min_ips ({}) dépasse min_count ({}) : jamais atteint",
                    rule.min_ips, rule.min_count
                ),
            ));
        }
        if !(MIN_WINDOW..=MAX_WINDOW).contains(&rule.window_secs) {
            return Err(RuleError::rule(
                id,
                format!(
                    "window_secs de {MIN_WINDOW} à {MAX_WINDOW} (reçu : {})",
                    rule.window_secs
                ),
            ));
        }
        Ok(Self {
            id: id.clone(),
            paths,
            methods,
            statuses,
            scope: rule.scope,
            min_count: rule.min_count,
            min_ips: rule.min_ips,
            window_secs: rule.window_secs,
            severity: rule.severity,
        })
    }

    /// L'entrée compte pour la règle : méthode, statut et chemin, du moins
    /// coûteux au plus coûteux.
    pub fn matches(&self, entry: &Entry) -> bool {
        (self.methods.is_empty()
            || entry
                .method
                .as_ref()
                .is_some_and(|m| self.methods.contains(m)))
            && (self.statuses.is_empty() || self.statuses.iter().any(|r| r.contains(&entry.status)))
            && (self.paths.is_empty() || self.paths.iter().any(|g| g.matches(&entry.path)))
    }
}

/// Règles et exclusions effectives d'un site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    /// Dans l'ordre : défauts non désactivés, `[logs]`, puis `[sites.logs]`.
    pub rules: Vec<CompiledRule>,
    /// Chemins retirés de l'analyse (`[sites.logs] exclude`).
    pub exclude: Vec<Glob>,
    /// `Entry.ip` est un proxy : règles de portée `ip` et score coupés.
    pub behind_proxy: bool,
}

impl RuleSet {
    /// Le chemin est retiré de l'analyse.
    pub fn excluded(&self, path: &str) -> bool {
        self.exclude.iter().any(|g| g.matches(path))
    }

    /// Règles qui comptent pour ce site : sans celles de portée `ip`
    /// derrière un proxy.
    pub fn active(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules
            .iter()
            .filter(|r| !(self.behind_proxy && r.scope == Scope::Ip))
    }
}

/// Défauts moins `disable`, puis `global`, puis `site` : identifiants
/// uniques, `disable` ne nomme que des règles par défaut.
pub fn compile_rules(
    disable: &[String],
    global: &[Rule],
    site: &[Rule],
) -> Result<Vec<CompiledRule>, RuleError> {
    let mut disabled = HashSet::new();
    for id in disable {
        if !DEFAULT_IDS.contains(&id.as_str()) {
            return Err(RuleError(format!(
                "logs.disable : « {} » n'est pas une règle par défaut ({})",
                id.escape_debug(),
                DEFAULT_IDS.join(", ")
            )));
        }
        disabled.insert(id.as_str());
    }
    if global.len() + site.len() > MAX_RULES {
        return Err(RuleError(format!("{MAX_RULES} règles ajoutées au plus")));
    }
    let defaults = defaults();
    let mut seen = HashSet::new();
    let mut compiled = Vec::new();
    for rule in defaults
        .iter()
        .filter(|r| !disabled.contains(r.id.as_str()))
        .chain(global)
        .chain(site)
    {
        let rule = CompiledRule::compile(rule)?;
        if !seen.insert(rule.id.clone()) {
            return Err(RuleError(format!(
                "règle « {} » déclarée deux fois (désactiver d'abord une règle par défaut pour la remplacer)",
                rule.id
            )));
        }
        compiled.push(rule);
    }
    Ok(compiled)
}

pub fn compile_excludes(exclude: &[String]) -> Result<Vec<Glob>, RuleError> {
    if exclude.len() > MAX_EXCLUDES {
        return Err(RuleError(format!(
            "exclude : {MAX_EXCLUDES} motifs au plus"
        )));
    }
    exclude
        .iter()
        .map(|p| Glob::new(p).map_err(|err| RuleError(format!("exclude : {err}"))))
        .collect()
}

/// Règles effectives d'un site de `config`. Déjà validées au chargement :
/// une erreur ici ne vient que d'une `Config` construite à la main.
pub fn for_site(config: &Config, site: &Site) -> Result<RuleSet, RuleError> {
    let (site_rules, exclude, behind_proxy): (&[Rule], &[String], bool) = match &site.logs {
        Some(logs) => (&logs.rules, &logs.exclude, logs.behind_proxy),
        None => (&[], &[], false),
    };
    Ok(RuleSet {
        rules: compile_rules(&config.logs.disable, &config.logs.rules, site_rules)?,
        exclude: compile_excludes(exclude)?,
        behind_proxy,
    })
}
