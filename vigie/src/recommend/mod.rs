//! Recommandations dérivées des logs (#13).
//!
//! Deux étapes séparées, testées à part :
//!
//! - l'**analyse** (déterministe) : la dernière [`Analysis`] d'un site → des
//!   [`Proposal`] graduées ([`recommend`]) : robots.txt pour un robot qui le
//!   respecte, règle d'UA pour un robot non protégé qui ne le respecte pas,
//!   règle d'IP pour une IP au score propre élevé que son reverse DNS classe
//!   hébergeur. Jamais rien contre un moteur, un aperçu social, un
//!   navigateur ou un assistant qui agit pour une personne ;
//! - la **génération** du bloc `# BEGIN vigie` ([`htaccess`]), testée par
//!   fichiers de référence, et son plan cumulatif ([`plan`]) : les groupes
//!   encore valides du bloc en place sont repris, les expirés retirés.
//!
//! robots.txt reste une proposition à poser à la main ; seul le bloc part
//! par le canal de commandes (`htaccess-apply`), validé de nouveau par
//! l'agent.

pub mod history;
pub mod htaccess;
pub mod rdns;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use jiff::tz::TimeZone;

use crate::analysis::catalog::{self, BotClass};
use crate::analysis::findings::Analysis;
use crate::analysis::score::{self, LEVEL_HIGH, Level, Network};
use htaccess::{Group, Target};

/// Une proposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proposal {
    /// `User-agent: <bot>` / `Disallow: /`, à poser à la main.
    Robots { bot: String, publisher: String },
    /// Règle d'UA de 30 jours ; le littéral est le jeton du catalogue.
    UserAgent { bot: String, literal: String },
    /// Règle d'IP de 24 h.
    Ip {
        ip: IpAddr,
        rdns: String,
        own_score: u8,
    },
}

/// Ce que l'analyse doit savoir du site.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    pub analysis: &'a Analysis,
    /// Fuseau du site (`[sites.logs] tz`) : sans lui, ni UA ni IP.
    pub tz: Option<&'a TimeZone>,
    /// `Entry.ip` est celle d'un proxy : pas de règle d'IP.
    pub behind_proxy: bool,
    /// IP jamais bloquées : IP sortantes du veilleur, adresses source des
    /// retraits de l'agent, `protect_ips` du site.
    pub protected_ips: &'a BTreeSet<IpAddr>,
}

/// Robot qui admet une règle d'UA : jeton du catalogue, classe non
/// protégée, ni `Unknown` ni `Tool` (jeton générique), pas un jeton
/// robots.txt seul, littéral valide qui ne touche aucun UA protégé.
pub fn ua_rule_allowed(name: &str) -> bool {
    let Some(bot) = catalog::find(name) else {
        return false;
    };
    !bot.protected()
        && !bot.robots_only
        && !bot.honours_robots
        && !matches!(bot.class, BotClass::Unknown | BotClass::Tool)
        && htaccess::literal_ok(bot.name)
        && !htaccess::touches_protected(bot.name)
}

/// Résolution inverse injectée : nom de chaque IP, `None` si non résolue.
pub type Reverse<'a> = dyn FnMut(&[IpAddr]) -> HashMap<IpAddr, Option<String>> + 'a;

/// Propositions graduées. `reverse` résout les IP candidates (au plus
/// [`rdns::MAX_IPS`]) : injecté pour les tests.
pub fn recommend(inputs: &Inputs<'_>, reverse: &mut Reverse<'_>) -> Vec<Proposal> {
    let mut robots = Vec::new();
    let mut uas = Vec::new();
    for seen in &inputs.analysis.bots {
        let Some(bot) = catalog::find(&seen.name) else {
            continue;
        };
        if bot.protected() {
            continue;
        }
        if bot.honours_robots {
            robots.push(Proposal::Robots {
                bot: bot.name.to_owned(),
                publisher: bot.publisher.to_owned(),
            });
        } else if inputs.tz.is_some() && ua_rule_allowed(bot.name) {
            uas.push(Proposal::UserAgent {
                bot: bot.name.to_owned(),
                literal: bot.name.to_owned(),
            });
        }
    }
    robots.sort_by_key(key);
    uas.sort_by_key(key);

    let mut ips = Vec::new();
    if inputs.tz.is_some() && !inputs.behind_proxy {
        let candidates: Vec<IpAddr> = inputs
            .analysis
            .verdicts
            .iter()
            .filter(|v| {
                v.level == Level::High
                    && v.own_score >= LEVEL_HIGH
                    && !v.class.protected()
                    && !inputs.protected_ips.contains(&v.ip)
                    && htaccess::ip_ok(v.ip)
            })
            .map(|v| v.ip)
            .take(rdns::MAX_IPS)
            .collect();
        if !candidates.is_empty() {
            let names = reverse(&candidates);
            for verdict in &inputs.analysis.verdicts {
                if !candidates.contains(&verdict.ip) {
                    continue;
                }
                let Some(Some(name)) = names.get(&verdict.ip) else {
                    continue;
                };
                if score::network(Some(name)) == Network::Hosting {
                    ips.push(Proposal::Ip {
                        ip: verdict.ip,
                        rdns: name.clone(),
                        own_score: verdict.own_score,
                    });
                }
            }
        }
    }
    ips.sort_by_key(|p| match p {
        Proposal::Ip { ip, .. } => Some(*ip),
        _ => None,
    });
    robots.into_iter().chain(uas).chain(ips).collect()
}

fn key(p: &Proposal) -> String {
    match p {
        Proposal::Robots { bot, .. } | Proposal::UserAgent { bot, .. } => bot.to_ascii_lowercase(),
        Proposal::Ip { ip, .. } => ip.to_string(),
    }
}

/// Texte robots.txt des propositions, à poser à la main.
pub fn robots_txt(proposals: &[Proposal]) -> String {
    proposals
        .iter()
        .filter_map(|p| match p {
            Proposal::Robots { bot, .. } => Some(format!("User-agent: {bot}\nDisallow: /\n")),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Marge sous laquelle un groupe en place n'est pas repris : la commande
/// peut n'être servie qu'au passage suivant de l'agent.
pub const KEEP_MARGIN: i64 = 3600;

/// Bloc à appliquer et ce qui change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub groups: Vec<Group>,
    /// Groupes du bloc en place repris tels quels.
    pub kept: Vec<Group>,
    /// Groupes du bloc en place retirés (expirés ou sur le point de l'être).
    pub expired: Vec<Group>,
    /// Groupes nouveaux.
    pub added: Vec<Group>,
}

impl Plan {
    pub fn block(&self) -> String {
        htaccess::render(&self.groups)
    }

    pub fn changes(&self) -> bool {
        !self.expired.is_empty() || !self.added.is_empty()
    }
}

/// Bloc cumulatif : groupes encore valides de `current` (bloc en place
/// connu), puis un groupe d'UA neuf pour les littéraux qui n'y sont pas, puis
/// un groupe par IP neuve. `None` sans fuseau.
pub fn plan(current: &[Group], proposals: &[Proposal], now: i64, tz: &TimeZone) -> Option<Plan> {
    let (kept, expired): (Vec<Group>, Vec<Group>) = current
        .iter()
        .cloned()
        .partition(|g| g.until_ts > now + KEEP_MARGIN);
    let covered_uas: BTreeSet<String> = kept
        .iter()
        .flat_map(|g| match &g.target {
            Target::UserAgents(l) => l.iter().map(|s| s.to_ascii_lowercase()).collect(),
            Target::Ip(_) => Vec::new(),
        })
        .collect();
    let covered_ips: BTreeSet<IpAddr> = kept
        .iter()
        .filter_map(|g| match g.target {
            Target::Ip(ip) => Some(ip),
            Target::UserAgents(_) => None,
        })
        .collect();
    let mut literals = Vec::new();
    let mut ips = Vec::new();
    for p in proposals {
        match p {
            Proposal::UserAgent { literal, .. }
                if !covered_uas.contains(&literal.to_ascii_lowercase()) =>
            {
                literals.push(literal.clone());
            }
            Proposal::Ip { ip, .. } if !covered_ips.contains(ip) => ips.push(*ip),
            _ => {}
        }
    }
    let mut added = Vec::new();
    if !literals.is_empty() {
        added.push(Group::new(
            Target::UserAgents(literals),
            now + htaccess::UA_TTL,
            tz,
        )?);
    }
    for ip in ips {
        added.push(Group::new(Target::Ip(ip), now + htaccess::IP_TTL, tz)?);
    }
    let groups = kept.iter().chain(&added).cloned().collect();
    Some(Plan {
        groups,
        kept,
        expired,
        added,
    })
}

/// Résumé d'un groupe pour l'affichage.
pub fn describe(group: &Group) -> String {
    let until = htaccess::readable(&group.until);
    match &group.target {
        Target::UserAgents(l) => format!("UA {} jusqu'au {until}", l.join(", ")),
        Target::Ip(ip) => format!("IP {ip} jusqu'au {until}"),
    }
}
