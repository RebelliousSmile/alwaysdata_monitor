//! Registre des capacités (issues #2 et #4) : la seule déclaration de ce
//! qui s'exécute ou s'ouvre pour un site.
//!
//! - Chaque **contrôle** ([`Control`]) déclare les CMS auxquels il
//!   s'applique et sa condition d'existence : agent enregistré et runtime
//!   effectif `php` pour le battement de cœur, l'intégrité et les familles
//!   de l'agent, référence d'empreintes en plus pour l'intégrité, source de
//!   logs pour `logs`. [`watched`] en dérive le seul verdict « surveillé »,
//!   que `tick`, l'ingestion des rapports et l'API consultent tous.
//! - Chaque **commande** ([`CommandKind`]) déclare les runtimes qui
//!   l'admettent ; un site sans runtime (`generic` non déclaré) n'en admet
//!   aucune.
//!
//! Les listes sont fermées et codées en dur, par des `match` sans joker : une
//! variante nouvelle oblige à décider, et ajouter un contrôle, une famille ou
//! une commande est un changement de code relu, jamais une valeur de
//! configuration. Le CMS et le runtime d'un site viennent de `config.toml`,
//! jamais de l'agent (`docs/protocole-commandes.md`). Ce que le registre ne
//! connaît pas n'est pas surveillé : fail-closed.

use std::fmt;

use crate::checks::CheckKind;
use crate::config::{Runtime, Site, SiteKind};
use crate::finding::{Finding, Severity};

const ALL_CMS: &[SiteKind] = &[SiteKind::Generic, SiteKind::Wordpress, SiteKind::Prestashop];

/// Familles de constats qu'émet l'agent PHP (`finding('…'` de
/// `vigie-agent.php`), sous le préfixe `agent:`. Une famille bien formée
/// mais absente d'ici, ou non admise pour le CMS du site, est écartée à
/// l'ingestion et comptée (`reports.dropped`). `integrity` n'en est pas une :
/// le nom est réservé au veilleur ([`Control::Integrity`]), et un rapport qui
/// l'emploie est refusé en entier (`report.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentFamily {
    /// Racine du site introuvable.
    Root,
    /// Fichier critique absent ou illisible.
    CriticalFile,
    /// Fichier qui ne contient plus le texte attendu.
    MustContain,
    /// Fichier PHP dans `wp-content/uploads`.
    UploadsPhp,
}

impl AgentFamily {
    pub const ALL: [Self; 4] = [
        Self::Root,
        Self::CriticalFile,
        Self::MustContain,
        Self::UploadsPhp,
    ];

    /// Nom émis par l'agent, sans préfixe.
    pub fn name(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::CriticalFile => "critical-file",
            Self::MustContain => "must-contain",
            Self::UploadsPhp => "uploads-php",
        }
    }

    /// Nom du contrôle, préfixé par `agent:`.
    pub fn check_name(self) -> &'static str {
        match self {
            Self::Root => "agent:root",
            Self::CriticalFile => "agent:critical-file",
            Self::MustContain => "agent:must-contain",
            Self::UploadsPhp => "agent:uploads-php",
        }
    }

    /// `None` pour un nom hors de la liste : fail-closed.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|family| family.name() == name)
    }

    /// CMS qui admettent la famille : `uploads-php` ne vaut que pour
    /// WordPress (`wp-content/uploads`).
    pub fn cms(self) -> &'static [SiteKind] {
        match self {
            Self::UploadsPhp => &[SiteKind::Wordpress],
            Self::Root | Self::CriticalFile | Self::MustContain => ALL_CMS,
        }
    }
}

/// Condition d'existence d'un contrôle, en plus du CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    /// Aucune : les contrôles externes.
    Nothing,
    /// Agent enregistré et runtime effectif `php`.
    PhpAgent,
    /// Agent enregistré, runtime effectif `php` et référence d'empreintes.
    PhpAgentAndBaseline,
    /// `[sites.logs] source` déclaré.
    LogSource,
    /// Agent enregistré sur un site dont le runtime effectif n'est pas `php`.
    AgentWithoutPhp,
}

/// Ce que le veilleur sait d'un site hors de sa configuration : lu en base
/// par l'appelant (dans la transaction d'`accept_report` pour la référence,
/// que le premier rapport y crée).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ctx {
    /// Une clé d'agent est enregistrée.
    pub agent: bool,
    /// Une référence d'empreintes existe.
    pub baseline: bool,
}

/// Contrôles connus du veilleur : un incident ou un passage ne porte jamais
/// d'autre nom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Control {
    /// Contrôle externe, lancé par `tick`.
    Check(CheckKind),
    /// Silence de l'agent (`checks/heartbeat.rs`).
    Heartbeat,
    /// Dérive des empreintes, calculée par le veilleur (`facts.rs`).
    Integrity,
    /// Famille de constats de l'agent.
    Agent(AgentFamily),
    /// Analyse des logs (#8).
    Logs,
    /// Avertissement : clé d'agent sur un site sans runtime `php`.
    Typology,
}

/// Nom du contrôle `typology`.
pub const TYPOLOGY: &str = "typology";
/// Clé de l'unique constat `typology`.
pub const TYPOLOGY_KEY: &str = "agent-runtime";

impl Control {
    /// Tous les contrôles, dans l'ordre d'affichage.
    pub const ALL: [Self; 13] = [
        Self::Check(CheckKind::Content),
        Self::Check(CheckKind::Installer),
        Self::Check(CheckKind::Exposed),
        Self::Check(CheckKind::Tls),
        Self::Check(CheckKind::Headers),
        Self::Heartbeat,
        Self::Integrity,
        Self::Agent(AgentFamily::Root),
        Self::Agent(AgentFamily::CriticalFile),
        Self::Agent(AgentFamily::MustContain),
        Self::Agent(AgentFamily::UploadsPhp),
        Self::Logs,
        Self::Typology,
    ];

    /// Nom du contrôle, tel qu'il figure dans les incidents et les passages.
    pub fn name(self) -> &'static str {
        match self {
            Self::Check(kind) => kind.name(),
            Self::Heartbeat => crate::checks::heartbeat::NAME,
            Self::Integrity => "agent:integrity",
            Self::Agent(family) => family.check_name(),
            Self::Logs => crate::analysis::findings::CHECK,
            Self::Typology => TYPOLOGY,
        }
    }

    /// `None` pour un nom hors du registre : fail-closed.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|control| control.name() == name)
    }

    /// CMS auxquels le contrôle s'applique.
    pub fn cms(self) -> &'static [SiteKind] {
        match self {
            Self::Check(kind) => match kind {
                CheckKind::Installer => &[SiteKind::Wordpress, SiteKind::Prestashop],
                CheckKind::Content | CheckKind::Exposed | CheckKind::Tls | CheckKind::Headers => {
                    ALL_CMS
                }
            },
            Self::Agent(family) => family.cms(),
            Self::Heartbeat | Self::Integrity | Self::Logs | Self::Typology => ALL_CMS,
        }
    }

    /// Condition d'existence, en plus du CMS.
    pub fn needs(self) -> Needs {
        match self {
            Self::Check(_) => Needs::Nothing,
            Self::Heartbeat | Self::Agent(_) => Needs::PhpAgent,
            Self::Integrity => Needs::PhpAgentAndBaseline,
            Self::Logs => Needs::LogSource,
            Self::Typology => Needs::AgentWithoutPhp,
        }
    }

    /// Le contrôle est-il surveillé pour ce site ?
    pub fn watched(self, site: &Site, ctx: &Ctx) -> bool {
        if !self.cms().contains(&site.kind) {
            return false;
        }
        let php = site.effective_runtime() == Some(Runtime::Php);
        match self.needs() {
            Needs::Nothing => true,
            Needs::PhpAgent => ctx.agent && php,
            Needs::PhpAgentAndBaseline => ctx.agent && php && ctx.baseline,
            Needs::LogSource => site.logs.as_ref().is_some_and(|l| l.source.is_some()),
            Needs::AgentWithoutPhp => ctx.agent && !php,
        }
    }

    /// Contrôle rapporté par l'agent (familles et intégrité, préfixe `agent:`).
    pub fn is_agent(self) -> bool {
        match self {
            Self::Integrity | Self::Agent(_) => true,
            Self::Check(_) | Self::Heartbeat | Self::Logs | Self::Typology => false,
        }
    }
}

impl fmt::Display for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Verdict unique « surveillé » d'un nom de contrôle pour un site : celui de
/// `tick` (`close_unwatched`), de l'ingestion (constats écartés,
/// `accept_report`) et de l'API (passages affichés). Un nom inconnu du
/// registre n'est jamais surveillé.
pub fn watched(site: &Site, check: &str, ctx: &Ctx) -> bool {
    Control::from_name(check).is_some_and(|control| control.watched(site, ctx))
}

/// Contrôles surveillés pour ce site, dans l'ordre de [`Control::ALL`].
pub fn allowed_controls(site: &Site, ctx: &Ctx) -> Vec<Control> {
    Control::ALL
        .into_iter()
        .filter(|control| control.watched(site, ctx))
        .collect()
}

/// Constat d'une famille de l'agent admis pour ce site ? Seulement les noms
/// `agent:<famille>` du registre, au verdict de [`watched`] pour un site
/// dont l'agent vient de signer : `agent:integrity` vient du veilleur.
pub fn admits_agent_finding(site: &Site, check: &str) -> bool {
    let ctx = Ctx {
        agent: true,
        baseline: false,
    };
    matches!(Control::from_name(check), Some(Control::Agent(_))) && watched(site, check, &ctx)
}

/// Constat `typology` du site : un avertissement tant qu'une clé d'agent est
/// enregistrée sur un site dont le runtime effectif n'est pas `php`, aucun
/// sinon.
pub fn typology_findings(site: &Site, ctx: &Ctx) -> Vec<Finding> {
    if !Control::Typology.watched(site, ctx) {
        return Vec::new();
    }
    vec![Finding::new(
        &site.id,
        TYPOLOGY,
        Severity::Warning,
        TYPOLOGY_KEY,
        "agent enregistré sur un site sans runtime php : déclarer runtime = \"php\"",
    )]
}

/// Commandes que le veilleur peut servir à un agent (#10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandKind {
    /// Aller-retour sans effet : prouve que le canal fonctionne.
    Ping,
    /// L'agent crée une nouvelle paire de clés de rapport et rend sa clé
    /// publique.
    RotateKey,
    /// Remplace le bloc `# BEGIN vigie` du `.htaccess` (#13).
    HtaccessApply,
    /// Remet le `.htaccess` précédent (#13).
    HtaccessRollback,
}

impl CommandKind {
    pub const ALL: [Self; 4] = [
        Self::Ping,
        Self::RotateKey,
        Self::HtaccessApply,
        Self::HtaccessRollback,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::RotateKey => "rotate-key",
            Self::HtaccessApply => "htaccess-apply",
            Self::HtaccessRollback => "htaccess-rollback",
        }
    }

    /// `None` pour un nom hors de la liste : fail-closed.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// Commande disponible dans ce binaire. `htaccess-*` le sont depuis #13,
    /// dans le même changement que la grammaire fermée vérifiée par l'agent
    /// (`recommend::htaccess`, `vigie-agent.php`) : un bloc `.htaccess` libre
    /// donnerait l'exécution de code sur le site.
    pub fn available(self) -> bool {
        match self {
            Self::Ping | Self::RotateKey | Self::HtaccessApply | Self::HtaccessRollback => true,
        }
    }

    /// Écriture qui ne se rejoue pas à l'aveugle : remettre en file après une
    /// issue inconnue exige `--force`.
    pub fn non_idempotent(self) -> bool {
        match self {
            Self::Ping => false,
            Self::RotateKey | Self::HtaccessApply | Self::HtaccessRollback => true,
        }
    }

    /// Runtimes qui admettent la commande. `match` sans joker : une variante
    /// nouvelle oblige à décider. Tant qu'aucun agent Node n'existe, aucune
    /// commande n'admet `node`.
    pub fn runtimes(self) -> &'static [Runtime] {
        match self {
            Self::Ping | Self::RotateKey => &[Runtime::Php],
            Self::HtaccessApply | Self::HtaccessRollback => &[Runtime::Php],
        }
    }
}

impl fmt::Display for CommandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Le site n'a pas de runtime : ni déclaré, ni impliqué par son CMS.
    NoRuntime,
    RuntimeNotAllowed {
        runtime: Runtime,
    },
    /// Commande de la liste, pas encore disponible dans ce binaire.
    Unavailable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuntime => f.write_str("le site n'a pas de runtime déclaré"),
            Self::RuntimeNotAllowed { runtime } => {
                write!(
                    f,
                    "commande non admise pour le runtime {}",
                    runtime.as_str()
                )
            }
            Self::Unavailable => f.write_str("commande pas encore disponible"),
        }
    }
}

/// La commande est-elle admise pour ce site ? À vérifier à la création et
/// de nouveau à la délivrance : la configuration a pu changer entre-temps.
pub fn permit(command: CommandKind, site: &Site) -> Result<(), Refusal> {
    let runtime = site.effective_runtime().ok_or(Refusal::NoRuntime)?;
    if !command.runtimes().contains(&runtime) {
        return Err(Refusal::RuntimeNotAllowed { runtime });
    }
    if !command.available() {
        return Err(Refusal::Unavailable);
    }
    Ok(())
}

/// Commandes admises pour ce site, dans l'ordre de [`CommandKind::ALL`].
pub fn allowed(site: &Site) -> Vec<CommandKind> {
    CommandKind::ALL
        .into_iter()
        .filter(|&command| permit(command, site).is_ok())
        .collect()
}
