//! Registre des capacités : quelles commandes un site admet (issue #2).
//!
//! La liste des commandes est fermée et codée en dur : ajouter une commande
//! est un changement de code relu, jamais une valeur de configuration. Chaque
//! commande déclare les runtimes qui l'admettent ; un site sans runtime
//! (`generic` non déclaré) n'en admet aucune. Le runtime d'un site vient de
//! `config.toml`, jamais de l'agent (`docs/protocole-commandes.md`).
//!
//! Les contrôles déclarent de même les CMS auxquels ils s'appliquent
//! (`CheckKind::cms`).

use std::fmt;

use crate::config::{Runtime, Site};

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
        }
    }
}

/// La commande est-elle admise pour ce site ? À vérifier à la création et
/// de nouveau à la délivrance : la configuration a pu changer entre-temps.
pub fn permit(command: CommandKind, site: &Site) -> Result<(), Refusal> {
    let runtime = site.effective_runtime().ok_or(Refusal::NoRuntime)?;
    if command.runtimes().contains(&runtime) {
        Ok(())
    } else {
        Err(Refusal::RuntimeNotAllowed { runtime })
    }
}

/// Commandes admises pour ce site, dans l'ordre de [`CommandKind::ALL`].
pub fn allowed(site: &Site) -> Vec<CommandKind> {
    CommandKind::ALL
        .into_iter()
        .filter(|&command| permit(command, site).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SiteKind;

    fn site(kind: SiteKind, runtime: Option<Runtime>) -> Site {
        Site {
            id: "site-a".into(),
            url: "https://site-a.example.org/".into(),
            kind,
            runtime,
            keyword_url: None,
            keyword: None,
            interval: 300,
            agent_silence: 900,
        }
    }

    #[test]
    fn the_full_matrix_matches_the_literal_table() {
        use CommandKind::*;
        let generic = |runtime| site(SiteKind::Generic, runtime);
        // (commande, aucun, php, node, static)
        let table = [
            (Ping, false, true, false, false),
            (RotateKey, false, true, false, false),
            (HtaccessApply, false, true, false, false),
            (HtaccessRollback, false, true, false, false),
        ];
        assert_eq!(table.len(), CommandKind::ALL.len());
        for (command, none, php, node, stat) in table {
            for (runtime, expected) in [
                (None, none),
                (Some(Runtime::Php), php),
                (Some(Runtime::Node), node),
                (Some(Runtime::Static), stat),
            ] {
                assert_eq!(
                    permit(command, &generic(runtime)).is_ok(),
                    expected,
                    "{command} pour {runtime:?}"
                );
            }
        }
    }

    #[test]
    fn a_php_command_is_refused_for_static_and_node() {
        let php = site(SiteKind::Generic, Some(Runtime::Php));
        assert_eq!(permit(CommandKind::HtaccessApply, &php), Ok(()));
        for runtime in [Runtime::Static, Runtime::Node] {
            assert_eq!(
                permit(
                    CommandKind::HtaccessApply,
                    &site(SiteKind::Generic, Some(runtime))
                ),
                Err(Refusal::RuntimeNotAllowed { runtime })
            );
        }
        assert_eq!(
            permit(CommandKind::Ping, &site(SiteKind::Generic, None)),
            Err(Refusal::NoRuntime)
        );
        assert!(allowed(&site(SiteKind::Generic, None)).is_empty());
    }

    #[test]
    fn a_cms_implies_php() {
        for kind in [SiteKind::Wordpress, SiteKind::Prestashop] {
            assert_eq!(allowed(&site(kind, None)), CommandKind::ALL);
        }
    }

    #[test]
    fn names_round_trip_and_unknown_names_are_refused() {
        for command in CommandKind::ALL {
            assert_eq!(CommandKind::from_name(command.name()), Some(command));
        }
        for name in ["", "PING", "shell", "eval", "rotate_key", "ping "] {
            assert_eq!(CommandKind::from_name(name), None, "{name:?}");
        }
    }
}
