//! Constats des contrôles. Un constat est identifié par une clé stable
//! `site/contrôle/clé` : c'est elle qui fait qu'un même problème vu sur
//! plusieurs passages reste un seul incident.

use std::fmt;

/// Ordonnée : une gravité qui monte renvoie l'e-mail d'ouverture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Montré dans `status`, jamais envoyé par e-mail.
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Libellé des e-mails et de `status`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "information",
            Self::Warning => "avertissement",
            Self::Critical => "critique",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub site: String,
    /// Nom d'un contrôle externe, `heartbeat`, ou `agent:<famille>` pour un
    /// constat rapporté par l'agent du site.
    pub check: String,
    pub severity: Severity,
    /// Stable d'un passage à l'autre : jamais d'heure ni de valeur mesurée.
    pub key: String,
    /// Peut changer d'un passage à l'autre (jours restants, code HTTP…).
    pub detail: String,
}

impl Finding {
    pub fn new(
        site: &str,
        check: impl Into<String>,
        severity: Severity,
        key: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            site: site.to_owned(),
            check: check.into(),
            severity,
            key: key.into(),
            detail: detail.into(),
        }
    }

    pub fn incident_key(&self) -> String {
        format!("{}/{}/{}", self.site, self.check, self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_ordered_and_round_trip() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
        for s in [Severity::Info, Severity::Warning, Severity::Critical] {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        assert_eq!(Severity::parse("grave"), None);
    }

    #[test]
    fn incident_key_joins_site_check_and_key() {
        let f = Finding::new("site-a", "exposed", Severity::Critical, ".env", "x");
        assert_eq!(f.incident_key(), "site-a/exposed/.env");
    }
}
