//! Silence d'un agent : un site dont la clé est enregistrée et qui n'envoie
//! plus de rapport accepté est lui-même un signal. Évalué par `tick` à chaque
//! passage, sans requête ; le rapport accepté suivant clôt l'incident.

use crate::config::Site;
use crate::finding::{Finding, Severity};
use crate::store::Agent;

pub const NAME: &str = "heartbeat";
const KEY: &str = "silent";

pub fn evaluate(site: &Site, agent: &Agent, now: i64) -> Vec<Finding> {
    let silence = now - agent.last_sign_of_life();
    let threshold = i64::try_from(site.agent_silence).unwrap_or(i64::MAX);
    if silence <= threshold {
        return Vec::new();
    }
    let detail = match agent.last_valid_at {
        Some(_) => format!(
            "aucun rapport valide de l'agent depuis {}",
            crate::human_age(silence)
        ),
        None => format!(
            "aucun rapport valide de l'agent depuis l'enregistrement de sa clé, il y a {}",
            crate::human_age(silence)
        ),
    };
    vec![Finding::new(
        &site.id,
        NAME,
        Severity::Critical,
        KEY,
        detail,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SiteKind;

    fn site() -> Site {
        Site {
            id: "site-a".into(),
            url: "https://www.example.org/".into(),
            kind: SiteKind::Generic,
            runtime: None,
            keyword_url: None,
            keyword: None,
            interval: 300,
            agent_silence: 900,
            logs: None,
            inventory: None,
        }
    }

    fn agent(last_valid_at: Option<i64>) -> Agent {
        Agent {
            site: "site-a".into(),
            pubkey: [0; 32],
            added_at: 1_000,
            rotated_at: None,
            last_seq: 0,
            last_valid_at,
            agent: None,
        }
    }

    #[test]
    fn silent_beyond_the_threshold_only() {
        assert!(evaluate(&site(), &agent(None), 1_900).is_empty());
        let findings = evaluate(&site(), &agent(None), 1_901);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].incident_key(), "site-a/heartbeat/silent");
        assert!(findings[0].detail.contains("enregistrement"));

        assert!(evaluate(&site(), &agent(Some(5_000)), 5_900).is_empty());
        let findings = evaluate(&site(), &agent(Some(5_000)), 7_000);
        assert_eq!(
            findings[0].detail,
            "aucun rapport valide de l'agent depuis 33 min"
        );
    }
}
