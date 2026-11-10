//! Schéma du rapport d'agent, version 1 (`docs/protocole-agent.md`).
//!
//! Lu seulement après vérification de la signature : un corps non signé n'est
//! jamais analysé. Les messages d'erreur ne reprennent aucune valeur reçue,
//! pour que le journal ne contienne jamais le contenu d'un rapport.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::finding::{Finding, Severity};
use crate::store::AGENT_PREFIX;

pub const VERSION: u64 = 1;
pub const MAX_FINDINGS: usize = 100;
pub const MAX_FACTS: usize = 50;
pub const MAX_FILES: usize = 100;
/// Écart toléré entre `sent_at` et l'horloge du veilleur, en secondes.
pub const MAX_CLOCK_SKEW: i64 = 300;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub v: u64,
    pub site: String,
    pub seq: u64,
    pub sent_at: i64,
    pub agent: String,
    pub findings: Vec<ReportFinding>,
    pub facts: BTreeMap<String, serde_json::Value>,
    /// Empreintes SHA-256 des fichiers critiques, `null` pour un fichier
    /// absent. Facultatif : un agent qui ne l'envoie pas n'a pas de référence.
    #[serde(default)]
    pub files: Option<BTreeMap<String, Option<String>>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportFinding {
    pub check: String,
    pub severity: String,
    pub key: String,
    pub detail: String,
}

/// Rapport conforme au schéma.
#[derive(Debug, Clone)]
pub struct Valid {
    pub site: String,
    pub seq: i64,
    pub sent_at: i64,
    pub agent: String,
    /// Contrôles préfixés par `agent:`, de toute famille bien formée :
    /// l'ingestion écarte et compte ensuite celles que le registre des
    /// capacités n'admet pas pour le site (`ingest::screen`).
    pub findings: Vec<Finding>,
    /// Relevé, réencodé en JSON compact.
    pub facts: String,
    /// Empreintes des fichiers critiques, en JSON compact (`{}` si absentes).
    pub files: String,
}

/// Raison d'un refus de schéma, sans aucune valeur reçue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SchemaError(pub String);

fn err(reason: impl Into<String>) -> SchemaError {
    SchemaError(reason.into())
}

/// Aucun caractère de contrôle, retour à la ligne compris.
fn is_printable(value: &str, max_chars: usize) -> bool {
    let count = value.chars().count();
    (1..=max_chars).contains(&count) && !value.chars().any(char::is_control)
}

fn is_check_name(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// SHA-256 en 64 caractères hexadécimaux minuscules.
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_fact_key(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Analyse et valide un corps déjà authentifié pour le site `header_site`.
pub fn parse(body: &[u8], header_site: &str) -> Result<Valid, SchemaError> {
    let report: Report = serde_json::from_slice(body).map_err(|e| {
        err(format!(
            "JSON non conforme ({:?}, ligne {}, colonne {})",
            e.classify(),
            e.line(),
            e.column()
        ))
    })?;
    report.validate(header_site)
}

impl Report {
    pub fn validate(self, header_site: &str) -> Result<Valid, SchemaError> {
        if self.v != VERSION {
            return Err(err("version de protocole inconnue"));
        }
        if self.site != header_site {
            return Err(err("site du corps différent de X-Vigie-Site"));
        }
        let seq = i64::try_from(self.seq)
            .ok()
            .filter(|seq| *seq >= 1)
            .ok_or_else(|| err("seq hors de 1..=2^63-1"))?;
        if !is_printable(&self.agent, 64) {
            return Err(err("agent : 1 à 64 caractères imprimables"));
        }
        if self.findings.len() > MAX_FINDINGS {
            return Err(err(format!("plus de {MAX_FINDINGS} constats")));
        }
        if self.facts.len() > MAX_FACTS {
            return Err(err(format!("plus de {MAX_FACTS} entrées dans facts")));
        }
        for (i, (key, value)) in self.facts.iter().enumerate() {
            if !is_fact_key(key) {
                return Err(err(format!("facts : clé n° {} invalide", i + 1)));
            }
            let ok = match value {
                serde_json::Value::String(s) => s.chars().count() <= 256,
                serde_json::Value::Number(_)
                | serde_json::Value::Bool(_)
                | serde_json::Value::Null => true,
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => false,
            };
            if !ok {
                return Err(err(format!("facts : valeur n° {} invalide", i + 1)));
            }
        }
        let files = self.files.unwrap_or_default();
        if files.len() > MAX_FILES {
            return Err(err(format!("plus de {MAX_FILES} entrées dans files")));
        }
        for (i, (path, hash)) in files.iter().enumerate() {
            if !is_printable(path, 200) {
                return Err(err(format!("files : chemin n° {} invalide", i + 1)));
            }
            if hash.as_deref().is_some_and(|h| !is_sha256(h)) {
                return Err(err(format!("files : empreinte n° {} invalide", i + 1)));
            }
        }
        let mut findings = Vec::with_capacity(self.findings.len());
        for (i, f) in self.findings.iter().enumerate() {
            let n = i + 1;
            if !is_check_name(&f.check) {
                return Err(err(format!("constat n° {n} : check invalide")));
            }
            // Nom réservé au veilleur (`capability::Control::Integrity`) : tout
            // le rapport est refusé. Une famille inconnue, elle, n'est
            // qu'écartée à l'ingestion (`docs/decisions.md`, issue #4).
            if f.check == crate::facts::INTEGRITY {
                return Err(err(format!("constat n° {n} : check réservé au veilleur")));
            }
            let Some(severity) = Severity::parse(&f.severity) else {
                return Err(err(format!("constat n° {n} : severity invalide")));
            };
            if !is_printable(&f.key, 200) {
                return Err(err(format!("constat n° {n} : key invalide")));
            }
            if !is_printable(&f.detail, 300) {
                return Err(err(format!("constat n° {n} : detail invalide")));
            }
            findings.push(Finding::new(
                &self.site,
                format!("{AGENT_PREFIX}{}", f.check),
                severity,
                f.key.as_str(),
                f.detail.as_str(),
            ));
        }
        let facts = serde_json::to_string(&self.facts).map_err(|_| err("facts illisible"))?;
        let files = serde_json::to_string(&files).map_err(|_| err("files illisible"))?;
        Ok(Valid {
            site: self.site,
            seq,
            sent_at: self.sent_at,
            agent: self.agent,
            findings,
            facts,
            files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HASH: &str = "33bf0cf98fa40b5f4c44e053816b75487245c5fc01e66dd65470e2e70cbee0d8";

    fn body(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("json")
    }

    fn base() -> serde_json::Value {
        json!({
            "v": 1,
            "site": "site-a",
            "seq": 1,
            "sent_at": 1_792_079_580,
            "agent": "agent-php/0.1.0",
            "findings": [
                {"check": "php", "severity": "warning", "key": "display_errors", "detail": "activé"}
            ],
            "facts": {"php_version": "8.3.12", "wp_plugins": 12, "debug": false, "cms": null},
            "files": {".htaccess": HASH, "wp-config.php": null}
        })
    }

    #[test]
    fn accepts_a_valid_report_and_prefixes_its_checks() {
        let valid = parse(&body(base()), "site-a").expect("valide");
        assert_eq!(valid.seq, 1);
        assert_eq!(valid.findings.len(), 1);
        assert_eq!(valid.findings[0].check, "agent:php");
        assert_eq!(valid.findings[0].severity, Severity::Warning);
        assert_eq!(
            valid.findings[0].incident_key(),
            "site-a/agent:php/display_errors"
        );
        assert!(valid.facts.contains("\"php_version\":\"8.3.12\""));
        assert_eq!(
            valid.files,
            format!(r#"{{".htaccess":"{HASH}","wp-config.php":null}}"#)
        );
    }

    #[test]
    fn files_is_optional() {
        let mut value = base();
        value.as_object_mut().expect("objet").remove("files");
        let valid = parse(&body(value), "site-a").expect("valide");
        assert_eq!(valid.files, "{}");
    }

    fn refused(mutate: impl FnOnce(&mut serde_json::Value)) -> SchemaError {
        let mut value = base();
        mutate(&mut value);
        parse(&body(value), "site-a").expect_err("refusé")
    }

    #[test]
    fn refuses_every_rule_of_the_schema() {
        refused(|v| v["v"] = json!(2));
        refused(|v| v["site"] = json!("site-b"));
        refused(|v| v["seq"] = json!(0));
        refused(|v| v["seq"] = json!(u64::MAX));
        refused(|v| v["seq"] = json!(-1));
        refused(|v| v["agent"] = json!(""));
        refused(|v| v["agent"] = json!("a".repeat(65)));
        refused(|v| v["agent"] = json!("a\nb"));
        refused(|v| v["extra"] = json!(1));
        refused(|v| v["findings"][0]["extra"] = json!(1));
        refused(|v| v["findings"][0]["check"] = json!("PHP"));
        refused(|v| v["findings"][0]["check"] = json!("a".repeat(33)));
        refused(|v| v["findings"][0]["severity"] = json!("grave"));
        refused(|v| v["findings"][0]["key"] = json!(""));
        refused(|v| v["findings"][0]["key"] = json!("k".repeat(201)));
        refused(|v| v["findings"][0]["detail"] = json!("d\u{7}"));
        refused(|v| v["findings"][0]["detail"] = json!("d".repeat(301)));
        refused(|v| v["facts"] = json!({"Bad": 1}));
        refused(|v| v["facts"] = json!({"a": [1]}));
        refused(|v| v["facts"] = json!({"a": {"b": 1}}));
        refused(|v| v["facts"] = json!({"a": "x".repeat(257)}));
        refused(|v| {
            v["findings"] = json!(vec![v["findings"][0].clone(); MAX_FINDINGS + 1]);
        });
        refused(|v| {
            let facts: serde_json::Map<_, _> = (0..=MAX_FACTS)
                .map(|i| (format!("k{i}"), json!(i)))
                .collect();
            v["facts"] = serde_json::Value::Object(facts);
        });
        refused(|v| {
            v.as_object_mut().expect("objet").remove("facts");
        });
        refused(|v| v["findings"][0]["check"] = json!("integrity"));
        refused(|v| v["files"] = json!([HASH]));
        refused(|v| v["files"] = json!({"": HASH}));
        refused(|v| {
            v["files"] = json!({"a
b": HASH})
        });
        refused(|v| v["files"] = json!({"p".repeat(201): HASH}));
        refused(|v| v["files"] = json!({".htaccess": HASH.to_uppercase()}));
        refused(|v| v["files"] = json!({".htaccess": &HASH[1..]}));
        refused(|v| v["files"] = json!({".htaccess": format!("{}g", &HASH[1..])}));
        refused(|v| v["files"] = json!({".htaccess": 1}));
        refused(|v| {
            let files: serde_json::Map<_, _> = (0..=MAX_FILES)
                .map(|i| (format!("f{i}"), json!(HASH)))
                .collect();
            v["files"] = serde_json::Value::Object(files);
        });
    }

    #[test]
    fn accepts_the_limits() {
        let mut value = base();
        value["agent"] = json!("é".repeat(64));
        value["findings"][0]["key"] = json!("k".repeat(200));
        value["findings"][0]["detail"] = json!("d".repeat(300));
        value["findings"][0]["check"] = json!("a".repeat(32));
        value["facts"] = json!({"a": "x".repeat(256)});
        value["seq"] = json!(i64::MAX);
        value["files"] = json!({"p".repeat(200): HASH});
        parse(&body(value), "site-a").expect("limites acceptées");
    }

    #[test]
    fn errors_never_quote_the_body() {
        let secret = "SECRET-dans-le-corps";
        for raw in [
            format!(r#"{{"{secret}": 1}}"#),
            format!(r#"{{"v":1,"site":"{secret}"}}"#),
            "pas du json".to_owned(),
        ] {
            let e = parse(raw.as_bytes(), "site-a").expect_err("refusé");
            assert!(!e.to_string().contains(secret), "{e}");
        }
        let e = refused(|v| v["findings"][0]["severity"] = json!(secret));
        assert!(!e.to_string().contains(secret), "{e}");
    }
}
