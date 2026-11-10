//! `custom` : les pages que l'exploitant a déclarées dans
//! `[[sites.custom_checks]]` (statut attendu, texte présent, texte absent).
//!
//! Un seul contrôle pour toutes les règles : les noms de contrôle sont figés
//! à la compilation (registre des capacités). Le constat d'une règle a pour
//! clé son `id`, stable d'un passage à l'autre ; son `detail` dit ce qui a
//! échoué.

use super::{CheckError, CheckKind, Ctx};
use crate::config::{CustomCheck, CustomSeverity, Site};
use crate::finding::{Finding, Severity};
use crate::http::{HttpError, Page};

pub fn run(site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
    let base = site
        .base_url()
        .map_err(|err| CheckError::new(format!("URL illisible : {err}")))?;
    let mut findings = Vec::new();
    for rule in &site.custom_checks {
        // `path` commence par `/` (validé à la lecture de la configuration) :
        // la jointure ne quitte jamais l'origine du site.
        let url = base
            .join(&rule.path)
            .map_err(|err| CheckError::new(format!("règle « {} » : {err}", rule.id)))?;
        // Une erreur réseau isolée arrive : un second essai avant de crier.
        let fetched = match ctx.http.get(&url, true, ctx.deadline) {
            Err(first) if !first.cut_short => ctx.http.get(&url, true, ctx.deadline),
            other => other,
        };
        match fetched {
            Ok(page) => findings.extend(evaluate(&site.id, rule, &page)),
            Err(err) if err.cut_short => return Err(err.into()),
            Err(HttpError { message, .. }) => findings.push(finding(
                &site.id,
                rule,
                format!("{} injoignable : {message}", rule.path),
            )),
        }
    }
    Ok(findings)
}

/// Premier écart entre la page et la règle, ou rien si elle est conforme.
fn evaluate(site: &str, rule: &CustomCheck, page: &Page) -> Option<Finding> {
    let detail = if page.status != rule.status {
        format!(
            "{} répond {}, {} attendu",
            page.url, page.status, rule.status
        )
    } else if let Some(text) = rule.contains.as_deref().filter(|t| !page.body.contains(t)) {
        format!("« {text} » absent de {}", page.url)
    } else if let Some(text) = rule.absent.as_deref().filter(|t| page.body.contains(t)) {
        format!("« {text} » présent dans {}", page.url)
    } else {
        return None;
    };
    Some(finding(site, rule, detail))
}

fn finding(site: &str, rule: &CustomCheck, detail: String) -> Finding {
    let severity = match rule.severity {
        CustomSeverity::Warning => Severity::Warning,
        CustomSeverity::Critical => Severity::Critical,
    };
    Finding::new(site, CheckKind::Custom.name(), severity, &rule.id, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, status: u16, contains: Option<&str>, absent: Option<&str>) -> CustomCheck {
        CustomCheck {
            id: id.into(),
            path: "/panier".into(),
            status,
            contains: contains.map(Into::into),
            absent: absent.map(Into::into),
            severity: CustomSeverity::Warning,
        }
    }

    fn page(status: u16, body: &str) -> Page {
        Page {
            url: url::Url::parse("https://site-a.example.org/panier").expect("url"),
            status,
            headers: ureq::http::HeaderMap::new(),
            body: body.into(),
        }
    }

    #[test]
    fn a_conforming_page_gives_no_finding() {
        let r = rule("panier", 200, Some("Votre panier"), Some("Fatal error"));
        assert_eq!(evaluate("a", &r, &page(200, "<h1>Votre panier</h1>")), None);
    }

    #[test]
    fn the_status_is_checked_first() {
        let r = rule("panier", 200, Some("Votre panier"), None);
        let f = evaluate("a", &r, &page(503, "Votre panier")).expect("écart");
        assert_eq!(f.key, "panier");
        assert!(f.detail.contains("répond 503, 200 attendu"), "{}", f.detail);
    }

    #[test]
    fn a_missing_text_is_reported() {
        let r = rule("panier", 200, Some("Votre panier"), None);
        let f = evaluate("a", &r, &page(200, "Erreur")).expect("écart");
        assert!(f.detail.contains("« Votre panier » absent"), "{}", f.detail);
    }

    #[test]
    fn a_forbidden_text_is_reported() {
        let r = rule("panier", 200, None, Some("Fatal error"));
        let f = evaluate("a", &r, &page(200, "x Fatal error y")).expect("écart");
        assert!(f.detail.contains("« Fatal error » présent"), "{}", f.detail);
    }

    #[test]
    fn a_non_200_status_can_be_the_expected_one() {
        let r = rule("legacy", 404, None, None);
        assert_eq!(evaluate("a", &r, &page(404, "")), None);
        assert!(evaluate("a", &r, &page(200, "")).is_some());
    }

    #[test]
    fn the_severity_follows_the_rule() {
        let mut r = rule("panier", 200, None, None);
        assert_eq!(finding("a", &r, "x".into()).severity, Severity::Warning);
        r.severity = CustomSeverity::Critical;
        assert_eq!(finding("a", &r, "x".into()).severity, Severity::Critical);
    }
}
