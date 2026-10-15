//! `headers` : en-têtes de sécurité de la page d'accueil. Des constats
//! d'information, montrés dans `status`, jamais envoyés par e-mail.

use url::Url;

use super::{CheckError, CheckKind, Ctx};
use crate::config::Site;
use crate::finding::{Finding, Severity};

pub fn run(site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
    let url =
        Url::parse(&site.url).map_err(|err| CheckError::new(format!("URL illisible : {err}")))?;
    let page = ctx.http.get(&url, true, ctx.deadline)?;
    let mut findings = Vec::new();
    let mut missing = |key: &str, detail: &str| {
        findings.push(Finding::new(
            &site.id,
            CheckKind::Headers.name(),
            Severity::Info,
            key,
            detail,
        ));
    };
    if page.header("strict-transport-security").is_none() {
        missing("hsts", "Strict-Transport-Security absent");
    }
    if !page
        .header("x-content-type-options")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("nosniff"))
    {
        missing("nosniff", "X-Content-Type-Options: nosniff absent");
    }
    let frame_ancestors = page
        .header("content-security-policy")
        .is_some_and(|csp| csp.to_ascii_lowercase().contains("frame-ancestors"));
    if page.header("x-frame-options").is_none() && !frame_ancestors {
        missing("frame", "ni X-Frame-Options ni frame-ancestors dans la CSP");
    }
    Ok(findings)
}
