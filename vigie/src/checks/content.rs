//! `content` : la page attendue répond 200 et contient le mot-clé. C'est la
//! reprise de la sonde UptimeRobot, qui reste en place comme second avis.

use url::Url;

use super::{CheckError, CheckKind, Ctx, UNREACHABLE};
use crate::config::Site;
use crate::finding::{Finding, Severity};
use crate::http::HttpError;

pub fn run(site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
    let name = CheckKind::Content.name();
    let url = Url::parse(site.content_url())
        .map_err(|err| CheckError::new(format!("URL illisible : {err}")))?;
    // Une erreur réseau isolée arrive : un second essai avant de crier.
    let page = match ctx.http.get(&url, true, ctx.deadline) {
        Ok(page) => page,
        Err(first) if !first.cut_short => match ctx.http.get(&url, true, ctx.deadline) {
            Ok(page) => page,
            Err(err) if err.cut_short => return Err(err.into()),
            Err(HttpError { message, .. }) => {
                return Ok(vec![Finding::new(
                    &site.id,
                    name,
                    Severity::Critical,
                    UNREACHABLE,
                    format!("injoignable : {message}"),
                )]);
            }
        },
        Err(first) => return Err(first.into()),
    };
    if page.status != 200 {
        return Ok(vec![Finding::new(
            &site.id,
            name,
            Severity::Critical,
            "status",
            format!("{} répond {}, 200 attendu", page.url, page.status),
        )]);
    }
    match &site.keyword {
        Some(keyword) if !page.body.contains(keyword.as_str()) => Ok(vec![Finding::new(
            &site.id,
            name,
            Severity::Critical,
            "keyword",
            format!("« {keyword} » absent de {}", page.url),
        )]),
        _ => Ok(Vec::new()),
    }
}
