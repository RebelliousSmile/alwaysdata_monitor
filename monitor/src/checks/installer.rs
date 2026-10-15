//! `installer` : un installeur servi permet à un inconnu de prendre le site
//! (base de son choix, compte administrateur). La réponse attendue est 403 ou
//! 404 ; sur un WordPress installé, `install.php` répond 200 « déjà installé »,
//! d'où la recherche du formulaire plutôt que du seul code.

use super::{CheckError, CheckKind, Ctx, same_as_witness, witness_path};
use crate::config::{Site, SiteKind};
use crate::finding::{Finding, Severity};

struct Probe {
    path: &'static str,
    signatures: &'static [&'static str],
}

const WORDPRESS: &[Probe] = &[
    Probe {
        path: "wp-admin/install.php",
        signatures: &[r#"id="setup""#, r#"name="weblog_title""#],
    },
    Probe {
        path: "wp-admin/setup-config.php",
        signatures: &[r#"name="dbname""#, "setup-config.php?step="],
    },
];

const PRESTASHOP: &[Probe] = &[Probe {
    path: "install/",
    signatures: &["PrestaShop"],
}];

pub fn run(site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
    let (probes, witness_prefix) = match site.kind {
        SiteKind::Wordpress => (WORDPRESS, "wp-admin/"),
        SiteKind::Prestashop => (PRESTASHOP, "install/"),
        SiteKind::Generic => return Ok(Vec::new()),
    };
    let base = site
        .base_url()
        .map_err(|err| CheckError::new(format!("URL illisible : {err}")))?;
    let join = |path: &str| {
        base.join(path)
            .map_err(|err| CheckError::new(format!("{path} : {err}")))
    };
    let witness = ctx
        .http
        .get(&join(&witness_path(witness_prefix))?, false, ctx.deadline)?;
    let mut findings = Vec::new();
    for probe in probes {
        let page = ctx.http.get(&join(probe.path)?, false, ctx.deadline)?;
        if page.status == 200
            && probe.signatures.iter().any(|s| page.body.contains(s))
            && !same_as_witness(&page, &witness)
        {
            findings.push(Finding::new(
                &site.id,
                CheckKind::Installer.name(),
                Severity::Critical,
                probe.path,
                format!(
                    "installeur ouvert : {} répond 200 avec son formulaire",
                    page.url
                ),
            ));
        }
    }
    Ok(findings)
}
