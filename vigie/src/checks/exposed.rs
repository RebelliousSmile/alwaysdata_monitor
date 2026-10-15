//! `exposed` : fichiers qui n'auraient jamais dû être servis (secrets,
//! dépôt git, sauvegardes, dumps SQL). Un constat exige les trois : réponse
//! 200, signature du fichier, et un corps différent de celui du témoin.

use super::{CheckError, CheckKind, Ctx, same_as_witness, witness_path};
use crate::config::Site;
use crate::finding::{Finding, Severity};

type Signature = fn(&str) -> bool;

const PROBES: &[(&str, Signature)] = &[
    (".env", looks_like_env),
    (".git/HEAD", looks_like_git_head),
    ("wp-config.php.bak", looks_like_php_config),
    ("wp-config.php~", looks_like_php_config),
    ("backup.sql", looks_like_sql_dump),
    ("dump.sql", looks_like_sql_dump),
    ("database.sql", looks_like_sql_dump),
    ("db.sql", looks_like_sql_dump),
];

pub fn run(site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
    let base = site
        .base_url()
        .map_err(|err| CheckError::new(format!("URL illisible : {err}")))?;
    let join = |path: &str| {
        base.join(path)
            .map_err(|err| CheckError::new(format!("{path} : {err}")))
    };
    let witness = ctx
        .http
        .get(&join(&witness_path(""))?, false, ctx.deadline)?;
    let mut findings = Vec::new();
    for (path, signature) in PROBES {
        let page = ctx.http.get(&join(path)?, false, ctx.deadline)?;
        if page.status == 200 && signature(&page.body) && !same_as_witness(&page, &witness) {
            findings.push(Finding::new(
                &site.id,
                CheckKind::Exposed.name(),
                Severity::Critical,
                *path,
                format!("fichier exposé : {} est servi", page.url),
            ));
        }
    }
    Ok(findings)
}

/// Au moins une ligne `NOM=valeur`, nom en majuscules.
fn looks_like_env(body: &str) -> bool {
    body.lines().any(|line| {
        let Some((name, _)) = line.split_once('=') else {
            return false;
        };
        let mut bytes = name.bytes();
        matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
            && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    })
}

/// `ref: refs/heads/…`, ou une empreinte détachée de 40 caractères.
fn looks_like_git_head(body: &str) -> bool {
    let head = body.trim();
    head.starts_with("ref: ") || (head.len() == 40 && head.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn looks_like_php_config(body: &str) -> bool {
    body.contains("DB_PASSWORD") || body.contains("define(")
}

fn looks_like_sql_dump(body: &str) -> bool {
    body.contains("CREATE TABLE") || body.contains("INSERT INTO") || body.contains("-- MySQL dump")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_signatures() {
        assert!(looks_like_env("# commentaire\nAPP_KEY=base64:x\n"));
        assert!(!looks_like_env("<html>a=b</html>"));
        assert!(!looks_like_env("app_key=x"));
        assert!(looks_like_git_head("ref: refs/heads/main\n"));
        assert!(looks_like_git_head(&"a".repeat(40)));
        assert!(!looks_like_git_head("<!doctype html>"));
        assert!(looks_like_php_config("define( 'DB_PASSWORD', 'x' );"));
        assert!(looks_like_sql_dump("-- MySQL dump 10.13\n"));
        assert!(!looks_like_sql_dump("<html>404</html>"));
    }
}
