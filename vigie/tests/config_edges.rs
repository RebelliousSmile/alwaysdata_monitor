//! `kind` et `runtime` aux limites (issue #4) : une valeur que la
//! configuration ne connaît pas est refusée au chargement, avant que `serve`
//! ou `tick` ne s'en servent. Ni repli sur `generic`, ni casse tolérée, ni
//! runtime qui contredit le CMS : le registre des capacités ne voit que des
//! valeurs fermées.

use std::path::Path;

use vigie::config::{self, ConfigError, Runtime, SiteKind};

const HEAD: &str = r#"
database = "/srv/vigie/vigie.db"

[alerts]
to = "alertes@example.org"
from = "vigie@example.org"
smtp_host = "smtp.example.org"
password_file = "/srv/vigie/smtp-password"

[[sites]]
id = "site-a"
url = "https://site-a.example.org/"
"#;

fn load(extra: &str) -> Result<config::Config, ConfigError> {
    config::parse(Path::new("config.toml"), &format!("{HEAD}{extra}"))
}

/// Refusée au chargement, en citant le champ fautif.
fn refused(extra: &str, field: &str) -> ConfigError {
    let err = load(extra).expect_err(extra);
    assert!(err.to_string().contains(field), "{extra:?} : {err}");
    err
}

#[test]
fn an_empty_miscased_or_unknown_kind_is_refused() {
    for value in [
        "\"\"",
        "\" \"",
        "\"WordPress\"",
        "\"WORDPRESS\"",
        "\"Generic\"",
        "\"wordpress \"",
        "\"joomla\"",
        "\"static\"",
        "\"php\"",
        "1",
        "true",
        "[\"wordpress\"]",
    ] {
        let err = refused(&format!("kind = {value}\n"), "kind");
        assert!(matches!(err, ConfigError::Parse { .. }), "{value} : {err}");
    }
}

#[test]
fn an_empty_miscased_or_unknown_runtime_is_refused() {
    for value in [
        "\"\"",
        "\"PHP\"",
        "\"Php\"",
        "\"php \"",
        "\"python\"",
        "\"wordpress\"",
        "\"none\"",
        "0",
    ] {
        let err = refused(&format!("runtime = {value}\n"), "runtime");
        assert!(matches!(err, ConfigError::Parse { .. }), "{value} : {err}");
    }
}

#[test]
fn a_runtime_that_contradicts_the_cms_is_refused() {
    for kind in ["wordpress", "prestashop"] {
        for runtime in ["node", "static"] {
            let err = refused(
                &format!("kind = \"{kind}\"\nruntime = \"{runtime}\"\n"),
                "implique php",
            );
            assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
            assert!(err.to_string().contains("« site-a »"), "{err}");
        }
    }
}

#[test]
fn the_admitted_values_load_with_their_effective_runtime() {
    let cases = [
        ("", SiteKind::Generic, None),
        ("kind = \"generic\"\n", SiteKind::Generic, None),
        ("runtime = \"php\"\n", SiteKind::Generic, Some(Runtime::Php)),
        (
            "runtime = \"node\"\n",
            SiteKind::Generic,
            Some(Runtime::Node),
        ),
        (
            "runtime = \"static\"\n",
            SiteKind::Generic,
            Some(Runtime::Static),
        ),
        (
            "kind = \"wordpress\"\n",
            SiteKind::Wordpress,
            Some(Runtime::Php),
        ),
        (
            "kind = \"wordpress\"\nruntime = \"php\"\n",
            SiteKind::Wordpress,
            Some(Runtime::Php),
        ),
        (
            "kind = \"prestashop\"\n",
            SiteKind::Prestashop,
            Some(Runtime::Php),
        ),
    ];
    for (extra, kind, runtime) in cases {
        let config = load(extra).expect(extra);
        assert_eq!(config.sites[0].kind, kind, "{extra:?}");
        assert_eq!(config.sites[0].effective_runtime(), runtime, "{extra:?}");
    }
}

#[test]
fn a_kind_or_runtime_key_outside_a_site_is_refused() {
    // Hors de `[[sites]]`, la clé est inconnue : refusée, jamais ignorée.
    let raw = format!("kind = \"wordpress\"\n{HEAD}");
    let err = config::parse(Path::new("config.toml"), &raw).expect_err("refusée");
    assert!(err.to_string().contains("kind"), "{err}");
    let err = refused("runtimes = \"php\"\n", "runtimes");
    assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
}
