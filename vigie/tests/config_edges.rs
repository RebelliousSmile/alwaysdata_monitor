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

#[test]
fn an_inventory_source_needs_the_php_runtime() {
    let inventory = "[sites.inventory]\nsource = \"agent-php\"\n";
    for ok in [
        "kind = \"wordpress\"\n",
        "kind = \"prestashop\"\n",
        "runtime = \"php\"\n",
    ] {
        let config = load(&format!("{ok}{inventory}")).expect(ok);
        assert!(config.sites[0].inventory.is_some());
    }
    for refused_runtime in ["", "runtime = \"static\"\n", "runtime = \"node\"\n"] {
        let err = refused(&format!("{refused_runtime}{inventory}"), "inventory");
        assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
    }
    for value in ["\"agent\"", "\"Agent-Php\"", "\"agent_php\"", "1"] {
        let err = refused(
            &format!("kind = \"wordpress\"\n[sites.inventory]\nsource = {value}\n"),
            "source",
        );
        assert!(matches!(err, ConfigError::Parse { .. }), "{value} : {err}");
    }
    refused(
        "kind = \"wordpress\"\n[sites.inventory]\nsource = \"agent-php\"\nautre = 1\n",
        "autre",
    );
    refused("kind = \"wordpress\"\n[sites.inventory]\n", "source");
}

/// `[sites.inventory]` de #20 : `sources` (1 ou 2 valeurs distinctes) ou la
/// forme `source` de F5, jamais les deux ; seul `agent-php` exige le runtime
/// effectif `php`, `ci` est admis partout, runtime absent compris.
#[test]
fn inventory_sources_admit_ci_for_any_runtime() {
    use vigie::config::InventorySource::{AgentPhp, Ci};
    let kinds = ["", "kind = \"wordpress\"\n", "kind = \"prestashop\"\n"];
    let runtimes = [
        "",
        "runtime = \"php\"\n",
        "runtime = \"node\"\n",
        "runtime = \"static\"\n",
    ];
    let declared = [
        ("[\"agent-php\"]", vec![AgentPhp]),
        ("[\"ci\"]", vec![Ci]),
        ("[\"agent-php\", \"ci\"]", vec![AgentPhp, Ci]),
        ("[\"ci\", \"agent-php\"]", vec![Ci, AgentPhp]),
    ];
    for kind in kinds {
        for runtime in runtimes {
            let base = format!("{kind}{runtime}");
            // Combinaison refusée par la règle #4 (CMS PHP sans runtime php) :
            // hors sujet ici.
            let Ok(plain) = load(&base) else {
                continue;
            };
            let php = plain.sites[0].effective_runtime() == Some(Runtime::Php);
            for (value, sources) in &declared {
                let extra = format!("{base}[sites.inventory]\nsources = {value}\n");
                if sources.contains(&AgentPhp) && !php {
                    let err = refused(&extra, "exige le runtime php");
                    assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
                } else {
                    let config = load(&extra).expect(&extra);
                    assert_eq!(&config.sites[0].inventory_sources(), sources, "{extra}");
                }
            }
        }
    }
    // La forme de F5 reste lue comme une liste d'un élément.
    let config = load("kind = \"wordpress\"\n[sites.inventory]\nsource = \"agent-php\"\n")
        .expect("forme F5");
    assert_eq!(config.sites[0].inventory_sources(), [AgentPhp]);
    let config = load("runtime = \"static\"\n[sites.inventory]\nsource = \"ci\"\n").expect("ci");
    assert_eq!(config.sites[0].inventory_sources(), [Ci]);
    for (extra, field) in [
        (
            "kind = \"wordpress\"\n[sites.inventory]\nsource = \"agent-php\"\nsources = [\"ci\"]\n",
            "ensemble",
        ),
        ("[sites.inventory]\nsources = []\n", "une valeur au moins"),
        (
            "[sites.inventory]\nsources = [\"ci\", \"ci\"]\n",
            "en double",
        ),
        ("[sites.inventory]\nsources = [\"cd\"]\n", "sources"),
        ("[sites.inventory]\nsources = \"ci\"\n", "sources"),
    ] {
        refused(extra, field);
    }
}

#[test]
fn vulns_sources_are_a_closed_list_without_duplicates() {
    // Liste fermée (#16) : identifiant inconnu, doublon ou clé inconnue
    // refusés au chargement ; liste vide admise, comme l'absence de section.
    let err = refused(
        "[vulns]\nsources = [\"osv-npm\", \"osv-pypi\"]\n",
        "osv-pypi",
    );
    assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
    let err = refused(
        "[vulns]\nsources = [\"osv-npm\", \"osv-npm\"]\n",
        "deux fois",
    );
    assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
    let err = refused(
        "[vulns]\nsources = [\"osv-npm\"]\nurl = \"https://example.org/all.zip\"\n",
        "url",
    );
    assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    let config = load("[vulns]\nsources = []\n").expect("liste vide");
    assert!(vigie::vulns::sync::registry::declared(&config).is_empty());
    let config = load("[vulns]\nsources = [\"osv-npm\", \"osv-crates-io\"]\n").expect("admise");
    assert_eq!(
        vigie::vulns::sync::registry::declared(&config),
        ["osv-crates-io", "osv-npm"]
    );
    assert!(load("").expect("sans section").vulns.is_none());
}

#[test]
fn the_wordfence_section_goes_with_the_source() {
    // `wordfence` déclarée sans sa section, ou l'inverse : refusé.
    refused("[vulns]\nsources = [\"wordfence\"]\n", "[vulns.wordfence]");
    let section = "[vulns.wordfence]\ntoken_file = \"/home/vigie/vigie/keys/wordfence-token\"\nterms_reviewed = \"2099-01-01\"\n";
    refused(&format!("[vulns]\nsources = []\n{section}"), "sans effet");
    // Chemin relatif, date invalide, clé inconnue.
    refused(
        "[vulns]\nsources = [\"wordfence\"]\n[vulns.wordfence]\ntoken_file = \"keys/token\"\nterms_reviewed = \"2099-01-01\"\n",
        "chemin absolu",
    );
    refused(
        "[vulns]\nsources = [\"wordfence\"]\n[vulns.wordfence]\ntoken_file = \"/k/t\"\nterms_reviewed = \"2099-13-45\"\n",
        "AAAA-MM-JJ",
    );
    refused(
        "[vulns]\nsources = [\"wordfence\"]\n[vulns.wordfence]\ntoken_file = \"/k/t\"\nterms_reviewed = \"2099-01-01\"\nurl = \"x\"\n",
        "url",
    );
    // Section admise même si le binaire n'a pas consigné la relecture : le
    // refus vient de la source, la configuration reste valide.
    let config = load(&format!(
        "[vulns]\nsources = [\"wordfence\", \"friends-of-presta\"]\n{section}"
    ))
    .expect("admise");
    assert_eq!(
        vigie::vulns::sync::registry::declared(&config),
        ["friends-of-presta", "wordfence"]
    );
    assert_eq!(
        config.vulns.unwrap().wordfence.unwrap().terms_reviewed,
        "2099-01-01"
    );
}
