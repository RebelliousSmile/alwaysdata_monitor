//! Test différentiel des comparateurs PHP et Composer contre `version_compare`
//! de PHP (#15, phase 1).
//!
//! Hors de `cargo test` ordinaire : lancé par
//! `VIGIE_PHP="<commande php>" cargo test --test vulns_php_diff -- --ignored`.
//! En CI, la commande est le PHP 8.1 épinglé en Docker (`vigie.yml`), sous la
//! même forme que `VIGIE_E2E_PHP` ; le fichier des paires est écrit sous le
//! dossier temporaire (`/tmp`, monté dans le conteneur). Sans `VIGIE_PHP`, le
//! test rend tôt avec un message ; avec, il échoue au moindre écart en citant
//! la paire.
//!
//! Paires : vecteurs `wordpress` et `prestashop` ; formes normalisées des
//! vecteurs `composer` (Composer compare par `version_compare` après
//! `VersionParser::normalize`, dont les vecteurs sont dans `composer.json`) ;
//! 5 000 paires du fuzz dans le domaine accepté pour chacun des deux.

use std::cmp::Ordering;
use std::io::Write;
use std::process::Command;

use serde_json::Value;
use vigie::vulns::version::{Scheme, composer, parse};

#[path = "support/versions_fuzz.rs"]
mod versions_fuzz;
use versions_fuzz::{XorShift, pool};

/// Lit chaque ligne `a<TAB>b` et rend le signe de `version_compare(a, b)`.
const PHP_SCRIPT: &str = r#"$f = fopen($argv[1], "r");
while (($l = fgets($f)) !== false) {
    $p = explode("\t", rtrim($l, "\n"));
    echo version_compare($p[0], $p[1]), "\n";
}"#;

fn vector_pairs(name: &str) -> Vec<(String, String)> {
    let path = format!(
        "{}/tests/fixtures/versions/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["cmp"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["a"].as_str().unwrap().to_owned(),
                c["b"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// Paire, schéma de Vigie et chaînes passées à PHP.
struct Pair {
    scheme: Scheme,
    a: String,
    b: String,
    php_a: String,
    php_b: String,
}

fn pair(scheme: Scheme, a: &str, b: &str) -> Pair {
    let (php_a, php_b) = match scheme {
        Scheme::Composer => (
            composer::normalize(a).unwrap(),
            composer::normalize(b).unwrap(),
        ),
        _ => (a.to_owned(), b.to_owned()),
    };
    Pair {
        scheme,
        a: a.to_owned(),
        b: b.to_owned(),
        php_a,
        php_b,
    }
}

fn pairs() -> Vec<Pair> {
    let mut out = Vec::new();
    for name in ["wordpress.json", "prestashop.json"] {
        for (a, b) in vector_pairs(name) {
            out.push(pair(Scheme::Php, &a, &b));
        }
    }
    for (a, b) in vector_pairs("composer.json") {
        out.push(pair(Scheme::Composer, &a, &b));
    }
    for (seed, scheme) in [
        (0xd1ff_0000_0001_u64, Scheme::Php),
        (0xd1ff_0000_0002_u64, Scheme::Composer),
    ] {
        let mut rng = XorShift(seed);
        // Petit domaine : beaucoup de paires proches ou égales.
        let versions = pool(&mut rng, scheme, 600);
        for _ in 0..5_000 {
            let a = &versions[rng.below(versions.len())];
            let b = &versions[rng.below(versions.len())];
            out.push(pair(scheme, a, b));
        }
    }
    out
}

#[test]
#[ignore = "lancé avec VIGIE_PHP (voir l'en-tête)"]
fn version_compare_matches_php() {
    let Ok(command) = std::env::var("VIGIE_PHP") else {
        eprintln!("VIGIE_PHP absent : test différentiel non lancé");
        return;
    };
    let command: Vec<&str> = command.split_whitespace().collect();
    assert!(!command.is_empty(), "VIGIE_PHP vide");
    let pairs = pairs();
    let file = std::env::temp_dir().join(format!("vigie-php-diff-{}.tsv", std::process::id()));
    {
        let mut f = std::fs::File::create(&file).unwrap();
        for p in &pairs {
            writeln!(f, "{}\t{}", p.php_a, p.php_b).unwrap();
        }
    }
    let output = Command::new(command[0])
        .args(&command[1..])
        .arg("-r")
        .arg(PHP_SCRIPT)
        .arg(&file)
        .output()
        .unwrap_or_else(|e| panic!("lancement de VIGIE_PHP : {e}"));
    let _ = std::fs::remove_file(&file);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), pairs.len(), "une ligne par paire");
    for (p, line) in pairs.iter().zip(lines) {
        let php = match line {
            "-1" => Ordering::Less,
            "0" => Ordering::Equal,
            "1" => Ordering::Greater,
            other => panic!("sortie PHP {other:?}"),
        };
        let a = parse(p.scheme, &p.a).unwrap();
        let b = parse(p.scheme, &p.b).unwrap();
        assert_eq!(
            a.cmp(&b),
            php,
            "{} : {:?} ? {:?} (PHP : {:?} ? {:?})",
            p.scheme,
            p.a,
            p.b,
            p.php_a,
            p.php_b
        );
    }
}
