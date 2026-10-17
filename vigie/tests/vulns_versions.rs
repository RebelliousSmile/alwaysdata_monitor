//! Comparateurs de versions par écosystème (#15, phase 1) : vecteurs JSON de
//! `tests/fixtures/versions/`, puis fuzz à graine fixe (aucune panique ;
//! ordre total sur les versions analysables).
//!
//! Format d'un fichier de vecteurs : `{"cmp": [{"a", "b", "order", "why"}],
//! "unparsable": [{"v", "why"}]}`, plus `"normalize": [{"in", "out", "why"}]`
//! pour Composer. Chaque `cmp` est vérifié dans les deux sens.

use std::cmp::Ordering;
use std::path::PathBuf;

use serde::Deserialize;
use vigie::vulns::version::{Bound, MAX_VERSION_CHARS, Scheme, composer, parse, parse_bound, php};

#[path = "support/versions_fuzz.rs"]
mod versions_fuzz;
use versions_fuzz::{XorShift, hostile, pool};

#[derive(Deserialize)]
struct Cmp {
    a: String,
    b: String,
    order: i8,
    why: String,
}

#[derive(Deserialize)]
struct Bad {
    v: String,
    why: String,
}

#[derive(Deserialize)]
struct Norm {
    #[serde(rename = "in")]
    input: String,
    out: Option<String>,
    why: String,
}

#[derive(Deserialize)]
struct Vectors {
    cmp: Vec<Cmp>,
    unparsable: Vec<Bad>,
    #[serde(default)]
    normalize: Vec<Norm>,
}

fn load(name: &str) -> Vectors {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/fixtures/versions", name]
        .iter()
        .collect();
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} : {e}"))
}

fn ordering(order: i8) -> Ordering {
    match order {
        -1 => Ordering::Less,
        0 => Ordering::Equal,
        1 => Ordering::Greater,
        other => panic!("ordre {other}"),
    }
}

fn check(name: &str, scheme: Scheme) -> Vectors {
    let vectors = load(name);
    assert!(!vectors.cmp.is_empty() && !vectors.unparsable.is_empty());
    for c in &vectors.cmp {
        let a = parse(scheme, &c.a).unwrap_or_else(|e| panic!("{name} {} : {e} ({})", c.a, c.why));
        let b = parse(scheme, &c.b).unwrap_or_else(|e| panic!("{name} {} : {e} ({})", c.b, c.why));
        let want = ordering(c.order);
        assert_eq!(a.cmp(&b), want, "{name} {} ? {} ({})", c.a, c.b, c.why);
        assert_eq!(
            b.cmp(&a),
            want.reverse(),
            "{name} {} ? {} ({})",
            c.b,
            c.a,
            c.why
        );
        assert_eq!(a == b, want == Ordering::Equal, "{name} {} == {}", c.a, c.b);
    }
    for bad in &vectors.unparsable {
        assert!(
            parse(scheme, &bad.v).is_err(),
            "{name} {:?} devrait être illisible ({})",
            bad.v,
            bad.why
        );
    }
    vectors
}

#[test]
fn composer_vectors() {
    let vectors = check("composer.json", Scheme::Composer);
    assert!(vectors.normalize.len() >= 40);
    for n in &vectors.normalize {
        assert_eq!(
            composer::normalize(&n.input).ok(),
            n.out,
            "normalize {:?} ({})",
            n.input,
            n.why
        );
    }
}

#[test]
fn npm_vectors() {
    check("npm.json", Scheme::Semver);
}

#[test]
fn cargo_vectors() {
    check("cargo.json", Scheme::Semver);
}

#[test]
fn wordpress_vectors() {
    check("wordpress.json", Scheme::Php);
}

#[test]
fn prestashop_vectors() {
    check("prestashop.json", Scheme::Php);
}

#[test]
fn the_floor_is_below_everything_and_zero_is_not_semver() {
    assert!(parse(Scheme::Semver, "0").is_err());
    for scheme in [Scheme::Semver, Scheme::Composer, Scheme::Php] {
        assert_eq!(parse_bound(scheme, "0"), Ok(Bound::Floor));
        let mut rng = XorShift(0x0f10_0123);
        for v in pool(&mut rng, scheme, 200) {
            assert!(
                Bound::Floor < Bound::At(parse(scheme, &v).unwrap()),
                "{scheme} {v}"
            );
        }
    }
}

#[test]
fn fuzz_never_panics() {
    let mut rng = XorShift(0x5eed_15f1_0000_0001);
    let mut parsed = 0;
    for _ in 0..200_000 {
        let s = hostile(&mut rng);
        for scheme in [Scheme::Semver, Scheme::Composer, Scheme::Php] {
            if let Ok(v) = parse(scheme, &s) {
                assert!(s.len() <= MAX_VERSION_CHARS);
                assert_eq!(v.as_str(), s);
                parsed += 1;
            }
        }
        let _ = php::canonize(&s);
        let _ = composer::normalize(&s);
    }
    // Le fuzz atteint aussi le domaine accepté.
    assert!(parsed > 1_000, "{parsed}");
}

#[test]
fn fuzz_order_is_total_on_parsable_versions() {
    for (seed, scheme) in [
        (0x5eed_15f1_0000_0002, Scheme::Semver),
        (0x5eed_15f1_0000_0003, Scheme::Composer),
        (0x5eed_15f1_0000_0004, Scheme::Php),
    ] {
        let mut rng = XorShift(seed);
        let versions: Vec<_> = pool(&mut rng, scheme, 1_500)
            .iter()
            .map(|s| parse(scheme, s).unwrap())
            .collect();
        let mut equal = 0;
        for _ in 0..100_000 {
            let a = &versions[rng.below(versions.len())];
            let b = &versions[rng.below(versions.len())];
            let c = &versions[rng.below(versions.len())];
            assert_eq!(a.cmp(a), Ordering::Equal, "réflexivité {a}");
            assert_eq!(a.cmp(b), b.cmp(a).reverse(), "antisymétrie {a} {b}");
            assert_eq!(a == b, a.cmp(b) == Ordering::Equal, "{a} == {b}");
            if a <= b && b <= c {
                assert!(a <= c, "transitivité {a} <= {b} <= {c}");
            }
            if a >= b && b >= c {
                assert!(a >= c, "transitivité {a} >= {b} >= {c}");
            }
            if a == b && a.as_str() != b.as_str() {
                equal += 1;
            }
        }
        // Des égalités entre chaînes différentes (01 = 1, a = alpha, build).
        assert!(equal > 0, "{scheme}");
    }
}
