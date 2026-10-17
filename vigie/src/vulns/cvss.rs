//! Vecteurs CVSS : analyse stricte des versions 3.0, 3.1 et 4.0 ; score de
//! base calculé pour 3.0 et 3.1 seulement, par la formule de la
//! spécification 3.1 de FIRST (§7.1, `Roundup` de l'annexe A). Aucun score
//! n'est jamais calculé depuis un vecteur 4.0 (décision F0) : il est validé
//! et gardé.
//!
//! Limite : un vecteur 3.0 est calculé par la formule 3.1, dont l'arrondi
//! diffère de 3.0 dans de rares cas (au dixième).

/// Version d'un vecteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvssVersion {
    V30,
    V31,
    V40,
}

/// Vecteur validé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cvss {
    pub version: CvssVersion,
    /// Score de base en dixièmes (98 pour 9,8), pour 3.0 et 3.1 seulement.
    pub base_score: Option<u8>,
}

/// Longueur maximale d'un vecteur.
pub const MAX_VECTOR_CHARS: usize = 256;

const V3_BASE: [(&str, &[&str]); 8] = [
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "R"]),
    ("S", &["U", "C"]),
    ("C", &["H", "L", "N"]),
    ("I", &["H", "L", "N"]),
    ("A", &["H", "L", "N"]),
];

/// Métriques temporelles et environnementales 3.x : admises, ignorées.
const V3_OTHER: [(&str, &[&str]); 14] = [
    ("E", &["X", "H", "F", "P", "U"]),
    ("RL", &["X", "U", "W", "T", "O"]),
    ("RC", &["X", "C", "R", "U"]),
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "R"]),
    ("MS", &["X", "U", "C"]),
    ("MC", &["X", "H", "L", "N"]),
    ("MI", &["X", "H", "L", "N"]),
    ("MA", &["X", "H", "L", "N"]),
];

const V4_BASE: [(&str, &[&str]); 11] = [
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("AT", &["N", "P"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "P", "A"]),
    ("VC", &["H", "L", "N"]),
    ("VI", &["H", "L", "N"]),
    ("VA", &["H", "L", "N"]),
    ("SC", &["H", "L", "N"]),
    ("SI", &["H", "L", "N"]),
    ("SA", &["H", "L", "N"]),
];

const V4_OTHER: [(&str, &[&str]); 21] = [
    ("E", &["X", "A", "P", "U"]),
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MAT", &["X", "N", "P"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "P", "A"]),
    ("MVC", &["X", "H", "L", "N"]),
    ("MVI", &["X", "H", "L", "N"]),
    ("MVA", &["X", "H", "L", "N"]),
    ("MSC", &["X", "H", "L", "N"]),
    ("MSI", &["X", "S", "H", "L", "N"]),
    ("MSA", &["X", "S", "H", "L", "N"]),
    ("S", &["X", "N", "P"]),
    ("AU", &["X", "N", "Y"]),
    ("R", &["X", "A", "U", "I"]),
    ("V", &["X", "D", "C"]),
    ("RE", &["X", "L", "M", "H"]),
    ("U", &["X", "Clear", "Green", "Amber", "Red"]),
];

/// Lit les métriques `K:V` après le préfixe : chaque métrique connue une
/// fois, avec une valeur admise ; toutes les métriques de base présentes.
fn metrics<'a>(
    body: &'a str,
    base: &[(&str, &[&str])],
    other: &[(&str, &[&str])],
) -> Option<Vec<(&'a str, &'a str)>> {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for part in body.split('/') {
        let (k, v) = part.split_once(':')?;
        let allowed = base
            .iter()
            .chain(other)
            .find(|(key, _)| *key == k)
            .map(|(_, values)| *values)?;
        if !allowed.contains(&v) || seen.iter().any(|(key, _)| *key == k) {
            return None;
        }
        seen.push((k, v));
    }
    base.iter()
        .all(|(k, _)| seen.iter().any(|(key, _)| key == k))
        .then_some(seen)
}

/// Analyse stricte d'un vecteur ; `None` s'il est invalide.
pub fn parse(vector: &str) -> Option<Cvss> {
    if vector.len() > MAX_VECTOR_CHARS {
        return None;
    }
    if let Some(body) = vector.strip_prefix("CVSS:4.0/") {
        metrics(body, &V4_BASE, &V4_OTHER)?;
        return Some(Cvss {
            version: CvssVersion::V40,
            base_score: None,
        });
    }
    let (version, body) = if let Some(body) = vector.strip_prefix("CVSS:3.1/") {
        (CvssVersion::V31, body)
    } else if let Some(body) = vector.strip_prefix("CVSS:3.0/") {
        (CvssVersion::V30, body)
    } else {
        return None;
    };
    let m = metrics(body, &V3_BASE, &V3_OTHER)?;
    let get = |k: &str| {
        m.iter()
            .find(|(key, _)| *key == k)
            .map(|(_, v)| *v)
            .unwrap_or("")
    };
    Some(Cvss {
        version,
        base_score: Some(base_score_v31(get)),
    })
}

/// `Roundup` de l'annexe A de CVSS 3.1, en entiers : arrondi au dixième
/// supérieur, rendu en dixièmes. Les formules restent en virgule flottante
/// (poids décimaux de la spécification) ; l'arrondi, lui, passe par
/// l'entier `round(input × 100 000)` comme l'annexe le prescrit, et rien
/// d'autre que des dixièmes entiers ne sort de ce module.
fn roundup(input: f64) -> u8 {
    let int_input = (input * 100_000.0).round() as i64;
    let tenths = if int_input % 10_000 == 0 {
        int_input / 10_000
    } else {
        int_input / 10_000 + 1
    };
    tenths.clamp(0, 100) as u8
}

/// Score de base CVSS 3.1 (§7.1).
fn base_score_v31<'a>(get: impl Fn(&str) -> &'a str) -> u8 {
    let changed = get("S") == "C";
    let av = match get("AV") {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        _ => 0.2,
    };
    let ac = if get("AC") == "L" { 0.77 } else { 0.44 };
    let pr = match (get("PR"), changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        (_, false) => 0.27,
        (_, true) => 0.5,
    };
    let ui = if get("UI") == "N" { 0.85 } else { 0.62 };
    let cia = |k: &str| match get(k) {
        "H" => 0.56,
        "L" => 0.22,
        _ => 0.0,
    };
    let iss = 1.0 - (1.0 - cia("C")) * (1.0 - cia("I")) * (1.0 - cia("A"));
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return 0;
    }
    if changed {
        roundup((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup((impact + exploitability).min(10.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundup_follows_appendix_a() {
        assert_eq!(roundup(4.0), 40);
        assert_eq!(roundup(4.02), 41);
        assert_eq!(roundup(4.000_000_1), 40);
        assert_eq!(roundup(10.0), 100);
    }

    #[test]
    fn strictness() {
        assert_eq!(
            parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                .unwrap()
                .base_score,
            Some(98)
        );
        assert!(parse("CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_none());
        assert!(parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H").is_none());
        assert!(parse("CVSS:2.0/AV:N").is_none());
        assert_eq!(
            parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
                .unwrap()
                .base_score,
            None
        );
    }
}
