//! Générateurs à graine fixe des tests de versions (`vulns_versions.rs`,
//! `vulns_php_diff.rs`), inclus par `#[path]` : xorshift sans dépendance,
//! comme `logs/tests.rs`.

#![allow(dead_code)]

use vigie::vulns::version::{Scheme, parse};

pub struct XorShift(pub u64);

impl XorShift {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

/// Jetons et octets hostiles du fuzz d'analyse.
const FUZZ_TOKENS: [&str; 24] = [
    "0",
    "1",
    "10",
    ".",
    "-",
    "+",
    "_",
    "alpha",
    "ALPHA",
    "RC",
    "dev",
    "pl",
    "patch",
    "v",
    "x",
    "\0",
    "\u{1b}",
    "é",
    "\u{202e}",
    " ",
    "99999999999999999999",
    "*",
    "@",
    "\u{7f}",
];

/// Chaîne quelconque, valide ou non.
pub fn hostile(rng: &mut XorShift) -> String {
    let mut s = String::new();
    if rng.chance(2) {
        // Au-delà de 128 caractères.
        return "1.".repeat(65 + rng.below(10));
    }
    for _ in 0..rng.below(12) {
        s.push_str(rng.pick(&FUZZ_TOKENS));
    }
    s
}

const NUMS: [&str; 9] = ["0", "1", "2", "3", "9", "10", "11", "01", "123"];
const PHP_WORDS: [&str; 9] = ["dev", "alpha", "a", "beta", "b", "RC", "rc", "pl", "p"];
const SEPS: [&str; 5] = [".", ".", "-", "_", "+"];

fn semver_candidate(rng: &mut XorShift) -> String {
    let core = ["0", "1", "2", "10", "11"];
    let mut s = format!(
        "{}.{}.{}",
        rng.pick(&core),
        rng.pick(&core),
        rng.pick(&core)
    );
    if rng.chance(60) {
        let idents = [
            "0", "1", "2", "10", "11", "alpha", "beta", "rc", "x-y", "A", "a1",
        ];
        let n = 1 + rng.below(3);
        let pre: Vec<&str> = (0..n).map(|_| rng.pick(&idents)).collect();
        s.push('-');
        s.push_str(&pre.join("."));
    }
    if rng.chance(20) {
        s.push_str(rng.pick(&["+b", "+b.1", "+20260101", "+x-y"]));
    }
    s
}

fn php_candidate(rng: &mut XorShift) -> String {
    let mut s = rng.pick(&NUMS).to_owned();
    for _ in 0..rng.below(5) {
        let word = rng.chance(30);
        // Sans séparateur, la canonisation en insère un aux transitions.
        if rng.chance(70) || !word {
            s.push_str(rng.pick(&SEPS));
        }
        s.push_str(if word {
            rng.pick(&PHP_WORDS)
        } else {
            rng.pick(&NUMS)
        });
    }
    s
}

fn composer_candidate(rng: &mut XorShift) -> String {
    let mut s = String::new();
    if rng.chance(10) {
        s.push(if rng.chance(50) { 'v' } else { 'V' });
    }
    if rng.chance(8) {
        s.push_str(rng.pick(&["20260101", "2026-01-01", "201903", "20100102-203040"]));
    } else {
        s.push_str(rng.pick(&NUMS));
        for _ in 0..rng.below(4) {
            s.push('.');
            s.push_str(rng.pick(&NUMS));
        }
    }
    if rng.chance(50) {
        s.push_str(rng.pick(&["", "-", ".", "_"]));
        s.push_str(rng.pick(&[
            "alpha", "a", "beta", "b", "RC", "rc", "Rc", "patch", "pl", "p", "ALPHA", "stable",
        ]));
        if rng.chance(60) {
            s.push_str(rng.pick(&["1", "2", ".2", "-3", "10", ".1.2"]));
        }
    }
    if rng.chance(15) {
        s.push_str(rng.pick(&["-dev", ".dev", "dev", "-DEV"]));
    }
    if rng.chance(10) {
        s.push_str("+build.1");
    }
    s
}

/// Candidat de forme plausible pour `scheme` (pas toujours analysable).
pub fn candidate(rng: &mut XorShift, scheme: Scheme) -> String {
    match scheme {
        Scheme::Semver => semver_candidate(rng),
        Scheme::Php => php_candidate(rng),
        Scheme::Composer => composer_candidate(rng),
    }
}

/// `n` chaînes analysables par `scheme`.
pub fn pool(rng: &mut XorShift, scheme: Scheme, n: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let c = candidate(rng, scheme);
        if parse(scheme, &c).is_ok() {
            out.push(c);
        }
    }
    out
}
