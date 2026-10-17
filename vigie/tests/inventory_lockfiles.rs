//! Lecture des lockfiles et construction du BOM de `vigie-inventory` (issue
//! #20, phase 2) : fixtures produites par les vrais outils
//! (`fixtures/inventory-tool/`, suffixées `.fixture` et copiées sous leur vrai
//! nom), composants attendus écrits à la main (`expected.json`), refus,
//! bornes, fuzz à graine fixe, parité avec l'agent PHP (F5) et vecteurs
//! communs `npm-alias.json`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use vigie::config::SiteKind;
use vigie::inventory::bom::{self, Envelope, RawComponent};
use vigie::inventory::build::{self, Cms, Document, Lockfile, Options, Stamp};
use vigie::inventory::lockfile::{self, Entry, Kind, LockError, Parsed, npm};
use vigie::inventory::{MAX_COMPONENTS, MAX_INVENTORY_BYTES};
use vigie::vulns::purl::PurlType;

/// 2026-10-17T12:00:00Z.
const T0: i64 = 1_792_238_400;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inventory-tool")
}

/// Copie un dossier de fixtures dans un dossier temporaire, chaque fichier
/// `X.fixture` sous son vrai nom `X`.
fn project(dir: &str) -> tempfile::TempDir {
    let out = tempfile::tempdir().expect("tempdir");
    for entry in std::fs::read_dir(fixtures().join(dir)).expect(dir) {
        let path = entry.expect("entrée").path();
        let name = path.file_name().and_then(|n| n.to_str()).expect("nom");
        let real = name.strip_suffix(".fixture").expect("suffixe .fixture");
        std::fs::copy(&path, out.path().join(real)).expect("copie");
    }
    out
}

/// Lockfiles connus à la racine d'un projet, triés par nom.
fn read_project(root: &Path) -> Vec<Lockfile> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .expect("projet")
        .map(|e| {
            e.expect("entrée")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| Kind::from_file_name(n).is_some())
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let kind = Kind::from_file_name(&name).expect("format");
            let text = lockfile::read_bounded(&root.join(&name)).expect("lecture");
            let parsed = lockfile::parse(kind, &text).unwrap_or_else(|e| panic!("{name} : {e}"));
            Lockfile { path: name, parsed }
        })
        .collect()
}

fn stamp(seq: i64) -> Stamp {
    Stamp {
        seq,
        sent_at: T0,
        serial: [seq as u8; 16],
    }
}

fn build(lockfiles: &[Lockfile], options: Options) -> Document {
    build::document("site-a", lockfiles, options, stamp(1)).expect("document")
}

/// Composant sous la forme d'`expected.json`.
fn summary(c: &RawComponent) -> Value {
    let property = |name: &str| {
        c.properties
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.value.clone())
            .expect(name)
    };
    json!({
        "purl": c.purl, "version": c.version, "scope": c.scope,
        "vigie:scope": property("vigie:scope"), "vigie:path": property("vigie:path"),
    })
}

fn expected() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(fixtures().join("expected.json")).expect("expected.json"),
    )
    .expect("json")
}

// --- Fixtures réelles --------------------------------------------------------

#[test]
fn each_fixture_gives_the_expected_components() {
    let expected = expected();
    for (case, want) in expected.as_object().expect("objet") {
        let dir = project(want["dir"].as_str().expect("dir"));
        let cms = match want["cms"].as_str() {
            Some("wordpress") => Some(Cms::Wordpress),
            None => None,
            Some(other) => panic!("{other}"),
        };
        let doc = build(
            &read_project(dir.path()),
            Options {
                cms,
                omit_dev: false,
            },
        );
        let got: Vec<Value> = doc.envelope.bom.components.iter().map(summary).collect();
        assert_eq!(&Value::Array(got), &want["components"], "{case}");
        let r = doc.report;
        assert_eq!(
            (r.offregistry, r.ignored, r.duplicates, r.invalid),
            (
                want["offregistry"].as_u64().expect("n") as usize,
                want["ignored"].as_u64().expect("n") as usize,
                want["duplicates"].as_u64().expect("n") as usize,
                want["invalid"].as_u64().expect("n") as usize,
            ),
            "{case}"
        );
        assert_eq!(
            Value::Bool(doc.envelope.complete),
            want["complete"],
            "{case}"
        );
        assert_eq!(
            doc.envelope.skipped as usize,
            r.offregistry + r.invalid,
            "{case}"
        );
    }
}

#[test]
fn npm_lockfile_versions_2_and_3_give_the_same_components() {
    let v2 = build(&read_project(project("npm-v2").path()), Options::default());
    let v3 = build(&read_project(project("npm-v3").path()), Options::default());
    assert_eq!(v2.envelope.bom.components, v3.envelope.bom.components);
    assert_eq!(v2.report, v3.report);
}

#[test]
fn no_fixture_carries_a_lockfile_name_and_every_case_is_expected() {
    let expected = expected();
    let dirs: BTreeSet<&str> = expected
        .as_object()
        .expect("objet")
        .values()
        .map(|v| v["dir"].as_str().expect("dir"))
        .collect();
    for entry in walk(&fixtures()) {
        let name = entry.file_name().and_then(|n| n.to_str()).expect("nom");
        assert!(
            Kind::from_file_name(name).is_none() && name != "package.json",
            "{name} : nom reconnu par GitHub, suffixer .fixture"
        );
        let parent = entry
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str());
        if name.ends_with(".fixture")
            && let Some(parent) = parent
            && !["two-lockfiles", "npm-and-yarn"].contains(&parent)
        {
            assert!(dirs.contains(parent), "{parent} sans attente");
        }
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("dossier") {
        let path = entry.expect("entrée").path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Question tranchée 5 : seulement les registres publics, les hôtes
/// wordpress.org des paquets WPackagist laissés tels que Composer les écrit,
/// la documentation de Composer (`_readme`, écrit par Composer) et
/// `example.org`.
#[test]
fn fixtures_only_name_public_registries_and_example_org() {
    let mut seen = BTreeSet::new();
    for path in walk(&fixtures()) {
        let text = std::fs::read_to_string(&path).expect("texte");
        for (i, _) in text.match_indices("://") {
            let start = text[..i]
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || "+.-".contains(c)))
                .map_or(0, |p| p + 1);
            let rest = &text[i + 3..];
            let end = rest
                .find(|c: char| " \"'\n,}]#?)".contains(c))
                .unwrap_or(rest.len());
            let url = &rest[..end];
            let (host, path_part) = url.split_once('/').unwrap_or((url, ""));
            let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
            let ok = match host {
                "registry.npmjs.org"
                | "registry.yarnpkg.com"
                | "index.crates.io"
                | "packagist.org"
                | "plugins.svn.wordpress.org"
                | "themes.svn.wordpress.org"
                | "downloads.wordpress.org" => true,
                "github.com" => path_part == "rust-lang/crates.io-index",
                "wordpress.org" => {
                    path_part.starts_with("plugins/") || path_part.starts_with("themes/")
                }
                "getcomposer.org" => path_part.starts_with("doc/"),
                h => h == "example.org" || h.ends_with(".example.org"),
            };
            assert!(ok, "{} : {}://{url}", path.display(), &text[start..i]);
            seen.insert(host.to_owned());
        }
    }
    assert!(seen.contains("registry.npmjs.org") && seen.contains("git.example.org"));
}

// --- Règles de lecture -----------------------------------------------------

/// Lockfile npm fabriqué : `packages` donnés en JSON.
fn npm_lock(packages: &str) -> String {
    format!(r#"{{"name": "exemple-app", "lockfileVersion": 3, "packages": {packages}}}"#)
}

fn one(entries: Vec<Entry>, path: &str) -> Vec<Lockfile> {
    vec![Lockfile {
        path: path.to_owned(),
        parsed: Parsed {
            entries,
            offregistry: 0,
            ignored: 0,
        },
    }]
}

fn cargo_entry(name: &str, version: &str) -> Entry {
    Entry {
        ecosystem: PurlType::Cargo,
        namespace: None,
        name: name.to_owned(),
        version: version.to_owned(),
        dev: false,
    }
}

#[test]
fn versions_out_of_grammar_are_dropped_never_truncated() {
    let long = "1".repeat(128);
    let doc = build(
        &one(
            vec![
                cargo_entry("garde", &long),
                cargo_entry("trop-long", &"1".repeat(129)),
                cargo_entry("tilde", "1.0.0~rc"),
                cargo_entry("espace", "1.0 .0"),
                cargo_entry("casse-Gardee", " 2.0.0 "),
            ],
            "Cargo.lock",
        ),
        Options::default(),
    );
    let got: Vec<(&str, &str)> = doc
        .envelope
        .bom
        .components
        .iter()
        .map(|c| (c.purl.as_str(), c.version.as_str()))
        .collect();
    let kept = format!("pkg:cargo/garde@{long}");
    assert_eq!(
        got,
        [
            (kept.as_str(), long.as_str()),
            ("pkg:cargo/trop-long", ""),
            ("pkg:cargo/tilde", ""),
            ("pkg:cargo/espace", ""),
            ("pkg:cargo/casse-Gardee@2.0.0", "2.0.0"),
        ]
    );
    assert!(doc.envelope.complete);
}

#[test]
fn names_out_of_grammar_are_skipped_and_counted() {
    let composer = format!(
        r#"{{"packages": [{{"name": "{}/x", "version": "1.0.0", "notification-url": "https://packagist.org/downloads/"}}]}}"#,
        "v".repeat(213)
    );
    let parsed = lockfile::parse(Kind::Composer, &composer).expect("composer");
    let mut lockfiles = vec![Lockfile {
        path: "composer.lock".to_owned(),
        parsed,
    }];
    lockfiles.extend(one(
        vec![
            Entry::npm("nom invalide", "1.0.0", false),
            cargo_entry("1chiffre", "1.0.0"),
            cargo_entry("bon", "1.0.0"),
        ],
        "Cargo.lock",
    ));
    let doc = build(&lockfiles, Options::default());
    assert_eq!(doc.report.invalid, 3);
    assert_eq!(doc.envelope.skipped, 3);
    assert!(!doc.envelope.complete);
    assert_eq!(doc.envelope.bom.components.len(), 1);
}

#[test]
fn composer_registry_packages_need_a_notification_url_or_wpackagist() {
    let lock = r#"{"packages": [
        {"name": "exemple/registre", "version": "1.0.0", "notification-url": "https://packagist.org/downloads/"},
        {"name": "exemple/chemin", "version": "1.0.0", "dist": {"type": "path", "url": "../chemin"}},
        {"name": "exemple/vcs", "version": "dev-main", "source": {"type": "git", "url": "https://git.example.org/exemple/vcs.git"}},
        {"name": "wpackagist-plugin/exemple-extension", "version": "2.0"},
        {"name": "Exemple/Majuscules", "version": "1.0.0", "notification-url": "https://packagist.org/downloads/"}
    ], "packages-dev": [
        {"name": "exemple/outil", "version": "v3.0.0", "notification-url": "https://packagist.org/downloads/"}
    ]}"#;
    let parsed = lockfile::parse(Kind::Composer, lock).expect("composer");
    assert_eq!((parsed.offregistry, parsed.entries.len()), (2, 4));
    let lockfiles = vec![Lockfile {
        path: "composer.lock".to_owned(),
        parsed,
    }];
    for (cms, plugin) in [
        (None, "pkg:composer/wpackagist-plugin/exemple-extension@2.0"),
        (
            Some(Cms::Wordpress),
            "pkg:wordpress/plugin/exemple-extension@2.0",
        ),
    ] {
        let doc = build(
            &lockfiles,
            Options {
                cms,
                omit_dev: false,
            },
        );
        let purls: Vec<&str> = doc
            .envelope
            .bom
            .components
            .iter()
            .map(|c| c.purl.as_str())
            .collect();
        assert_eq!(
            purls,
            [
                "pkg:composer/exemple/registre@1.0.0",
                plugin,
                "pkg:composer/exemple/majuscules@1.0.0",
                "pkg:composer/exemple/outil@v3.0.0",
            ]
        );
        assert_eq!(doc.envelope.skipped, 2);
        let dev = &doc.envelope.bom.components[3];
        assert_eq!(dev.scope, "excluded");
        assert_eq!(dev.properties[1].value, "dev");
    }
}

#[test]
fn wordpress_components_are_one_per_purl_without_version() {
    let lock = r#"{"packages": [
        {"name": "wpackagist-theme/exemple-theme", "version": "1.0"},
        {"name": "wpackagist-theme/exemple-theme", "version": "1.1"}
    ]}"#;
    let mut lockfiles = vec![Lockfile {
        path: "composer.lock".to_owned(),
        parsed: lockfile::parse(Kind::Composer, lock).expect("composer"),
    }];
    lockfiles.push(Lockfile {
        path: "app/composer.lock".to_owned(),
        parsed: lockfile::parse(Kind::Composer, lock).expect("composer"),
    });
    let doc = build(
        &lockfiles,
        Options {
            cms: Some(Cms::Wordpress),
            omit_dev: false,
        },
    );
    assert_eq!(doc.envelope.bom.components.len(), 1);
    assert_eq!(doc.report.duplicates, 3);
    // Sans --cms : paquets Composer, un par (purl, vigie:path).
    let doc = build(&lockfiles, Options::default());
    assert_eq!(doc.envelope.bom.components.len(), 4);
}

#[test]
fn a_package_in_two_lockfiles_is_two_components_but_one_per_lockfile() {
    let entries = vec![
        cargo_entry("itoa", "1.0.0"),
        cargo_entry("itoa", "1.0.0"),
        cargo_entry("itoa", "1.0.1"),
    ];
    let mut lockfiles = one(entries.clone(), "Cargo.lock");
    lockfiles.extend(one(entries, "outil/Cargo.lock"));
    let doc = build(&lockfiles, Options::default());
    let got: Vec<(String, String)> = doc
        .envelope
        .bom
        .components
        .iter()
        .map(|c| (c.purl.clone(), c.properties[0].value.clone()))
        .collect();
    assert_eq!(got.len(), 4);
    assert_eq!(doc.report.duplicates, 2);
}

#[test]
fn npm_alias_vectors_are_shared_with_the_php_agent() {
    let raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inventory/npm-alias.json"),
    )
    .expect("npm-alias.json");
    let vectors: Vec<Value> = serde_json::from_str(&raw).expect("json");
    assert!(vectors.len() >= 5);
    for v in vectors {
        let keys: BTreeSet<&str> = v
            .as_object()
            .expect("objet")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, BTreeSet::from(["key", "entry", "out", "why"]));
        let entry: npm::PackageEntry = serde_json::from_value(v["entry"].clone()).expect("entrée");
        let out = match npm::classify(v["key"].as_str().expect("key"), &entry) {
            npm::Verdict::Package(entry) => build::entry_purl(&entry, None).map(|p| p.canonical()),
            _ => None,
        };
        assert_eq!(
            out.as_deref(),
            v["out"].as_str(),
            "{}",
            v["why"].as_str().unwrap_or("")
        );
    }
}

#[test]
fn npm_members_extraneous_and_offregistry_entries() {
    // Texte brut : `json!` trierait les clés, l'ordre du fichier compte.
    let lock = npm_lock(
        r#"{
        "": {"name": "exemple-app"},
        "packages/espace": {"name": "espace", "version": "0.0.1"},
        "node_modules/espace": {"resolved": "packages/espace", "link": true},
        "node_modules/oublie": {"version": "1.0.0", "extraneous": true},
        "node_modules/git": {"version": "1.0.0", "resolved": "git+ssh://git@git.example.org/a.git#0123"},
        "node_modules/fichier": {"version": "1.0.0", "resolved": "file:../fichier"},
        "node_modules/archive": {"version": "1.0.0", "resolved": "https://files.example.org/a-1.0.0.tgz"},
        "node_modules/sans-resolved": {"version": "1.0.0"},
        "node_modules/facultatif": {"version": "1.0.0", "devOptional": true},
        "node_modules/outil": {"version": "1.0.0", "dev": true}
    }"#,
    );
    let parsed = lockfile::parse(Kind::Npm, &lock).expect("npm");
    assert_eq!((parsed.ignored, parsed.offregistry), (4, 3));
    let got: Vec<(&str, bool)> = parsed
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.dev))
        .collect();
    assert_eq!(
        got,
        [
            ("sans-resolved", false),
            ("facultatif", false),
            ("outil", true)
        ]
    );
}

// --- Refus -------------------------------------------------------------------

#[test]
fn unknown_versions_and_broken_files_are_refused_without_panic() {
    let cases: [(Kind, &str, LockError); 14] = [
        (
            Kind::Npm,
            r#"{"lockfileVersion": 1, "dependencies": {}}"#,
            LockError::UnsupportedVersion,
        ),
        (
            Kind::Npm,
            r#"{"packages": {}}"#,
            LockError::UnsupportedVersion,
        ),
        (Kind::Npm, "{\"lockfileVersion\": 3,", LockError::Unreadable),
        (Kind::Composer, "[1, 2]", LockError::Unreadable),
        (
            Kind::Pnpm,
            "lockfileVersion: '5.4'\n\npackages:\n",
            LockError::UnsupportedVersion,
        ),
        (
            Kind::Pnpm,
            "lockfileVersion: '9.0'\npackages:\n\t'a@1.0.0':\n",
            LockError::Structure { line: 3 },
        ),
        (
            Kind::Pnpm,
            "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: *alias\n",
            LockError::Structure { line: 4 },
        ),
        (
            Kind::Pnpm,
            "lockfileVersion: '9.0'\nsettings: {autoInstallPeers: true\npackages: {}\n",
            LockError::Structure { line: 2 },
        ),
        (
            Kind::Pnpm,
            "lockfileVersion: \"9\\q0\"\n",
            LockError::Structure { line: 1 },
        ),
        (
            Kind::Pnpm,
            "lockfileVersion: '9.0'\n---\npackages: {}\n",
            LockError::Structure { line: 2 },
        ),
        (
            Kind::Yarn,
            "__metadata:\n  version: 4\n  cacheKey: 8\n",
            LockError::UnsupportedVersion,
        ),
        (
            Kind::Yarn,
            "ms@^2.1.3:\n  version \"2.1.3\"\n# yarn lockfile v1\n",
            LockError::UnsupportedVersion,
        ),
        (
            Kind::Cargo,
            "[[package]]\nname = \"itoa\"\nversion = \"1.0.0\"\n",
            LockError::UnsupportedVersion,
        ),
        (
            Kind::Cargo,
            "version = 4\n[[package]\n",
            LockError::Unreadable,
        ),
    ];
    for (kind, text, want) in cases {
        assert_eq!(lockfile::parse(kind, text), Err(want), "{kind:?} {text:?}");
    }
}

#[test]
fn unread_blocks_may_hold_anything() {
    let pnpm = "lockfileVersion: '9.0'\n\nsettings:\n  &ancre: *alias\n  bloc: |\n    > texte\n\
                importers:\n  .:\n    dependencies: {a: [1, {b: '}'}]}\n\npackages:\n\n  \
                '@exemple/a@1.0.0':\n    resolution: {integrity: sha512-AAAA}\n    engines: {node: '>=12 <14 || >=16'}\n    \
                cpu: [arm64]\n    os: [darwin]\n    peerDependencies:\n      '*b': !tag x\n\n\
                snapshots:\n  '@exemple/a@1.0.0': {}\n";
    let parsed = lockfile::parse(Kind::Pnpm, pnpm).expect("pnpm");
    assert_eq!(parsed.entries, [Entry::npm("@exemple/a", "1.0.0", false)]);
    let berry = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"@esbuild/darwin-arm64@npm:0.24.0\":\n  \
                 version: 0.24.0\n  resolution: \"@esbuild/darwin-arm64@npm:0.24.0\"\n  conditions: os=darwin & cpu=arm64\n  \
                 bin:\n    a: '&b'\n  languageName: node\n  linkType: hard\n";
    let parsed = lockfile::parse(Kind::Yarn, berry).expect("berry");
    assert_eq!(
        parsed.entries,
        [Entry::npm("@esbuild/darwin-arm64", "0.24.0", false)]
    );
}

#[test]
fn errors_never_copy_bytes_of_the_file() {
    let secret = "secret-xyz";
    let texts = [
        format!("{{\"lockfileVersion\": 3, \"{secret}\": [}}"),
        format!("lockfileVersion: '9.0'\npackages:\n  {secret}:\n    resolution: {{{secret}\n"),
        format!("__metadata:\n  version: 8\n\"{secret}@npm:1\":\n  resolution: \"{secret}\\q\"\n"),
        format!("# yarn lockfile v1\n\n{secret}@^1:\n  version\n"),
        format!("version = 4\n[[package]]\nname = {secret}\n"),
    ];
    for kind in Kind::ALL {
        for text in &texts {
            if let Err(err) = lockfile::parse(kind, text) {
                assert!(!err.to_string().contains(secret), "{kind:?} : {err}");
                assert!(!format!("{err:?}").contains(secret), "{kind:?} : {err:?}");
            }
        }
    }
}

#[test]
fn files_lines_and_entries_are_bounded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let big = dir.path().join("composer.lock");
    let file = std::fs::File::create(&big).expect("fichier");
    file.set_len(lockfile::MAX_LOCKFILE_BYTES + 1)
        .expect("taille");
    assert_eq!(lockfile::read_bounded(&big), Err(LockError::TooLarge));
    let line = format!("version = 4\n# {}\n", "x".repeat(lockfile::MAX_LINE_BYTES));
    assert_eq!(
        lockfile::parse(Kind::Cargo, &line),
        Err(LockError::TooLarge)
    );
    let line = format!(
        "version = 4\n#{}\n",
        "x".repeat(lockfile::MAX_LINE_BYTES - 1)
    );
    assert!(lockfile::parse(Kind::Cargo, &line).is_ok());
    let mut many = String::from("# yarn lockfile v1\n\n");
    for i in 0..=lockfile::MAX_ENTRIES {
        many.push_str(&format!("p{i}@^1:\n  version \"1.0.0\"\n"));
    }
    assert_eq!(
        lockfile::parse(Kind::Yarn, &many),
        Err(LockError::TooManyEntries)
    );
}

// --- Fuzz -------------------------------------------------------------------

/// Générateur xorshift à graine fixe (forme de `logs/tests.rs`).
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Une mutation : octets retournés, ligne dupliquée, texte tronqué,
/// indentation changée, guillemet ouvert.
fn mutate(rng: &mut XorShift, text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    match rng.below(5) {
        0 => {
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(bytes.len());
                bytes[i] = rng.next() as u8;
            }
        }
        1 => {
            let lines: Vec<&str> = text.split('\n').collect();
            let i = rng.below(lines.len());
            let mut out = lines.clone();
            out.insert(i, lines[i]);
            return out.join("\n");
        }
        2 => bytes.truncate(rng.below(bytes.len())),
        3 => {
            let lines: Vec<String> = text
                .split('\n')
                .map(|l| {
                    if rng.below(8) == 0 {
                        format!("{}{l}", " ".repeat(rng.below(3)))
                    } else {
                        l.trim_start_matches(|c| c == ' ' && rng.below(4) == 0)
                            .to_owned()
                    }
                })
                .collect();
            return lines.join("\n");
        }
        _ => {
            let i = rng.below(bytes.len());
            bytes.insert(i, if rng.below(2) == 0 { b'"' } else { b'\'' });
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn readers_never_panic_on_mutated_lockfiles() {
    let cases = [
        (Kind::Composer, "composer/composer.lock.fixture"),
        (Kind::Npm, "npm-v3/package-lock.json.fixture"),
        (Kind::Pnpm, "pnpm-v6/pnpm-lock.yaml.fixture"),
        (Kind::Pnpm, "pnpm-v9/pnpm-lock.yaml.fixture"),
        (Kind::Yarn, "yarn-v1/yarn.lock.fixture"),
        (Kind::Yarn, "yarn-berry/yarn.lock.fixture"),
        (Kind::Cargo, "cargo/Cargo.lock.fixture"),
    ];
    for (n, (kind, file)) in cases.into_iter().enumerate() {
        let text = std::fs::read_to_string(fixtures().join(file)).expect(file);
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15 ^ n as u64);
        for round in 0..10_000 {
            let mutated = mutate(&mut rng, &text);
            let result = std::panic::catch_unwind(|| lockfile::parse(kind, &mutated));
            assert!(result.is_ok(), "{file} : panique au tour {round}");
        }
    }
}

// --- Ordre, troncature, complétude --------------------------------------------

fn many(prefix: &str, n: usize, dev: bool) -> Vec<Entry> {
    (0..n)
        .map(|i| Entry {
            dev,
            ..cargo_entry(&format!("{prefix}{i}"), "1.0.0")
        })
        .collect()
}

#[test]
fn truncation_removes_all_development_before_any_required_component() {
    let mut a = many("a-requis-", 900, false);
    a.extend(many("a-dev-", 400, true));
    let mut b = many("b-requis-", 600, false);
    b.extend(many("b-dev-", 101, true));
    let mut lockfiles = one(a, "Cargo.lock");
    lockfiles.extend(one(b, "outil/Cargo.lock"));
    let doc = build(&lockfiles, Options::default());
    let components = &doc.envelope.bom.components;
    assert_eq!(components.len(), MAX_COMPONENTS);
    assert_eq!(doc.report.truncated, 1);
    assert!(!doc.envelope.complete);
    let required = components.iter().filter(|c| c.scope == "required").count();
    assert_eq!(required, 1500);
    // Ordre global : requis de A, requis de B, dev de A, dev de B.
    assert!(components[899].name.starts_with("a-requis-"));
    assert!(components[900].name.starts_with("b-requis-"));
    assert!(components[1500].name.starts_with("a-dev-"));
    assert_eq!(components[1999].name, "b-dev-99");

    // Plus de 2 000 requis : tout le dev part d'abord, puis la fin des requis.
    let mut lockfiles = one(many("requis-", 2050, false), "Cargo.lock");
    lockfiles.extend(one(many("dev-", 10, true), "outil/Cargo.lock"));
    let doc = build(&lockfiles, Options::default());
    assert!(
        doc.envelope
            .bom
            .components
            .iter()
            .all(|c| c.scope == "required")
    );
    assert_eq!(doc.report.truncated, 60);
}

#[test]
fn the_envelope_stays_under_512_kib() {
    let long_version = "9".repeat(128);
    let entries: Vec<Entry> = (0..2000)
        .map(|i| cargo_entry(&format!("c{i:04}-{}", "n".repeat(58)), &long_version))
        .collect();
    let doc = build(&one(entries, "Cargo.lock"), Options::default());
    let size = serde_json::to_vec(&doc.envelope).expect("json").len();
    assert!(size <= MAX_INVENTORY_BYTES, "{size}");
    assert!(doc.report.truncated > 0);
    assert!(!doc.envelope.complete);
    // Retirés depuis la fin.
    assert_eq!(
        doc.envelope.bom.components.last().map(|c| c.name.as_str()),
        Some(format!("c{:04}-{}", doc.report.components - 1, "n".repeat(58)).as_str())
    );
}

#[test]
fn omit_dev_makes_the_document_incomplete_only_when_it_removes_something() {
    let mut entries = many("requis-", 2, false);
    entries.extend(many("dev-", 2, true));
    let omit = Options {
        cms: None,
        omit_dev: true,
    };
    let doc = build(&one(entries, "composer.lock"), omit);
    assert_eq!((doc.report.omitted, doc.envelope.complete), (2, false));
    assert_eq!(doc.envelope.bom.components.len(), 2);
    // yarn, pnpm 9, Cargo : aucune portée dev, --omit-dev sans effet.
    let doc = build(&one(many("requis-", 3, false), "Cargo.lock"), omit);
    assert_eq!((doc.report.omitted, doc.envelope.complete), (0, true));
}

// --- Document ----------------------------------------------------------------

/// Clés admises par la liste blanche, à chaque niveau.
fn assert_whitelisted(value: &Value, at: &str) {
    let allowed: &[&str] = match at {
        "envelope" => &[
            "v", "type", "site", "source", "seq", "sent_at", "agent", "complete", "skipped", "bom",
        ],
        "bom" => &[
            "bomFormat",
            "specVersion",
            "serialNumber",
            "metadata",
            "components",
        ],
        "metadata" => &["timestamp", "component"],
        "component" => &["type", "name"],
        "components" => &["type", "name", "version", "purl", "scope", "properties"],
        "properties" => &["name", "value"],
        other => panic!("{other}"),
    };
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                assert!(allowed.contains(&key.as_str()), "{at}.{key}");
                if matches!(child, Value::Object(_) | Value::Array(_)) {
                    assert_whitelisted(child, key);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_whitelisted(item, at);
            }
        }
        _ => {}
    }
}

#[test]
fn the_document_is_whitelisted_and_revalidated() {
    let lockfiles = read_project(project("composer").path());
    for cms in [None, Some(Cms::Wordpress)] {
        let doc = build(
            &lockfiles,
            Options {
                cms,
                omit_dev: false,
            },
        );
        let envelope = &doc.envelope;
        assert_eq!(envelope.bom.spec_version, "1.7");
        assert_eq!(envelope.agent, "vigie-inventory/0.1.0");
        let value = serde_json::to_value(envelope).expect("json");
        assert_eq!(value["source"], "ci");
        assert_whitelisted(&value, "envelope");
        build::validate_own(envelope, cms).expect("revalidé");
        let kind = Cms::site_kind(cms);
        let inventory = bom::parse(&serde_json::to_vec(envelope).expect("json"), "site-a", kind)
            .expect("liste blanche");
        assert_eq!(inventory.dropped_total(), 0);
    }
    // Un BOM wordpress revalidé comme un site generic : refusé.
    let doc = build(
        &lockfiles,
        Options {
            cms: Some(Cms::Wordpress),
            omit_dev: false,
        },
    );
    assert!(build::validate_own(&doc.envelope, None).is_err());
    // Un champ hors liste blanche : refusé.
    let mut value = serde_json::to_value(&doc.envelope).expect("json");
    value["bom"]["components"][0]["licenses"] = json!([]);
    assert!(serde_json::from_value::<Envelope>(value).is_err());
}

#[test]
fn two_builds_of_the_same_project_have_the_same_digest() {
    let lockfiles = read_project(project("npm-v3").path());
    let digest = |seq: i64| {
        let doc = build::document("site-a", &lockfiles, Options::default(), stamp(seq))
            .expect("document");
        let bytes = serde_json::to_vec(&doc.envelope).expect("json");
        (
            doc.envelope.bom.serial_number.clone(),
            bom::parse(&bytes, "site-a", SiteKind::Generic)
                .expect("liste blanche")
                .digest,
        )
    };
    let (serial_1, digest_1) = digest(1);
    let (serial_2, digest_2) = digest(2);
    assert_ne!(serial_1, serial_2);
    assert_eq!(digest_1, digest_2);
}

// --- Parité avec l'agent PHP (F5) ----------------------------------------------

/// Composants venus des lockfiles racine dans le relevé attendu de l'agent,
/// sans ceux que le relevé du disque remplace (même purl sans version).
fn agent_components() -> BTreeSet<(String, String, String, String)> {
    let raw = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("agent/php/tests/fixtures/inventory-expected.json"),
    )
    .expect("inventory-expected.json");
    let all: Value = serde_json::from_str(&raw).expect("json");
    all["wp-inventory"]["components"]
        .as_array()
        .expect("composants")
        .iter()
        .filter(|c| {
            matches!(
                c["vigie:path"].as_str(),
                Some("composer.lock" | "package-lock.json")
            )
        })
        .map(|c| {
            (
                c["purl"].as_str().expect("purl").to_owned(),
                c["version"].as_str().expect("version").to_owned(),
                c["scope"].as_str().expect("scope").to_owned(),
                c["vigie:scope"].as_str().expect("vigie:scope").to_owned(),
            )
        })
        .collect()
}

fn tool_components(root: &Path) -> BTreeSet<(String, String, String, String)> {
    let agent_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("agent/php/tests/fixtures/inventory-expected.json");
    let raw = std::fs::read_to_string(agent_root).expect("attendu");
    let all: Value = serde_json::from_str(&raw).expect("json");
    // purl sans version des composants relevés sur le disque par l'agent.
    let on_disk: BTreeSet<String> = all["wp-inventory"]["components"]
        .as_array()
        .expect("composants")
        .iter()
        .filter(|c| {
            !matches!(
                c["vigie:path"].as_str(),
                Some("composer.lock" | "package-lock.json" | "app/composer.lock")
            )
        })
        .map(|c| {
            c["purl"]
                .as_str()
                .expect("purl")
                .split('@')
                .next()
                .expect("base")
                .to_owned()
        })
        .collect();
    let lockfiles: Vec<Lockfile> = ["composer.lock", "package-lock.json"]
        .into_iter()
        .map(|name| {
            let text = lockfile::read_bounded(&root.join(name)).expect("lecture");
            Lockfile {
                path: name.to_owned(),
                parsed: lockfile::parse(Kind::from_file_name(name).expect("format"), &text)
                    .expect("lockfile"),
            }
        })
        .collect();
    let doc = build(
        &lockfiles,
        Options {
            cms: Some(Cms::Wordpress),
            omit_dev: false,
        },
    );
    doc.envelope
        .bom
        .components
        .iter()
        .filter(|c| !on_disk.contains(c.purl.split('@').next().expect("base")))
        .map(|c| {
            let s = summary(c);
            (
                c.purl.clone(),
                c.version.clone(),
                c.scope.clone(),
                s["vigie:scope"].as_str().expect("scope").to_owned(),
            )
        })
        .collect()
}

#[test]
fn the_tool_reads_the_agent_fixtures_like_the_agent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("agent/php/tests/fixtures/wp-inventory");
    let agent = agent_components();
    assert!(agent.len() >= 8, "{agent:?}");
    assert_eq!(tool_components(&root), agent);

    // Un écart volontaire (version modifiée dans une copie) fait échouer.
    let copy = tempfile::tempdir().expect("tempdir");
    for name in ["composer.lock", "package-lock.json"] {
        std::fs::copy(root.join(name), copy.path().join(name)).expect("copie");
    }
    let lock = copy.path().join("package-lock.json");
    let text = std::fs::read_to_string(&lock).expect("lecture");
    std::fs::write(
        &lock,
        text.replacen("\"version\": \"2.0.0\"", "\"version\": \"2.0.1\"", 1),
    )
    .expect("écriture");
    assert_ne!(tool_components(copy.path()), agent);
}

#[test]
fn npm_and_yarn_in_one_folder_need_a_choice() {
    let dir = project("npm-and-yarn");
    let mut found: Vec<String> = std::fs::read_dir(dir.path())
        .expect("projet")
        .map(|e| {
            e.expect("entrée")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    let err = lockfile::one_npm_lockfile_per_dir(&found, false).expect_err("refus");
    let message = err.to_string();
    assert!(
        message.contains("package-lock.json") && message.contains("yarn.lock"),
        "{message}"
    );
    assert!(message.contains("--lockfile"), "{message}");
    assert!(lockfile::one_npm_lockfile_per_dir(&found, true).is_err());
    let chosen = ["package-lock.json".to_owned()];
    assert!(lockfile::one_npm_lockfile_per_dir(&chosen, true).is_ok());
}

#[test]
fn two_lockfiles_list_every_required_component_before_any_dev() {
    let doc = build(
        &read_project(project("two-lockfiles").path()),
        Options::default(),
    );
    let got: Vec<(&str, &str)> = doc
        .envelope
        .bom
        .components
        .iter()
        .map(|c| (c.scope.as_str(), c.properties[0].value.as_str()))
        .collect();
    let first_dev = got.iter().position(|(s, _)| *s == "excluded").expect("dev");
    assert!(
        got[first_dev..].iter().all(|(s, _)| *s == "excluded"),
        "{got:?}"
    );
    // Dans chaque groupe, les lockfiles dans l'ordre reçu.
    assert_eq!(got[0].1, "composer.lock");
    assert_eq!(got[first_dev - 1].1, "package-lock.json");
    assert_eq!(
        got[first_dev..].iter().map(|(_, p)| *p).collect::<Vec<_>>(),
        ["composer.lock", "package-lock.json", "package-lock.json"]
    );
}
