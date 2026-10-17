//! Test différentiel de l'écrivain zip des tests (`support/zipgen.rs`) et du
//! lecteur strict (`vulns/sync/zip.rs`) contre `zipfile` de Python (#16,
//! phase 1) : le générateur écrit de vrais zips, sinon le lecteur ne serait
//! testé que contre lui-même.
//!
//! Hors de `cargo test` ordinaire : lancé par
//! `VIGIE_PYTHON=python3 cargo test --test vulns_zip_diff -- --ignored`
//! (pas CI Linux). Python est lancé avec `-I` (isolé : ni variables
//! `PYTHON*`, ni dossier courant dans le chemin d'import), son script écrit
//! dans un dossier temporaire distinct de celui des zips. Sans
//! `VIGIE_PYTHON`, le test rend tôt avec un message ; avec, il échoue au
//! moindre écart de nom, de taille ou de CRC.

#[path = "support/zipgen.rs"]
mod zipgen;

use std::process::Command;
use std::time::Duration;

use vigie::vulns::sync::Limits;
use vigie::vulns::sync::zip::{Body, ZipReader};

use zipgen::{Spec, ZEntry, build, crc32};

/// Une ligne `nom<TAB>taille<TAB>crc` par entrée de chaque zip.
const PY_SCRIPT: &str = r#"import sys, zipfile
for path in sys.argv[1:]:
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            data = z.read(info)
            assert len(data) == info.file_size
            print("%s\t%d\t%d" % (info.filename, info.file_size, info.CRC))
    print("--")
"#;

fn healthy() -> Vec<Spec> {
    let mixed = vec![
        ZEntry::new(
            "GHSA-aaaa-bbbb-cccc.json",
            br#"{"id":"GHSA-aaaa-bbbb-cccc"}"#,
        ),
        ZEntry::stored("RUSTSEC-2026-0001.json", b"stocke tel quel"),
        ZEntry::new("vide.json", b""),
        ZEntry::new("gros.json", &vec![b'a'; 300_000]),
    ];
    vec![
        Spec {
            entries: mixed.clone(),
            ..Spec::default()
        },
        Spec {
            entries: mixed,
            zip64: true,
            ..Spec::default()
        },
        Spec {
            entries: (0..70_000)
                .map(|i| ZEntry::new(&format!("E-{i}.json"), format!("{i}").as_bytes()))
                .collect(),
            ..Spec::default()
        },
    ]
}

#[test]
#[ignore = "lancé avec VIGIE_PYTHON (voir l'en-tête)"]
fn zipgen_archives_read_identically_by_python() {
    let Ok(python) = std::env::var("VIGIE_PYTHON") else {
        eprintln!("VIGIE_PYTHON absent : test différentiel non lancé");
        return;
    };
    let python: Vec<&str> = python.split_whitespace().collect();
    assert!(!python.is_empty(), "VIGIE_PYTHON vide");
    let zips = tempfile::tempdir().expect("dossier des zips");
    let scripts = tempfile::tempdir().expect("dossier du script");
    let script = scripts.path().join("lire_zips.py");
    std::fs::write(&script, PY_SCRIPT).unwrap();
    let limits = Limits {
        compressed: 1 << 30,
        unpacked: 1 << 30,
        entries: 100_000,
        entry: 4 << 20,
        central_directory: 64 << 20,
        duration: Duration::from_secs(60),
        max_dropped_ratio: 0.01,
    };
    let mut expected = String::new();
    let mut paths = Vec::new();
    for (i, spec) in healthy().iter().enumerate() {
        let path = zips.path().join(format!("sain-{i}.zip"));
        std::fs::write(&path, build(spec).bytes).unwrap();
        let mut zip = ZipReader::open(&path, &limits).expect("lu par Vigie");
        for entry in zip.entries() {
            let entry = entry.expect("entrée lue par Vigie");
            let Body::Data(data) = entry.body else {
                panic!("{} sautée", entry.name);
            };
            expected.push_str(&format!(
                "{}\t{}\t{}\n",
                entry.name,
                data.len(),
                crc32(&data)
            ));
        }
        expected.push_str("--\n");
        paths.push(path);
    }
    let output = Command::new(python[0])
        .args(&python[1..])
        .arg("-I")
        .arg(&script)
        .args(&paths)
        .current_dir(scripts.path())
        .output()
        .unwrap_or_else(|e| panic!("lancement de VIGIE_PYTHON : {e}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let got = String::from_utf8(output.stdout).unwrap();
    assert_eq!(got.lines().count(), expected.lines().count());
    for (g, e) in got.lines().zip(expected.lines()) {
        assert_eq!(g, e);
    }
}
