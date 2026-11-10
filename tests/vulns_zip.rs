//! Lecteur zip strict des dumps (`vulns/sync/zip.rs`) : zips sains, entrées
//! sautées et comptées, dumps refusés, fuzz à graine fixe. Tous les zips
//! sont produits par `support/zipgen.rs` ; aucun binaire hostile commité.

#[path = "support/zipgen.rs"]
mod zipgen;

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::Duration;

use vigie::vulns::Reason;
use vigie::vulns::sync::zip::{Body, Entry, ZipReader};
use vigie::vulns::sync::{Limits, SyncError};

use zipgen::{Built, Spec, ZEntry, build, crc32, put_u16, put_u32, put_u64, zip_of};

const MIB: u64 = 1024 * 1024;

fn limits() -> Limits {
    Limits {
        compressed: 64 * MIB,
        unpacked: 64 * MIB,
        entries: 100_000,
        entry: 4 * MIB,
        central_directory: 16 * MIB,
        duration: Duration::from_secs(60),
        max_dropped_ratio: 0.01,
    }
}

fn write(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("dump.zip");
    std::fs::write(&path, bytes).expect("écriture");
    path
}

fn read_all(bytes: &[u8], limits: &Limits) -> Result<Vec<Entry>, SyncError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), bytes);
    let mut zip = ZipReader::open(&path, limits)?;
    zip.entries().collect()
}

fn refused(bytes: &[u8]) -> SyncError {
    read_all(bytes, &limits()).expect_err("dump refusé")
}

fn three() -> Vec<ZEntry> {
    vec![
        ZEntry::new(
            "GHSA-aaaa-bbbb-cccc.json",
            br#"{"id":"GHSA-aaaa-bbbb-cccc"}"#,
        ),
        ZEntry::new("RUSTSEC-2026-0001.json", &[b'x'; 5000]),
        ZEntry::new("MAL-2026-1.json", b"{}"),
    ]
}

fn spec(entries: Vec<ZEntry>) -> Spec {
    Spec {
        entries,
        ..Spec::default()
    }
}

// --- Zip sain ---

#[test]
fn three_deflate_entries_are_read_exactly() {
    let entries = read_all(&zip_of(three()), &limits()).expect("lu");
    assert_eq!(entries.len(), 3);
    for (got, want) in entries.iter().zip(three()) {
        assert_eq!(got.name.as_bytes(), want.name.as_slice());
        assert_eq!(got.body, Body::Data(want.data.clone()));
    }
}

#[test]
fn seventy_thousand_entries_with_zip64_end() {
    let entries: Vec<ZEntry> = (0..70_000)
        .map(|i| ZEntry::stored(&format!("E-{i}.json"), format!("{i}").as_bytes()))
        .collect();
    let built = build(&spec(entries));
    assert!(built.locator.is_some(), "fin ZIP64 attendue");
    let read = read_all(&built.bytes, &limits()).expect("lu");
    assert_eq!(read.len(), 70_000);
    for (i, e) in read.iter().enumerate() {
        assert_eq!(e.name, format!("E-{i}.json"));
        assert_eq!(e.body, Body::Data(format!("{i}").into_bytes()));
    }
}

#[test]
fn zip64_end_on_request_and_stored_entry() {
    let built = build(&Spec {
        entries: vec![ZEntry::stored("a.json", b"stocke")],
        zip64: true,
        ..Spec::default()
    });
    let read = read_all(&built.bytes, &limits()).expect("lu");
    assert_eq!(read[0].body, Body::Data(b"stocke".to_vec()));
}

#[test]
fn declared_unpacked_is_exposed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), &zip_of(three()));
    let zip = ZipReader::open(&path, &limits()).expect("ouvert");
    let sum: u64 = three().iter().map(|e| e.data.len() as u64).sum();
    assert_eq!(zip.declared_unpacked(), sum);
    assert_eq!(zip.len(), 3);
}

// --- Entrée sautée et comptée ---

#[test]
fn entry_declared_above_the_bound_is_skipped_undecompressed() {
    // Taille déclarée de 5 Mio, données réelles minuscules et invalides :
    // l'entrée n'est jamais décompressée.
    let mut big = ZEntry::new("GROS-1.json", b"{}");
    big.unpacked = Some(5 * MIB as u32);
    big.raw = Some(vec![0xFF; 16]);
    let read = read_all(&zip_of(vec![big, ZEntry::new("ok.json", b"1")]), &limits()).expect("lu");
    assert_eq!(read[0].body, Body::Skipped(Reason::TooLarge));
    assert_eq!(read[1].body, Body::Data(b"1".to_vec()));
}

#[test]
fn bad_names_are_skipped_and_never_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let names = [
        "../../x.json",
        "/etc/x.json",
        "a/b.json",
        "x.txt",
        "dossier/",
    ];
    let entries: Vec<ZEntry> = names.iter().map(|n| ZEntry::new(n, b"{}")).collect();
    let path = write(dir.path(), &zip_of(entries));
    let mut zip = ZipReader::open(&path, &limits()).expect("ouvert");
    let read: Vec<Entry> = zip.entries().collect::<Result<_, _>>().expect("lu");
    assert_eq!(read.len(), names.len());
    for e in &read {
        assert_eq!(e.body, Body::Skipped(Reason::BadEntryName), "{}", e.name);
    }
    // Seul le dump est dans le dossier ; rien autour.
    let listed: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(listed.len(), 1);
    assert!(!dir.path().join("x.json").exists());
    assert!(!dir.path().parent().unwrap().join("x.json").exists());
}

// --- Dump refusé ---

#[test]
fn declared_total_above_the_bound_is_refused_before_decompression() {
    let mut a = ZEntry::new("a.json", b"{}");
    a.unpacked = Some(3 * MIB as u32);
    a.raw = Some(vec![0xFF; 4]);
    let mut b = a.clone();
    b.name = b"b.json".to_vec();
    let small = Limits {
        unpacked: 4 * MIB,
        ..limits()
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write(dir.path(), &zip_of(vec![a, b]));
    assert_eq!(
        ZipReader::open(&path, &small).err(),
        Some(SyncError::TooLarge {
            what: "taille décompressée déclarée"
        })
    );
}

#[test]
fn lying_bomb_produces_at_most_declared_plus_one() {
    // Déclare 10 octets, décompresse 1 Mio.
    let mut e = ZEntry::new("bombe.json", &vec![b'0'; MIB as usize]);
    e.unpacked = Some(10);
    let err = refused(&zip_of(vec![e]));
    assert_eq!(
        err,
        SyncError::Zip("longueur réelle différente de la taille déclarée")
    );
}

#[test]
fn overlapping_local_records_are_refused() {
    let built = build(&Spec {
        entries: vec![ZEntry::new("a.json", b"{}"), ZEntry::new("b.json", b"[]")],
        duplicate_central: vec![0],
        ..Spec::default()
    });
    assert_eq!(
        refused(&built.bytes),
        SyncError::Zip("entrées locales qui se recouvrent")
    );
}

#[test]
fn wrong_crc_corrupt_stream_or_short_length_are_refused() {
    let mut bad_crc = ZEntry::new("a.json", b"{}");
    bad_crc.crc = Some(crc32(b"{}") ^ 1);
    assert_eq!(refused(&zip_of(vec![bad_crc])), SyncError::Zip("CRC faux"));

    let mut corrupt = ZEntry::new("a.json", b"{}");
    corrupt.raw = Some(vec![0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(matches!(refused(&zip_of(vec![corrupt])), SyncError::Zip(_)));

    let mut short = ZEntry::new("a.json", b"0123456789");
    short.unpacked = Some(20);
    assert_eq!(
        refused(&zip_of(vec![short])),
        SyncError::Zip("longueur réelle différente de la taille déclarée")
    );
}

#[test]
fn stored_entry_with_different_sizes_is_refused() {
    let mut e = ZEntry::stored("a.json", b"0123");
    e.unpacked = Some(8);
    assert_eq!(
        refused(&zip_of(vec![e])),
        SyncError::Zip("entrée stockée de tailles différentes")
    );
}

#[test]
fn method_encryption_and_entry_zip64_are_refused() {
    let mut method = ZEntry::new("a.json", b"{}");
    method.method = Some(12);
    assert_eq!(
        refused(&zip_of(vec![method])),
        SyncError::Zip("méthode de compression non prise en charge")
    );
    let mut encrypted = ZEntry::new("a.json", b"{}");
    encrypted.flags = 1;
    assert_eq!(
        refused(&zip_of(vec![encrypted])),
        SyncError::Zip("entrée chiffrée")
    );
    let mut zip64 = ZEntry::new("a.json", b"{}");
    zip64.unpacked = Some(0xFFFF_FFFF);
    assert_eq!(
        refused(&zip_of(vec![zip64])),
        SyncError::Zip("ZIP64 par entrée non pris en charge")
    );
}

#[test]
fn data_descriptor_is_refused_with_its_message() {
    let mut e = ZEntry::new("a.json", b"{}");
    e.flags = 1 << 3;
    let err = refused(&zip_of(vec![e]));
    assert!(
        err.to_string()
            .contains("descripteurs de données non pris en charge : format de l'export changé ?"),
        "{err}"
    );
}

#[test]
fn local_header_differing_from_central_is_refused() {
    let mut name = ZEntry::new("a.json", b"{}");
    name.local_name = Some(b"b.json".to_vec());
    assert_eq!(
        refused(&zip_of(vec![name])),
        SyncError::Zip("en-tête local différent du répertoire central")
    );
    let mut method = ZEntry::new("a.json", b"{}");
    method.local_method = Some(0);
    assert_eq!(
        refused(&zip_of(vec![method])),
        SyncError::Zip("en-tête local différent du répertoire central")
    );
}

#[test]
fn central_directory_must_be_consumed_exactly() {
    let garbage = build(&Spec {
        entries: three(),
        central_garbage: vec![0; 7],
        ..Spec::default()
    });
    assert_eq!(
        refused(&garbage.bytes),
        SyncError::Zip("octets restants dans le répertoire central")
    );
    let fewer = build(&Spec {
        entries: three(),
        declared_entries: Some(4),
        ..Spec::default()
    });
    assert_eq!(
        refused(&fewer.bytes),
        SyncError::Zip("moins d'entrées que déclaré")
    );
}

#[test]
fn zip64_locator_and_record_must_be_in_place() {
    let base = build(&Spec {
        entries: three(),
        zip64: true,
        ..Spec::default()
    });
    let (record, locator) = (base.zip64_record.unwrap(), base.locator.unwrap());

    let mut elsewhere = base.bytes.clone();
    put_u64(&mut elsewhere, locator + 8, 0);
    assert!(matches!(refused(&elsewhere), SyncError::Zip(_)));

    let mut long_record = base.bytes.clone();
    put_u64(&mut long_record, record + 4, 52);
    assert_eq!(
        refused(&long_record),
        SyncError::Zip("enregistrement ZIP64 mal placé")
    );

    let mut no_locator = base.bytes.clone();
    put_u32(&mut no_locator, locator, 0);
    assert_eq!(
        refused(&no_locator),
        SyncError::Zip("localisateur ZIP64 absent")
    );

    let mut disks = base.bytes.clone();
    put_u32(&mut disks, locator + 16, 2);
    assert_eq!(
        refused(&disks),
        SyncError::Zip("archive sur plusieurs disques")
    );

    let mut incoherent = base.bytes.clone();
    put_u64(&mut incoherent, record + 24, 2);
    assert_eq!(
        refused(&incoherent),
        SyncError::Zip("fin de fichier ZIP64 incohérente")
    );
}

#[test]
fn huge_offsets_and_sizes_fail_without_panic() {
    let base = build(&Spec {
        entries: three(),
        zip64: true,
        ..Spec::default()
    });
    let record = base.zip64_record.unwrap();
    for (at, value) in [
        (record + 48, u64::MAX),
        (record + 40, u64::MAX),
        (record + 48, u64::MAX - 10),
        (record + 4, u64::MAX),
        (base.locator.unwrap() + 8, u64::MAX - 5),
    ] {
        let mut bytes = base.bytes.clone();
        put_u64(&mut bytes, at, value);
        let err = refused(&bytes);
        assert!(
            matches!(err, SyncError::Zip(_) | SyncError::TooLarge { .. }),
            "{err:?}"
        );
    }
    // Offset local géant dans le répertoire central classique.
    let mut e = ZEntry::new("a.json", b"{}");
    e.offset = Some(0xFFFF_FFF0);
    assert!(matches!(refused(&zip_of(vec![e])), SyncError::Zip(_)));
}

#[test]
fn missing_truncated_or_misplaced_end_is_refused() {
    let built = build(&spec(three()));
    assert_eq!(refused(b""), SyncError::Zip("fin de fichier absente"));
    assert_eq!(
        refused(&built.bytes[..built.bytes.len() - 3]),
        SyncError::Zip("fin de fichier absente")
    );
    // Commentaire annoncé plus long que la fin du fichier.
    let mut comment = built.bytes.clone();
    put_u16(&mut comment, built.eocd + 20, 4);
    assert_eq!(refused(&comment), SyncError::Zip("fin de fichier absente"));
    // Répertoire central hors du fichier, ou pas juste avant la fin.
    let mut outside = built.bytes.clone();
    put_u32(&mut outside, built.eocd + 16, 0x00FF_FFFF);
    assert!(matches!(refused(&outside), SyncError::Zip(_)));
    let mut gap = built.bytes.clone();
    put_u32(&mut gap, built.eocd + 16, built.cd_offset as u32 - 1);
    assert_eq!(
        refused(&gap),
        SyncError::Zip("répertoire central hors de sa place")
    );
    let mut disks = built.bytes.clone();
    put_u16(&mut disks, built.eocd + 4, 1);
    assert_eq!(
        refused(&disks),
        SyncError::Zip("archive sur plusieurs disques")
    );
}

#[test]
fn too_many_entries_or_incoherent_zip64_count_are_refused() {
    let few = Limits {
        entries: 2,
        ..limits()
    };
    assert_eq!(
        read_all(&zip_of(three()), &few).err(),
        Some(SyncError::TooLarge {
            what: "nombre d'entrées"
        })
    );
    let base: Built = build(&Spec {
        entries: three(),
        zip64: true,
        ..Spec::default()
    });
    let mut bytes = base.bytes.clone();
    let record = base.zip64_record.unwrap();
    put_u64(&mut bytes, record + 24, 5);
    put_u64(&mut bytes, record + 32, 5);
    assert_eq!(
        refused(&bytes),
        SyncError::Zip("moins d'entrées que déclaré")
    );
}

// --- Fuzz ---

/// xorshift à graine fixe, comme `logs/tests.rs`.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn fifty_thousand_byte_mutations_never_panic() {
    let small = Limits {
        compressed: MIB,
        unpacked: 64 * 1024,
        entries: 64,
        entry: 16 * 1024,
        central_directory: 64 * 1024,
        ..limits()
    };
    let classic = zip_of(three());
    let zip64 = build(&Spec {
        entries: three(),
        zip64: true,
        ..Spec::default()
    })
    .bytes;
    let mut rng = XorShift(0x5eed_2026_1017);
    let mut accepted = 0;
    for i in 0..50_000 {
        let mut bytes = if i % 2 == 0 {
            classic.clone()
        } else {
            zip64.clone()
        };
        for _ in 0..1 + rng.next() % 4 {
            let at = (rng.next() % bytes.len() as u64) as usize;
            bytes[at] = match rng.next() % 4 {
                0 => 0xFF,
                1 => 0,
                _ => rng.next() as u8,
            };
        }
        let size = bytes.len() as u64;
        if let Ok(mut zip) = ZipReader::from_reader(Cursor::new(bytes), size, &small) {
            let mut produced = 0u64;
            for entry in zip.entries() {
                match entry {
                    Ok(Entry {
                        body: Body::Data(d),
                        ..
                    }) => {
                        assert!(d.len() as u64 <= small.entry);
                        produced += d.len() as u64;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            assert!(produced <= small.unpacked);
            accepted += 1;
        }
    }
    // Des mutations tombent sur des octets sans effet (dates, données).
    assert!(accepted > 0);
}
