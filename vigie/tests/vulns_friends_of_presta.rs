//! Convertisseur Friends-Of-Presta (#17, phase 2) : archive `.tar.gz`
//! construite par le test (`support/targen.rs`), en-tête YAML fermé, puces de
//! la section Summary, grammaire de « Impacted release » (`release.json`),
//! avis hostiles, verdicts et fuzz. Avis **fictifs**
//! (`tests/fixtures/vulns/friends-of-presta/README`). Aucun réseau.

#[path = "support/targen.rs"]
mod targen;

use std::path::{Path, PathBuf};

use serde::Deserialize;
use vigie::vulns::advisory::{Advisory, Event, Reason, ScoreOrigin, Tally};
use vigie::vulns::purl::Purl;
use vigie::vulns::range::{UnknownReason, Verdict, match_advisory};
use vigie::vulns::sources::friends_of_presta::{
    ArchiveLimits, ArchiveRead, LICENSE, convert_post, front_matter, parse_archive, post_url,
};
use vigie::vulns::sources::release::parse_release;
use vigie::vulns::sources::tar::TarLimits;
use vigie::vulns::sync::{Sink, SyncError};

use targen::{REVISION, ROOT, TEntry, archive, gz, header, posts, repository, tar};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulns/friends-of-presta")
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(rel)).unwrap_or_else(|e| panic!("{rel} : {e}"))
}

#[derive(Default)]
struct Collect(Vec<Advisory>);

impl Sink for Collect {
    fn push(&mut self, advisory: Advisory) -> Result<(), SyncError> {
        self.0.push(advisory);
        Ok(())
    }
}

const MIB: u64 = 1024 * 1024;

fn limits() -> ArchiveLimits {
    ArchiveLimits {
        tar: TarLimits {
            members: 50_000,
            unpacked: 512 * MIB,
        },
        advisory: MIB,
        deadline: None,
    }
}

fn read_archive(
    bytes: &[u8],
    limits: &ArchiveLimits,
) -> Result<(Vec<Advisory>, Tally, ArchiveRead), SyncError> {
    let mut sink = Collect::default();
    let mut tally = Tally::default();
    let read = parse_archive(bytes, limits, &mut sink, &mut tally)?;
    Ok((sink.0, tally, read))
}

fn fixture_archive() -> (Vec<Advisory>, Tally, ArchiveRead) {
    read_archive(&archive(&posts(&fixtures().join("_posts"))), &limits()).expect("archive")
}

fn by_id<'a>(all: &'a [Advisory], id: &str) -> &'a Advisory {
    all.iter()
        .find(|a| a.id == id)
        .unwrap_or_else(|| panic!("{id} absente"))
}

fn verdict(a: &Advisory, purl: &str, version: Option<&str>) -> Verdict {
    let purl = Purl::parse(purl).unwrap();
    let lines = a.lines_for(&purl);
    assert!(!lines.is_empty(), "{} : aucune ligne pour {purl}", a.id);
    match_advisory(&lines, version)
}

fn affected(fixed: Option<&str>) -> Verdict {
    Verdict::Affected {
        fixed: fixed.map(str::to_owned),
        divergence: false,
        beyond_last_known: false,
    }
}

const RANGE_UNKNOWN: Verdict = Verdict::Unknown(UnknownReason::RangeUnknown);

// ---------------------------------------------------------------- archive

#[test]
fn only_posts_are_read_and_the_revision_is_kept() {
    let (all, tally, read) = fixture_archive();
    assert_eq!(read.entries, 13);
    assert_eq!(read.revision.as_deref(), Some(REVISION));
    // dependancies écartée, comptée hors périmètre ; README, _layouts et
    // image ignorés sans compte.
    assert_eq!(all.len(), 12, "{tally:?}");
    assert_eq!(tally.get(Reason::OutOfScope), 1);
    assert_eq!(tally.get(Reason::BadArchiveMember), 0);
    assert_eq!(tally.dropped(), 0, "{tally:?}");
    assert!(read.unpacked > 0);
}

#[test]
fn hostile_members_are_skipped_and_counted() {
    let post = read("_posts/2099-01-15-exemplemodule.md");
    let mut entries = repository(&[]);
    entries.extend([
        TEntry::File(format!("{ROOT}/../x.md"), post.clone()),
        TEntry::File("/etc/x".into(), b"x".to_vec()),
        TEntry::Symlink(format!("{ROOT}/_posts/lien.md"), "/etc/passwd".into()),
        TEntry::HardLink(format!("{ROOT}/_posts/dur.md"), "x".into()),
        TEntry::Device(format!("{ROOT}/_posts/disque.md")),
        TEntry::PaxFile(format!("{ROOT}/_posts/{}", "n".repeat(4097)), post.clone()),
        // Noms longs lus par pax et par GNU `L`.
        TEntry::PaxFile(
            format!("{ROOT}/_posts/2099-01-15-exemplemodule.md"),
            post.clone(),
        ),
        TEntry::GnuFile(format!("{ROOT}/_posts/2099-01-28-gnu.md"), post.clone()),
    ]);
    let (all, tally, _) = read_archive(&gz(&tar(&entries, Some(REVISION))), &limits()).unwrap();
    assert_eq!(tally.get(Reason::BadArchiveMember), 6, "{tally:?}");
    let ids: Vec<&str> = all.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(ids, ["FOP-2099-01-15-exemplemodule", "FOP-2099-01-28-gnu"]);
}

fn refused(bytes: &[u8]) -> SyncError {
    read_archive(bytes, &limits()).expect_err("archive refusée")
}

#[test]
fn broken_archives_are_stream_errors() {
    let post = read("_posts/2099-01-15-exemplemodule.md");
    let good = tar(
        &repository(&[("a.md".into(), post.clone())]),
        Some(REVISION),
    );
    // Deux racines.
    let mut two = repository(&[]);
    two.push(TEntry::File(
        "autre-racine/_posts/a.md".into(),
        post.clone(),
    ));
    assert!(matches!(
        refused(&gz(&tar(&two, None))),
        SyncError::Format(_)
    ));
    // Tronquée, somme fausse, gzip corrompu, second membre.
    let gzipped = gz(&good);
    assert!(matches!(
        refused(&gzipped[..gzipped.len() / 2]),
        SyncError::Format(_)
    ));
    assert!(matches!(refused(&gz(&good[..3000])), SyncError::Format(_)));
    let mut bad_sum = good.clone();
    bad_sum[1024 + 10] ^= 1;
    assert!(matches!(refused(&gz(&bad_sum)), SyncError::Format(_)));
    let mut corrupt = gzipped.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xff;
    assert!(matches!(refused(&corrupt), SyncError::Format(_)));
    let mut twice = gzipped.clone();
    twice.extend_from_slice(&gz(b"x"));
    assert!(matches!(refused(&twice), SyncError::Format(_)));
    // Octet non nul après la fin ; bourrage nul au-delà de 10 240 octets.
    let mut after = good.clone();
    let last = after.len() - 1;
    after[last] = 1;
    assert!(matches!(refused(&gz(&after)), SyncError::Format(_)));
    let mut long_tail = good.clone();
    long_tail.extend_from_slice(&[0u8; 10_240]);
    assert!(matches!(refused(&gz(&long_tail)), SyncError::Format(_)));
    // Bloc nul isolé.
    let mut lone = good[..good.len() - 10_240].to_vec();
    lone.extend_from_slice(&[0u8; 512]);
    lone.extend_from_slice(&header(b"x", 0, b'0', b""));
    assert!(read_archive(&gz(&lone), &limits()).is_err());
}

#[test]
fn pax_and_size_fields_are_strict() {
    let pax = |records: Vec<u8>, flag: u8| {
        let mut raw = header(b"PaxHeaders/x", records.len() as u64, flag, b"").to_vec();
        raw.extend_from_slice(&records);
        while !raw.len().is_multiple_of(512) {
            raw.push(0);
        }
        gz(&tar(&[TEntry::Raw(raw)], None))
    };
    // Longueur 0, débordante, clé size.
    assert!(matches!(
        refused(&pax(b"0 path=a\n".to_vec(), b'x')),
        SyncError::Format(_)
    ));
    assert!(matches!(
        refused(&pax(b"90 path=a\n".to_vec(), b'x')),
        SyncError::Format(_)
    ));
    assert!(matches!(
        refused(&pax(targen::pax_record("size", b"10"), b'x')),
        SyncError::Format(_)
    ));
    // En-tête pax de 64 Kio + 1.
    let big = targen::pax_record("comment", &vec![b'a'; 64 * 1024]);
    assert!(big.len() > 64 * 1024);
    assert!(matches!(refused(&pax(big, b'g')), SyncError::Format(_)));
    // Taille en base 256.
    let mut h = header(format!("{ROOT}/x").as_bytes(), 0, b'0', b"");
    h[124] = 0x80;
    targen::fix_checksum(&mut h);
    assert!(matches!(
        refused(&gz(&tar(&[TEntry::Raw(h.to_vec())], None))),
        SyncError::Format(_)
    ));
}

#[test]
fn caps_are_enforced() {
    let post = read("_posts/2099-01-15-exemplemodule.md");
    let many: Vec<(String, Vec<u8>)> = (0..20)
        .map(|i| (format!("2099-01-15-m{i}.md"), post.clone()))
        .collect();
    let bytes = archive(&many);
    let mut small = limits();
    small.tar.members = 10;
    assert!(matches!(
        read_archive(&bytes, &small).unwrap_err(),
        SyncError::TooLarge { .. }
    ));
    // Données sautées (image) et bourrage comptés dans le plafond.
    let mut tight = limits();
    tight.tar.unpacked = 4096;
    let image = gz(&tar(
        &[TEntry::File(format!("{ROOT}/image.png"), vec![1; 8192])],
        None,
    ));
    assert!(matches!(
        read_archive(&image, &tight).unwrap_err(),
        SyncError::TooLarge { .. }
    ));
    // Avis de 1 Mio + 1 : sauté, too_large.
    let mut huge = post.clone();
    huge.resize(MIB as usize + 1, b' ');
    let (all, tally, _) =
        read_archive(&archive(&[("2099-01-15-gros.md".into(), huge)]), &limits()).unwrap();
    assert!(all.is_empty());
    assert_eq!(tally.get(Reason::TooLarge), 1);
    // Échéance passée.
    let mut late = limits();
    late.deadline = Some(std::time::Instant::now());
    assert_eq!(
        read_archive(&bytes, &late).unwrap_err(),
        SyncError::Deadline
    );
}

// ---------------------------------------------------------------- happy path

#[test]
fn a_module_advisory_converts_field_by_field() {
    let (all, _, _) = fixture_archive();
    let a = by_id(&all, "FOP-2099-01-15-exemplemodule");
    assert_eq!(a.aliases, ["CVE-2099-0002"]);
    assert_eq!(a.cwe, ["CWE-89"]);
    assert_eq!(
        a.summary,
        "[CVE-2099-0002] Injection SQL fictive dans exemplemodule"
    );
    let day = "2099-01-15T00:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    assert_eq!((a.published, a.modified), (Some(day), day));
    let score = a.score.unwrap();
    assert_eq!(
        (score.tenths, score.origin),
        (98, ScoreOrigin::FriendsOfPresta)
    );
    assert_eq!(a.severity.len(), 1);
    assert!(a.severity[0].vector.starts_with("CVSS:3.1/"));
    assert_eq!(a.license, LICENSE);
    let url = post_url("2099-01-15-exemplemodule.md");
    assert_eq!(
        url,
        "https://github.com/friends-of-presta/security-advisories/blob/main/_posts/2099-01-15-exemplemodule.md"
    );
    assert_eq!(a.source_url, url);
    assert_eq!(
        a.attribution,
        format!("Friends-Of-Presta, CC BY-SA 4.0 — {url}")
    );
    assert!(a.references.is_empty());
    assert!(!format!("{a:?}").contains("jamais stocké"));
    let line = &a.affected[0];
    assert_eq!(line.purl.to_string(), "pkg:prestashop/module/exemplemodule");
    assert_eq!(line.scheme.as_str(), "php");
    assert_eq!(
        serde_json::to_value(&line.ranges).unwrap(),
        serde_json::json!([{"scheme": "php", "events": [
            {"introduced": "0"}, {"last_affected": "1.5.0"}, {"fixed": "1.5.1"}
        ]}])
    );
}

#[test]
fn lists_core_categories_and_long_names() {
    let (all, _, _) = fixture_archive();
    let two = by_id(&all, "FOP-2099-01-16-deuxmodules");
    let purls: Vec<String> = two.affected.iter().map(|l| l.purl.to_string()).collect();
    assert_eq!(
        purls,
        [
            "pkg:prestashop/module/exemplemodule2",
            "pkg:prestashop/module/autremodule"
        ]
    );
    assert_eq!(two.affected[0].ranges, two.affected[1].ranges);
    let core = by_id(&all, "FOP-2099-01-17-noyau");
    assert_eq!(
        core.affected[0].purl.to_string(),
        "pkg:prestashop/core/prestashop"
    );
    // Nom de 63 caractères : identifiant raccourci, stable.
    let long = all.iter().find(|a| a.id.starts_with("FOPH-")).unwrap();
    assert_eq!(long.id.len(), 61);
    assert!(
        long.id
            .starts_with("FOPH-2099-01-26-nomtreslongdavisfictifpourtesterl")
    );
    let (again, _, _) = fixture_archive();
    assert!(again.iter().any(|a| a.id == long.id));
    // Sans « Published at » : date du nom de fichier ; score 10 → 100.
    let undated = by_id(&all, "FOP-2099-01-21-sanspublication");
    assert_eq!(
        undated.published,
        Some(
            "2099-01-21T00:00:00Z"
                .parse::<jiff::Timestamp>()
                .unwrap()
                .as_second()
        )
    );
    assert_eq!(undated.score.unwrap().tenths, 100);
    // Score lu dans la puce quand l'en-tête n'en a pas.
    assert_eq!(
        by_id(&all, "FOP-2099-01-23-sansscoreentete")
            .score
            .unwrap()
            .tenths,
        70
    );
    // Titre piégé : assaini, 500 caractères.
    let title = by_id(&all, "FOP-2099-01-27-titrepiege");
    assert_eq!(title.summary.chars().count(), 500);
    assert!(!title.summary.contains('\u{1b}') && !title.summary.contains('\u{202e}'));
    assert!(title.summary.starts_with("Titre \" "));
}

#[test]
fn categories_in_any_of_three_forms() {
    for header in [
        "categories: modules",
        "categories: [modules]",
        "categories: [\"modules\", autre]",
        "categories:\n- modules",
        "categories:\n  - modules",
    ] {
        let text = format!("---\ntitle: \"T\"\n{header}\nseverity: 'high (7.5)'\n---\ncorps\n");
        let (fm, body) = front_matter(&text).unwrap_or_else(|| panic!("{header}"));
        assert!(fm.categories.contains(&"modules".to_owned()), "{header}");
        assert_eq!(fm.severity.as_deref(), Some("high (7.5)"));
        assert_eq!(body, "corps\n");
    }
}

// ---------------------------------------------------------------- grammaire

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseVector {
    #[serde(rename = "in")]
    input: String,
    out: Option<Vec<Event>>,
    why: String,
}

#[test]
fn release_vectors() {
    let vectors: Vec<ReleaseVector> = serde_json::from_slice(&read("release.json")).unwrap();
    assert!(vectors.len() >= 30);
    for v in &vectors {
        assert_eq!(
            parse_release(&v.input, true),
            v.out,
            "{} ({})",
            v.input,
            v.why
        );
    }
    // Sans remarque admise (corrections de plage) : toute remarque refusée.
    assert_eq!(parse_release("<= 1.5.0 (WARNING NO PATCH)", false), None);
    assert!(parse_release("<= 1.5.0", false).is_some());
}

// ---------------------------------------------------------------- verdicts

#[test]
fn verdicts_on_the_fixtures() {
    let (all, _, _) = fixture_archive();
    let m = by_id(&all, "FOP-2099-01-15-exemplemodule");
    let p = "pkg:prestashop/module/exemplemodule";
    assert_eq!(verdict(m, p, Some("1.5.0")), affected(Some("1.5.1")));
    assert_eq!(verdict(m, p, Some("1.5.1")), Verdict::NotAffected);
    let four = by_id(&all, "FOP-2099-01-19-quatrecomposants");
    let p4 = "pkg:prestashop/module/exemplequatre";
    assert_eq!(
        verdict(four, p4, Some("1.6.1.24")),
        affected(Some("1.6.1.25"))
    );
    assert_eq!(verdict(four, p4, Some("1.6.1.25")), Verdict::NotAffected);
    // Plage libre : « plage inconnue » pour toute version.
    let free = by_id(&all, "FOP-2099-01-20-modulelibre");
    assert!(free.affected[0].unevaluable);
    for v in ["0.1", "3.0.0", "99"] {
        assert_eq!(
            verdict(free, "pkg:prestashop/module/modulelibre", Some(v)),
            RANGE_UNKNOWN
        );
    }
    let open = by_id(&all, "FOP-2099-01-25-ouverte");
    assert_eq!(
        verdict(open, "pkg:prestashop/module/exempleouverte", Some("3.1")),
        affected(None)
    );
    let core = by_id(&all, "FOP-2099-01-17-noyau");
    assert_eq!(
        verdict(core, "pkg:prestashop/core/prestashop", Some("8.1.1")),
        affected(Some("8.1.2"))
    );
}

// ---------------------------------------------------------------- hostile

#[test]
fn hostile_advisories_end_as_named() {
    let mut names: Vec<String> = std::fs::read_dir(fixtures().join("hostile"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(names.len() >= 18, "{names:?}");
    for name in names {
        let stem = name.trim_end_matches(".md");
        let (kind, rest) = stem.split_once('-').unwrap();
        let reason = rest.split('-').next().unwrap();
        let mut tally = Tally::default();
        // Nom de fichier daté, pour la date de repli (sauf `bad_date`).
        let file = if reason == "bad_date" {
            format!("sans-date-{stem}")
        } else {
            format!("2099-02-01-{stem}")
        };
        let result = convert_post(&file, &read(&format!("hostile/{name}")), &mut tally);
        let counted: Vec<&str> = tally
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(r, _)| r.as_str())
            .collect();
        assert!(counted.contains(&reason), "{name} : {counted:?}");
        match kind {
            "drop" => assert!(result.is_err(), "{name}"),
            "keep" => {
                let a = result.unwrap_or_else(|r| panic!("{name} : {r:?}"));
                assert_eq!(tally.dropped(), 0, "{name} : {counted:?}");
                for line in &a.affected {
                    if line.unevaluable {
                        assert_eq!(match_advisory(&[line], Some("1.0")), RANGE_UNKNOWN);
                    }
                }
            }
            other => panic!("{name} : préfixe {other}"),
        }
    }
    // Nom de fichier hors grammaire.
    let mut tally = Tally::default();
    assert_eq!(
        convert_post(
            "2099 01 15",
            &read("_posts/2099-01-15-exemplemodule.md"),
            &mut tally
        ),
        Err(Reason::BadId)
    );
    // `dependancies` : hors périmètre, pas une perte.
    assert!(!Reason::OutOfScope.is_drop());
    assert!(Reason::UnknownCategory.is_drop() && Reason::BadFrontMatter.is_drop());
    assert!(!Reason::BadArchiveMember.is_drop());
}

#[test]
fn a_bad_published_date_falls_back_to_the_file_name() {
    let mut tally = Tally::default();
    let a = convert_post(
        "2099-02-01-date",
        &read("hostile/keep-bad_published-illisible.md"),
        &mut tally,
    )
    .unwrap();
    assert_eq!(
        a.published,
        Some(
            "2099-02-01T00:00:00Z"
                .parse::<jiff::Timestamp>()
                .unwrap()
                .as_second()
        )
    );
    assert_eq!(tally.get(Reason::BadPublished), 1);
    assert!(!Reason::BadPublished.is_drop());
}

// ---------------------------------------------------------------- fuzz

fn assert_bounded(a: &Advisory) {
    assert!(a.id.len() <= 64);
    assert!(a.summary.chars().count() <= 500);
    assert!(a.summary.chars().all(|c| !c.is_control()));
    assert!(a.attribution.chars().count() <= 2000);
    assert!(a.aliases.len() <= 32 && a.cwe.len() <= 8);
    assert!(a.score.is_none_or(|s| s.tenths <= 100));
    assert!(!a.affected.is_empty() && a.affected.len() <= 16);
    for l in &a.affected {
        assert!(l.purl.version().is_none());
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutate(rng: &mut XorShift, base: &[u8], alphabet: &[u8]) -> Vec<u8> {
    let mut m = base.to_vec();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(m.len().max(1));
        match rng.below(3) {
            0 if !m.is_empty() => m[at] = alphabet[rng.below(alphabet.len())],
            1 if !m.is_empty() => {
                m.remove(at);
            }
            _ => m.insert(at.min(m.len()), alphabet[rng.below(alphabet.len())]),
        }
    }
    m
}

#[test]
fn fuzz_mutations_never_panic_and_stay_bounded() {
    let seeds = posts(&fixtures().join("_posts"));
    let alphabet: &[u8] = b"-*:#[]()<>=,/ \n\"'|&\\0123456789.vV\x00\xff\x1b";
    let mut rng = XorShift(0x5eed_17f1_0003_0002);
    let mut kept = 0;
    for _ in 0..50_000 {
        let (name, base) = &seeds[rng.below(seeds.len())];
        let m = mutate(&mut rng, base, alphabet);
        let mut tally = Tally::default();
        if let Ok(a) = convert_post(name.trim_end_matches(".md"), &m, &mut tally) {
            assert_bounded(&a);
            for l in &a.affected {
                let _ = match_advisory(&[l], Some("1.0"));
            }
            kept += 1;
        }
    }
    assert!(kept > 1_000, "{kept}");
    let base = archive(&seeds[..3]);
    let raw = tar(&repository(&seeds[..3]), Some(REVISION));
    for i in 0..2_000 {
        // Octets de l'archive compressée, puis du tar avant compression.
        let m = if i % 2 == 0 {
            mutate(&mut rng, &base, alphabet)
        } else {
            gz(&mutate(&mut rng, &raw, alphabet))
        };
        if let Ok((all, _, _)) = read_archive(&m, &limits()) {
            all.iter().for_each(assert_bounded);
        }
    }
}
