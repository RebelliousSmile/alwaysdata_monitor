//! Rapprochement dans `tick` (#21, phase 2), de bout en bout sur une base
//! réelle : failles écrites par F1, KEV et EPSS par F4, inventaires `agent`
//! et `ci` acceptés par F5 et F6, puis `tick::run_with_sources`. Données
//! fictives seulement.

use std::time::{Duration, Instant};

use vigie::config::{InventorySource, SiteKind};
use vigie::inventory::Source;
use vigie::store::{CloseReason, InventoryOutcome};
use vigie::vulns::advisory::Advisory;
use vigie::vulns::enrich_store::StoreTables;
use vigie::vulns::matching::pass::{self, Budget};
use vigie::vulns::version::Scheme;

#[path = "support/match_harness.rs"]
mod match_harness;
#[path = "support/matching_data.rs"]
mod matching_data;
use match_harness::*;
use matching_data::*;

use InventorySource::{AgentPhp, Ci};

const VULNS: &[&str] = &["osv-packagist", "friends-of-presta", "wordfence"];

/// Faille Wordfence fictive de l'extension, corrigée en `fixed`.
fn wf(id: &str, cve: &str, score: u8, fixed: &str) -> Advisory {
    let aliases = [cve];
    let ranges = [("0", fixed)];
    build(&Fake {
        id,
        aliases: &aliases,
        purl: PLUGIN,
        scheme: Scheme::Php,
        ranges: &ranges,
        score: Some(score),
        attribution: ATTRIBUTION_WF,
        ..Fake::default()
    })
}

/// Faille Packagist fictive de `exemple/paquet`.
fn ghsa(id: &str, cve: &str, score: u8) -> Advisory {
    let aliases = [cve];
    build(&Fake {
        id,
        aliases: &aliases,
        score: Some(score),
        ..Fake::default()
    })
}

fn plugin(version: &str) -> String {
    format!("{PLUGIN}@{version}")
}

fn paquet(version: &str) -> String {
    format!("{PAQUET}@{version}")
}

const PLUGIN_PATH: &str = "wp-content/plugins/exemple-plugin";

fn wordpress(sources: &[InventorySource]) -> Harness {
    Harness::new(vec![site("site-a", SiteKind::Wordpress, sources)], VULNS)
}

fn accepted(outcome: InventoryOutcome) {
    assert!(
        matches!(outcome, InventoryOutcome::Accepted { .. }),
        "{outcome:?}"
    );
}

#[test]
fn an_affected_plugin_opens_then_closes_restored_on_the_fixed_version() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    let mails = h.tick(T0 + 60);
    let open = h.open("site-a");
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].key, format!("site-a/vulns/{PLUGIN}"));
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert!(
        mails[0]
            .subject
            .starts_with(&format!("[vigie] site-a : {PLUGIN} (agent : 1.2.3)"))
    );
    assert!(mails[0].body.contains("vigie site vulns site-a"));
    assert!(mails[0].body.contains("usage interne"));

    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.4"), PLUGIN_PATH)],
        T0 + DAY,
    ));
    let mails = h.tick(T0 + DAY + 60);
    assert!(h.open("site-a").is_empty());
    let closed = &h.incidents("site-a")[0];
    assert_eq!(closed.close_reason, Some(CloseReason::Resolved));
    assert_eq!(mails.len(), 1);
    assert!(mails[0].subject.contains("rétabli"), "{mails:?}");
}

#[test]
fn absence_from_a_complete_inventory_restores_and_a_partial_one_carries() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    assert_eq!(h.open("site-a").len(), 1);

    // Relevé partiel sans l'extension : reportée, rapprochée sur 1.2.3.
    accepted(h.inventory("site-a", Source::Agent, false, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    let open = h.open("site-a");
    assert_eq!(open.len(), 1);
    assert!(
        open[0].detail.contains("absent d'un relevé partiel"),
        "{}",
        open[0].detail
    );

    // Relevé complet sans l'extension : rétabli.
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + 2 * DAY));
    h.tick(T0 + 2 * DAY + 60);
    assert!(h.open("site-a").is_empty());
    assert_eq!(
        h.incidents("site-a")[0].close_reason,
        Some(CloseReason::Resolved)
    );
}

#[test]
fn a_carried_component_expires_unwatched_never_restored() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    accepted(h.inventory("site-a", Source::Agent, false, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    assert_eq!(h.open("site-a").len(), 1);
    // Dernière vue à T0 : au-delà de 7 jours, plus reporté.
    let mails = h.tick(T0 + 7 * DAY + 1);
    assert!(
        h.open("site-a")
            .iter()
            .all(|i| i.key.contains("inventaire-perime"))
    );
    let closed = &h.by_key("site-a", PLUGIN)[0];
    assert_eq!(closed.close_reason, Some(CloseReason::Unwatched));
    assert!(
        mails.iter().all(|m| !m.subject.contains("rétabli")),
        "{mails:?}"
    );
}

#[test]
fn alternating_partial_inventories_never_close_nor_reopen() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    // Première vue dans un relevé partiel, absent du suivant : reporté.
    for day in 0..20 {
        let with = day % 2 == 0;
        let comps: Vec<(String, &str)> = if with {
            vec![(plugin("1.2.3"), PLUGIN_PATH)]
        } else {
            Vec::new()
        };
        let comps: Vec<(&str, &str)> = comps.iter().map(|(p, q)| (p.as_str(), *q)).collect();
        accepted(h.inventory("site-a", Source::Agent, false, &comps, T0 + day * DAY));
        h.tick(T0 + day * DAY + 60);
        assert_eq!(h.by_key("site-a", PLUGIN).len(), 1, "jour {day}");
        assert_eq!(h.open("site-a").len(), 1, "jour {day}");
    }
}

#[test]
fn a_four_component_module_opens_then_closes_on_site_b() {
    let h = Harness::new(
        vec![site("site-b", SiteKind::Prestashop, &[AgentPhp])],
        VULNS,
    );
    let aliases = ["CVE-2099-0101"];
    let ranges = [("0", "1.6.1.25")];
    h.load(
        "friends-of-presta",
        &[build(&Fake {
            id: "FOP-2099-0001",
            aliases: &aliases,
            purl: MODULE,
            scheme: Scheme::Php,
            ranges: &ranges,
            score: Some(95),
            ..Fake::default()
        })],
        T0,
    );
    let at = |v: &str| format!("{MODULE}@{v}");
    let module = |v: &str| -> Vec<(String, String)> {
        (0..4)
            .map(|i| (at(v), format!("modules/exemplemodule/part{i}")))
            .collect()
    };
    let comps = module("1.6.1.24");
    let comps: Vec<(&str, &str)> = comps
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    accepted(h.inventory("site-b", Source::Agent, true, &comps, T0));
    let mails = h.tick(T0 + 60);
    assert_eq!(h.open("site-b").len(), 1);
    assert_eq!(mails.len(), 1);
    assert!(mails[0].body.contains("critique"));
    let comps = module("1.6.1.25");
    let comps: Vec<(&str, &str)> = comps
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    accepted(h.inventory("site-b", Source::Agent, true, &comps, T0 + DAY));
    h.tick(T0 + DAY + 60);
    assert!(h.open("site-b").is_empty());
}

#[test]
fn two_sources_are_one_union_and_each_proves_its_own_absence() {
    let h = Harness::new(vec![site("site-a", SiteKind::Generic, &[Ci])], VULNS);
    // Site générique : `ci` seule ; l'agent n'y est pas déclaré.
    drop(h);
    let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
    s.runtime = None;
    let h = Harness::new(vec![s], VULNS);
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&paquet("1.2.3"), "vendor")],
        T0,
    ));
    accepted(h.inventory(
        "site-a",
        Source::Ci,
        true,
        &[(&paquet("1.2.4"), "composer.lock")],
        T0,
    ));
    h.tick(T0 + 60);
    let open = h.open("site-a");
    assert_eq!(open.len(), 1, "{open:?}");
    assert!(
        open[0].detail.contains("agent : 1.2.3 ; ci : 1.2.4"),
        "{}",
        open[0].detail
    );

    // ci complète sans le composant, l'agent le voit encore : gardé.
    accepted(h.inventory("site-a", Source::Ci, true, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    assert_eq!(h.open("site-a").len(), 1);
    // ci le revoit touché, l'agent complet sans lui : gardé.
    accepted(h.inventory(
        "site-a",
        Source::Ci,
        true,
        &[(&paquet("1.2.2"), "composer.lock")],
        T0 + 2 * DAY,
    ));
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + 2 * DAY));
    h.tick(T0 + 2 * DAY + 60);
    assert_eq!(h.open("site-a").len(), 1);
    // Les deux complets sans lui : rétabli.
    accepted(h.inventory("site-a", Source::Ci, true, &[], T0 + 3 * DAY));
    h.tick(T0 + 3 * DAY + 60);
    assert!(h.open("site-a").is_empty(), "{:?}", h.open("site-a"));
    assert_eq!(
        h.incidents("site-a")[0].close_reason,
        Some(CloseReason::Resolved)
    );
}

#[test]
fn info_only_opens_nothing_and_epss_never_flaps() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 30, "1.2.4")],
        T0,
    );
    h.epss(&[("CVE-2099-0001", 90_000)], T0);
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    assert!(h.incidents("site-a").is_empty(), "information seulement");

    h.epss(&[("CVE-2099-0001", 110_000)], T0 + 120);
    let mails = h.tick(T0 + 180);
    let open = h.open("site-a");
    assert_eq!(open.len(), 1);
    assert_eq!(mails.len(), 1);

    h.epss(&[("CVE-2099-0001", 90_000)], T0 + 240);
    let mails = h.tick(T0 + 300);
    let open = h.open("site-a");
    assert_eq!(open.len(), 1, "gardé ouvert en information");
    assert_eq!(open[0].severity, vigie::finding::Severity::Info);
    assert!(mails.is_empty(), "aucun e-mail rétabli : {mails:?}");
    assert_eq!(h.incidents("site-a").len(), 1);
}

#[test]
fn thirty_vulns_on_one_extension_make_one_incident_and_one_email() {
    let h = wordpress(&[AgentPhp]);
    let advisories: Vec<Advisory> = (0..30)
        .map(|i| {
            wf(
                &format!("WF-2099-1{i:03}"),
                &format!("CVE-2099-1{i:03}"),
                75,
                "1.2.4",
            )
        })
        .collect();
    h.load("wordfence", &advisories, T0);
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    let mails = h.tick(T0 + 60);
    assert_eq!(h.incidents("site-a").len(), 1);
    assert_eq!(mails.len(), 1);
    assert!(
        mails[0].subject.contains("30 faille(s)"),
        "{:?}",
        mails[0].subject
    );
}

/// Paquets Composer fictifs `exemple/p<i>`, chacun touché par sa faille.
fn many(h: &Harness, n: usize, score: u8) -> Vec<(String, String)> {
    let advisories: Vec<Advisory> = (0..n)
        .map(|i| {
            let purl = format!("pkg:composer/exemple/p{i}");
            let id = format!("GHSA-2099-bbbb-{i:04}");
            let cve = format!("CVE-2099-2{i:03}");
            let aliases = [cve.as_str()];
            build(&Fake {
                id: &id,
                aliases: &aliases,
                purl: &purl,
                score: Some(score),
                ..Fake::default()
            })
        })
        .collect();
    h.load("osv-packagist", &advisories, T0);
    (0..n)
        .map(|i| {
            (
                format!("pkg:composer/exemple/p{i}@1.0.0"),
                "vendor".to_owned(),
            )
        })
        .collect()
}

fn refs(list: &[(String, String)]) -> Vec<(&str, &str)> {
    list.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect()
}

#[test]
fn five_openings_make_five_emails_and_six_make_one_digest() {
    for (n, expected) in [(5, 5), (6, 1)] {
        let h = wordpress(&[AgentPhp]);
        let comps = many(&h, n, 75);
        accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
        let mails = h.tick(T0 + 60);
        assert_eq!(mails.len(), expected, "{n} ouvertures : {mails:?}");
        assert_eq!(h.open("site-a").len(), n);
        assert_eq!(h.store().pending_opens().unwrap().len(), 0, "tous marqués");
        if expected == 1 {
            assert!(
                mails[0].subject.contains("6 constats de failles"),
                "{mails:?}"
            );
            assert!(
                mails[0].body.contains("6 avertissement(s)"),
                "{}",
                mails[0].body
            );
        }
    }
}

#[test]
fn six_reminders_and_six_closures_are_grouped() {
    let h = wordpress(&[AgentPhp]);
    let comps = many(&h, 6, 75);
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    assert_eq!(h.tick(T0 + 60).len(), 1);
    // Rappels : 24 h plus tard.
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0 + DAY));
    let mails = h.tick(T0 + DAY + 120);
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert!(mails[0].subject.contains("toujours en cours"), "{mails:?}");
    assert!(h.store().due_reminders(T0 + DAY + 120).unwrap().is_empty());
    // Clôtures : tous corrigés.
    let fixed: Vec<(String, String)> = (0..6)
        .map(|i| {
            (
                format!("pkg:composer/exemple/p{i}@1.2.4"),
                "vendor".to_owned(),
            )
        })
        .collect();
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&fixed), T0 + 2 * DAY));
    let mails = h.tick(T0 + 2 * DAY + 60);
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert!(mails[0].subject.contains("6 rétabli(s)"), "{mails:?}");
}

#[test]
fn a_failed_digest_marks_nothing_and_is_retried_whole() {
    let h = wordpress(&[AgentPhp]);
    let comps = many(&h, 6, 75);
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    h.mail.set_failing(true);
    assert!(h.tick(T0 + 60).is_empty());
    assert_eq!(h.store().pending_opens().unwrap().len(), 6);
    h.mail.set_failing(false);
    let mails = h.tick(T0 + 120);
    assert_eq!(mails.len(), 1, "{mails:?}");
}

#[test]
fn a_failed_marking_may_resend_the_digest_never_six_emails() {
    let h = wordpress(&[AgentPhp]);
    let comps = many(&h, 6, 75);
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    h.raw()
        .execute_batch(
            "CREATE TRIGGER marking_fails BEFORE UPDATE OF open_notified_at ON incidents
             BEGIN SELECT RAISE(ABORT, 'marquage refusé'); END;",
        )
        .unwrap();
    assert_eq!(h.tick(T0 + 60).len(), 1);
    h.raw().execute_batch("DROP TRIGGER marking_fails").unwrap();
    let mails = h.tick(T0 + 120);
    assert_eq!(mails.len(), 1, "doublon accepté, jamais six : {mails:?}");
    assert!(h.tick(T0 + 180).is_empty());
}

#[test]
fn kev_raises_the_same_incidents_with_one_digest() {
    let h = wordpress(&[AgentPhp]);
    let comps = many(&h, 6, 75);
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    h.tick(T0 + 60);
    let before: Vec<i64> = h.open("site-a").iter().map(|i| i.id).collect();
    let cves: Vec<String> = (0..6).map(|i| format!("CVE-2099-2{i:03}")).collect();
    let cves: Vec<&str> = cves.iter().map(String::as_str).collect();
    h.kev(&cves, T0 + 120);
    let mails = h.tick(T0 + 180);
    assert_eq!(mails.len(), 1, "{mails:?}");
    let after = h.open("site-a");
    assert_eq!(after.iter().map(|i| i.id).collect::<Vec<_>>(), before);
    assert!(
        after
            .iter()
            .all(|i| i.severity == vigie::finding::Severity::Critical)
    );

    // Un seul composant : même incident, critique, un e-mail d'ouverture.
    let h = wordpress(&[AgentPhp]);
    let comps = many(&h, 1, 75);
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    h.tick(T0 + 60);
    h.kev(&["CVE-2099-2000"], T0 + 120);
    let mails = h.tick(T0 + 180);
    assert_eq!(mails.len(), 1);
    assert_eq!(h.incidents("site-a").len(), 1);
    assert!(mails[0].body.contains("critique"));
}

fn budget(max_batches: usize) -> Budget {
    let far = Instant::now() + Duration::from_secs(3_600);
    Budget {
        deadline: far,
        hard_stop: far,
        max_batches,
    }
}

/// Passage du rapprochement seul, hors `tick`.
fn pass_at(h: &Harness, now: i64, budget: &Budget) -> pass::PassReport {
    let mut store = h.store();
    let reader = Store::open_read(&h.config.borrow().database)
        .unwrap()
        .unwrap();
    let tables = StoreTables::open(&reader).unwrap();
    pass::run(
        &mut store,
        &reader,
        &h.config.borrow(),
        &tables,
        now,
        budget,
    )
}

use vigie::store::Store;

#[test]
fn only_what_changed_is_redone() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    let first = pass_at(&h, T0 + 60, &budget(usize::MAX));
    assert_eq!(first.components, 1);
    assert_eq!(first.candidate_reads, 1);

    // Rien de changé : aucun lot, aucune écriture.
    let changes = h.count("SELECT total_changes()");
    let quiet = pass_at(&h, T0 + 120, &budget(usize::MAX));
    assert_eq!(quiet.batches, 0, "{quiet:?}");
    let _ = changes;

    // KEV seule : réévaluation, aucune plage relue, run neuf basculé.
    let run_before = h.count("SELECT active_run FROM vuln_match_state WHERE source = 'agent'");
    h.kev(&["CVE-2099-0001"], T0 + 180);
    let kev = pass_at(&h, T0 + 240, &budget(usize::MAX));
    assert_eq!(kev.candidate_reads, 0, "{kev:?}");
    assert_eq!(kev.components, 0);
    let run_after = h.count("SELECT active_run FROM vuln_match_state WHERE source = 'agent'");
    assert!(run_after > run_before);
    assert_eq!(
        h.open("site-a")[0].severity,
        vigie::finding::Severity::Critical
    );

    // Nouvelle génération de failles : tout est refait.
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0 + 300,
    );
    let redo = pass_at(&h, T0 + 360, &budget(usize::MAX));
    assert_eq!(redo.components, 1);

    // Correction de plage (F3) : époque changée, refait.
    h.raw()
        .execute(
            "INSERT INTO vuln_range_corrections (source, advisory_id, purl, ranges, reason,
                 operator, at, audit_hash)
             VALUES ('friends-of-presta', 'FOP-2099-9', 'pkg:prestashop/module/x', NULL, 'm',
                 'o', 1, ?1)",
            ["0".repeat(64)],
        )
        .unwrap();
    let corrected = pass_at(&h, T0 + 420, &budget(usize::MAX));
    assert_eq!(corrected.components, 1);

    // Renvoi inchangé : aucun run neuf.
    let run = h.count("SELECT active_run FROM vuln_match_state WHERE source = 'agent'");
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0 + 600,
    ));
    let resend = pass_at(&h, T0 + 660, &budget(usize::MAX));
    assert_eq!(resend.components, 0);
    assert_eq!(resend.commits, 1);
    assert_eq!(
        h.count("SELECT active_run FROM vuln_match_state WHERE source = 'agent'"),
        run
    );
}

#[test]
fn a_long_inventory_is_matched_one_batch_per_pass_and_switched_at_the_end() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0,
    );
    let comps: Vec<(String, String)> = (0..1_200)
        .map(|i| {
            (
                format!("pkg:composer/exemple/q{i}@1.0.0"),
                "vendor".to_owned(),
            )
        })
        .chain([(paquet("1.2.3"), "vendor".to_owned())])
        .collect();
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    for round in 1..=2 {
        let r = pass_at(&h, T0 + 60 * round, &budget(1));
        assert_eq!(r.batches, 1, "passage {round}");
        assert_eq!(
            h.count("SELECT count(*) FROM vuln_match_state WHERE active_run IS NOT NULL"),
            0,
            "aucun run partiel lu"
        );
        assert!(h.open("site-a").is_empty());
    }
    let r = pass_at(&h, T0 + 180, &budget(1));
    assert_eq!(r.batches, 1);
    assert_eq!(r.commits, 1);
    assert_eq!(h.open("site-a").len(), 1);
}

#[test]
fn a_match_epoch_change_before_the_switch_abandons_the_run() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0,
    );
    let comps: Vec<(String, String)> = (0..600)
        .map(|i| {
            (
                format!("pkg:composer/exemple/q{i}@1.0.0"),
                "vendor".to_owned(),
            )
        })
        .collect();
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    pass_at(&h, T0 + 60, &budget(1));
    let pending = h.count("SELECT pending_run FROM vuln_match_state");
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0 + 90,
    );
    let r = pass_at(&h, T0 + 120, &budget(usize::MAX));
    assert_eq!(r.commits, 1);
    let active = h.count("SELECT active_run FROM vuln_match_state");
    assert!(active > pending, "repris au début dans un run neuf");
}

#[test]
fn the_budget_allows_one_batch_and_none_past_the_hard_stop() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0,
    );
    let comps: Vec<(String, String)> = (0..1_100)
        .map(|i| {
            (
                format!("pkg:composer/exemple/q{i}@1.0.0"),
                "vendor".to_owned(),
            )
        })
        .collect();
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    let past = Instant::now();
    let none = pass_at(
        &h,
        T0 + 60,
        &Budget {
            deadline: past,
            hard_stop: past,
            max_batches: usize::MAX,
        },
    );
    assert_eq!(none.batches, 0);
    let one = pass_at(
        &h,
        T0 + 60,
        &Budget {
            deadline: past,
            hard_stop: Instant::now() + Duration::from_secs(60),
            max_batches: usize::MAX,
        },
    );
    assert_eq!(one.batches, 1, "le lot obligatoire seulement");
}

#[test]
fn slow_checks_leave_the_sends_their_reserved_time() {
    let h = wordpress(&[AgentPhp]);
    let comps = many(&h, 3, 75);
    accepted(h.inventory("site-a", Source::Agent, true, &refs(&comps), T0));
    // Tout le budget des envois déjà consommé avant l'étape : aucun lot,
    // et `notify` part quand même.
    {
        let mut options = h.options.borrow_mut();
        options.send_budget = Duration::from_millis(1);
        options.send_reserve = Duration::from_millis(1);
    }
    let started = Instant::now();
    let (summary, _) = h.tick_summary(T0 + 60);
    assert_eq!(summary.vulns_components, 0);
    assert!(started.elapsed() < Duration::from_secs(30));
    *h.options.borrow_mut() = vigie::tick::Options {
        check_budget: Duration::ZERO,
        ..vigie::tick::Options::default()
    };
    let (summary, mails) = h.tick_summary(T0 + 120);
    assert_eq!(summary.vulns_components, 3);
    assert_eq!(mails.len(), 3);
}

#[test]
fn a_corrupt_row_fails_its_site_only() {
    let h = Harness::new(
        vec![
            site("site-a", SiteKind::Wordpress, &[AgentPhp]),
            site("site-b", SiteKind::Wordpress, &[AgentPhp]),
        ],
        VULNS,
    );
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    for s in ["site-a", "site-b"] {
        accepted(h.inventory(
            s,
            Source::Agent,
            true,
            &[(&plugin("1.2.3"), PLUGIN_PATH)],
            T0,
        ));
    }
    h.tick(T0 + 60);
    h.raw()
        .execute(
            "UPDATE vuln_match_items SET facts = '{pas du json' WHERE site = 'site-a'",
            [],
        )
        .unwrap();
    // Un renvoi pour site-a seul : il est dû, sa ligne cassée est relue.
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0 + DAY,
    ));
    accepted(h.inventory(
        "site-b",
        Source::Agent,
        true,
        &[(&plugin("1.2.4"), PLUGIN_PATH)],
        T0 + DAY,
    ));
    let (summary, mails) = h.tick_summary(T0 + DAY + 60);
    assert_eq!(summary.vulns_errors, 1);
    assert!(
        h.open("site-b").is_empty(),
        "site-b rapproché malgré site-a"
    );
    let site_b: Vec<_> = mails
        .iter()
        .filter(|m| m.subject.contains("site-b"))
        .collect();
    assert_eq!(site_b.len(), 1, "e-mail de site-b envoyé : {mails:?}");
    assert_eq!(
        h.count("SELECT error_count FROM vuln_match_state WHERE site = 'site-a'"),
        1
    );
    // Retenté : un run neuf remplace la ligne cassée.
    let (summary, _) = h.tick_summary(T0 + DAY + 120);
    assert_eq!(summary.vulns_errors, 0);
    assert_eq!(
        h.count("SELECT error_count FROM vuln_match_state WHERE site = 'site-a'"),
        0
    );

    // Faille candidate illisible : site en erreur, retenté.
    h.raw()
        .execute("UPDATE vuln_affected SET ranges = 'cassé'", [])
        .unwrap();
    accepted(h.inventory(
        "site-b",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0 + 2 * DAY,
    ));
    let (summary, _) = h.tick_summary(T0 + 2 * DAY + 60);
    assert!(summary.vulns_errors >= 1);
    let (summary, _) = h.tick_summary(T0 + 2 * DAY + 120);
    assert!(summary.vulns_errors >= 1, "retenté au passage suivant");
}

#[test]
fn an_inventory_goes_stale_per_source() {
    let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
    s.runtime = None;
    let h = Harness::new(vec![s], VULNS);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    accepted(h.inventory("site-a", Source::Ci, true, &[], T0));
    h.tick(T0 + 60);
    // Seuil compté depuis max(dernier inventaire, déclaration) : la source
    // est vue déclarée au premier passage, T0 + 60.
    h.tick(T0 + 60 + 7 * DAY);
    assert!(h.by_key("site-a", "inventaire-perime-agent").is_empty());
    h.tick(T0 + 60 + 7 * DAY + 1);
    assert_eq!(h.by_key("site-a", "inventaire-perime-agent").len(), 1);
    assert!(h.by_key("site-a", "inventaire-perime-ci").is_empty());
    assert_eq!(
        h.by_key("site-a", PLUGIN)[0].closed_at,
        None,
        "constat gardé"
    );
    h.tick(T0 + 60 + 35 * DAY);
    assert!(h.by_key("site-a", "inventaire-perime-ci").is_empty());
    h.tick(T0 + 60 + 35 * DAY + 1);
    assert_eq!(h.by_key("site-a", "inventaire-perime-ci").len(), 1);

    // Renvoi inchangé : le constat de péremption se clôt.
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0 + 36 * DAY,
    ));
    h.tick(T0 + 36 * DAY + 60);
    let stale = &h.by_key("site-a", "inventaire-perime-agent")[0];
    assert_eq!(stale.close_reason, Some(CloseReason::Resolved));

    // Source déclarée sans aucun inventaire : comptée depuis la déclaration.
    let h = wordpress(&[AgentPhp]);
    h.tick(T0);
    h.tick(T0 + 7 * DAY + 2);
    assert_eq!(h.by_key("site-a", "inventaire-perime-agent").len(), 1);
}

#[test]
fn removals_close_unwatched_never_restored() {
    // site remove avec [sites.inventory] gardée : incidents gardés tels quels.
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    let before = h.open("site-a");
    assert!(h.store().remove_key("site-a", T0 + 120).unwrap());
    for table in [
        "vuln_match_state",
        "vuln_match_components",
        "vuln_match_items",
    ] {
        assert_eq!(
            h.count(&format!("SELECT count(*) FROM {table}")),
            0,
            "{table}"
        );
    }
    h.tick(T0 + 180);
    let after = h.open("site-a");
    assert_eq!(after[0].id, before[0].id);
    assert_eq!(after[0].detail, before[0].detail);
    // [sites.inventory] retirée : plus surveillé.
    h.config.borrow_mut().sites[0].inventory = None;
    let mails = h.tick(T0 + 240);
    assert!(h.open("site-a").is_empty());
    assert_eq!(
        h.incidents("site-a")[0].close_reason,
        Some(CloseReason::Unwatched)
    );
    assert!(mails.iter().all(|m| !m.subject.contains("rétabli")));

    // Source de failles retirée de [vulns] : plus surveillé.
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    h.config.borrow_mut().vulns.as_mut().unwrap().sources = vec!["osv-packagist".into()];
    let mails = h.tick(T0 + 120);
    assert!(h.open("site-a").is_empty());
    assert_eq!(
        h.incidents("site-a")[0].close_reason,
        Some(CloseReason::Unwatched)
    );
    assert!(
        mails.iter().all(|m| !m.subject.contains("rétabli")),
        "{mails:?}"
    );
}

#[test]
fn an_inventory_source_removed_closes_only_what_it_alone_saw() {
    let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
    s.runtime = None;
    let h = Harness::new(vec![s], VULNS);
    let other = ghsa("GHSA-2099-aaaa-0002", "CVE-2099-0002", 75);
    let other = Advisory {
        affected: vec![vigie::vulns::advisory::Affected {
            purl: vigie::vulns::purl::Purl::parse("pkg:composer/exemple/autre").unwrap(),
            ..other.affected[0].clone()
        }],
        ..other
    };
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75), other],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&paquet("1.2.3"), "vendor")],
        T0,
    ));
    accepted(h.inventory(
        "site-a",
        Source::Ci,
        true,
        &[("pkg:composer/exemple/autre@1.0.0", "composer.lock")],
        T0,
    ));
    h.tick(T0 + 60);
    assert_eq!(h.open("site-a").len(), 2);
    h.config.borrow_mut().sites[0].inventory = Some(vigie::config::SiteInventory::new(&[AgentPhp]));
    h.tick(T0 + 120);
    let open = h.open("site-a");
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].key, format!("site-a/vulns/{PAQUET}"));
    let closed = &h.by_key("site-a", "pkg:composer/exemple/autre")[0];
    assert_eq!(closed.close_reason, Some(CloseReason::Unwatched));
    assert_eq!(
        h.count("SELECT count(*) FROM vuln_match_state WHERE source = 'ci'"),
        0
    );
}

#[test]
fn lost_provenance_waits_for_every_source_that_carries_the_ecosystem() {
    let make = || {
        let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
        s.runtime = None;
        let h = Harness::new(vec![s], VULNS);
        h.load(
            "osv-packagist",
            &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
            T0,
        );
        accepted(h.inventory(
            "site-a",
            Source::Ci,
            true,
            &[(&paquet("1.2.3"), "composer.lock")],
            T0,
        ));
        accepted(h.inventory("site-a", Source::Agent, true, &[], T0));
        h.tick(T0 + 60);
        assert_eq!(h.open("site-a").len(), 1);
        assert!(h.store().remove_key("site-a", T0 + 120).unwrap());
        // Clés réenregistrées, inventaire complet de l'agent seul.
        let mut store = h.store();
        store
            .add_key(
                "site-a",
                &agent_key("site-a").verifying_key().to_bytes(),
                T0 + 130,
            )
            .unwrap();
        store
            .add_inventory_key(
                "site-a",
                &ci_key("site-a").verifying_key().to_bytes(),
                T0 + 130,
            )
            .unwrap();
        drop(store);
        h
    };
    let h = make();
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    assert_eq!(
        h.open("site-a")
            .iter()
            .filter(|i| i.key.contains("pkg:"))
            .count(),
        1,
        "ci requise"
    );
    accepted(h.inventory("site-a", Source::Ci, true, &[], T0 + 2 * DAY));
    h.tick(T0 + 2 * DAY + 60);
    let paquet_incident = &h.by_key("site-a", PAQUET)[0];
    assert_eq!(paquet_incident.close_reason, Some(CloseReason::Resolved));

    // Sans inventaire ci pendant 35 jours après le retrait : plus surveillé.
    let h = make();
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    h.tick(T0 + 120 + 35 * DAY + 1);
    let paquet_incident = &h.by_key("site-a", PAQUET)[0];
    assert_eq!(paquet_incident.close_reason, Some(CloseReason::Unwatched));
}

#[test]
fn ci_never_has_to_prove_a_wordpress_extension_gone() {
    let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
    s.runtime = None;
    let h = Harness::new(vec![s], VULNS);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    // CI incomplète (--omit-dev).
    accepted(h.inventory("site-a", Source::Ci, false, &[], T0));
    h.tick(T0 + 60);
    assert_eq!(h.by_key("site-a", PLUGIN).len(), 1);
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    assert_eq!(
        h.by_key("site-a", PLUGIN)[0].close_reason,
        Some(CloseReason::Resolved)
    );
}

#[test]
fn a_package_carried_by_partial_ci_closes_unwatched_after_35_days() {
    let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
    s.runtime = None;
    let h = Harness::new(vec![s], VULNS);
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&paquet("1.2.3"), "vendor")],
        T0,
    ));
    accepted(h.inventory(
        "site-a",
        Source::Ci,
        false,
        &[(&paquet("1.2.3"), "composer.lock")],
        T0,
    ));
    h.tick(T0 + 60);
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + DAY));
    accepted(h.inventory("site-a", Source::Ci, false, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    assert_eq!(
        h.by_key("site-a", PAQUET)[0].closed_at,
        None,
        "ci incomplète : gardé"
    );
    // Renvois de l'agent pour qu'il ne soit pas périmé.
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + 30 * DAY));
    h.tick(T0 + 30 * DAY + 60);
    assert_eq!(h.by_key("site-a", PAQUET)[0].closed_at, None);
    h.tick(T0 + 35 * DAY + 1);
    assert_eq!(
        h.by_key("site-a", PAQUET)[0].close_reason,
        Some(CloseReason::Unwatched)
    );
}

#[test]
fn a_package_seen_again_regains_its_view_and_ci_removed_is_no_longer_required() {
    let mut s = site("site-a", SiteKind::Wordpress, &[AgentPhp, Ci]);
    s.runtime = None;
    let h = Harness::new(vec![s], VULNS);
    h.load(
        "osv-packagist",
        &[ghsa("GHSA-2099-aaaa-0001", "CVE-2099-0001", 75)],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&paquet("1.2.3"), "vendor")],
        T0,
    ));
    accepted(h.inventory(
        "site-a",
        Source::Ci,
        true,
        &[(&paquet("1.2.3"), "composer.lock")],
        T0,
    ));
    h.tick(T0 + 60);
    // Perte de vue : agent complet sans lui, ci incomplète sans lui.
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + DAY));
    accepted(h.inventory("site-a", Source::Ci, false, &[], T0 + DAY));
    h.tick(T0 + DAY + 60);
    // Revu par l'agent : clé revue, aucune date de perte.
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&paquet("1.2.3"), "vendor")],
        T0 + 2 * DAY,
    ));
    h.tick(T0 + 2 * DAY + 60);
    assert_eq!(
        h.count("SELECT count(*) FROM vuln_match_keys WHERE lost_view_at IS NOT NULL"),
        0
    );
    // ci retirée de la configuration, paquet supprimé, agent complet.
    h.config.borrow_mut().sites[0].inventory = Some(vigie::config::SiteInventory::new(&[AgentPhp]));
    accepted(h.inventory("site-a", Source::Agent, true, &[], T0 + 3 * DAY));
    h.tick(T0 + 3 * DAY + 60);
    assert_eq!(
        h.by_key("site-a", PAQUET)[0].close_reason,
        Some(CloseReason::Resolved)
    );
}

#[test]
fn provenance_is_kept_only_for_keys_with_a_candidate() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[
            (&plugin("1.2.3"), PLUGIN_PATH),
            ("pkg:npm/sans-faille@1.0.0", "package.json"),
        ],
        T0,
    ));
    h.tick(T0 + 60);
    assert_eq!(h.count("SELECT count(*) FROM vuln_match_seen"), 1);
    assert_eq!(
        h.count("SELECT count(*) FROM vuln_match_seen WHERE key LIKE 'pkg:npm%'"),
        0
    );
}

#[test]
fn a_waiver_added_then_revoked_is_seen_by_the_next_pass() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 95, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    let waive = |id: i64, at: i64| {
        h.raw()
            .execute(
                "INSERT INTO vuln_waivers (id, site, source, base, advisory_ref, version,
                     covered_ids, reason, until, operator, created_at, audit_hash)
                 VALUES (?1, 'site-a', 'agent', ?2, 'CVE-2099-0001', '1.2.3',
                     '[\"CVE-2099-0001\",\"WF-2099-0001\"]', 'motif fictif', ?3, 'test', ?4, 'h')",
                rusqlite::params![id, PLUGIN, at + 30 * DAY, at],
            )
            .unwrap();
    };
    waive(1, T0 + 120);
    h.tick(T0 + 180);
    let open = h.open("site-a");
    assert_eq!(open[0].severity, vigie::finding::Severity::Info);
    assert!(open[0].detail.contains("sous dérogation"));
    waive(2, T0 + 200);
    for (id, at) in [(1, T0 + 240), (2, T0 + 300)] {
        h.raw()
            .execute(
                "UPDATE vuln_waivers SET revoked_at = ?2 WHERE id = ?1",
                rusqlite::params![id, at],
            )
            .unwrap();
        h.tick(at + 30);
    }
    assert_eq!(
        h.open("site-a")[0].severity,
        vigie::finding::Severity::Critical
    );

    // Échéance : la gravité remonte et l'e-mail d'ouverture repart.
    waive(3, T0 + 400);
    h.tick(T0 + 460);
    assert_eq!(h.open("site-a")[0].severity, vigie::finding::Severity::Info);
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0 + 5 * DAY,
    ));
    h.tick(T0 + 5 * DAY + 60);
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0 + 29 * DAY,
    ));
    h.tick(T0 + 29 * DAY + 60);
    let mails = h.tick(T0 + 400 + 30 * DAY);
    let incident = h.by_key("site-a", PLUGIN).pop().unwrap();
    assert_eq!(incident.severity, vigie::finding::Severity::Critical);
    let opened: Vec<_> = mails
        .iter()
        .filter(|m| m.subject.starts_with(&format!("[vigie] site-a : {PLUGIN}")))
        .collect();
    assert_eq!(opened.len(), 1, "e-mail d'ouverture renvoyé : {mails:?}");
}

#[test]
fn closed_vulns_incidents_are_masked_after_30_days() {
    let h = wordpress(&[AgentPhp]);
    h.load(
        "wordfence",
        &[wf("WF-2099-0001", "CVE-2099-0001", 75, "1.2.4")],
        T0,
    );
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.3"), PLUGIN_PATH)],
        T0,
    ));
    h.tick(T0 + 60);
    accepted(h.inventory(
        "site-a",
        Source::Agent,
        true,
        &[(&plugin("1.2.4"), PLUGIN_PATH)],
        T0 + DAY,
    ));
    h.tick(T0 + DAY + 60);
    let closed = h.incidents("site-a")[0].clone();
    h.config.borrow_mut().sites[0].inventory = None;
    h.tick(T0 + DAY + 60 + 30 * DAY + 1);
    let masked = h.store().incident(closed.id).unwrap().unwrap();
    assert_eq!(masked.key, format!("site-a/vulns/masque-{}", closed.id));
    assert!(!masked.detail.contains("exemple"), "{}", masked.detail);
    assert_eq!(
        h.count(
            "SELECT count(*) FROM check_runs WHERE check_name = 'vulns' AND detail LIKE '%exemple%'"
        ),
        0
    );
}
