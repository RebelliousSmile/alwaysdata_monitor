---
status: pending
---

# Instruction: Résultats stockés, passage de tick borné, contrôle vulns, inventaire périmé, e-mails

**Prérequis** : F1, F2, F3, F4 et F5 fusionnés. Avant de commencer, relire leurs plans tels qu'implémentés (noms de `candidates`, `last_inventory`, `StoreTables`, fonction de redistribution) et reporter tout écart dans la section « Interfaces reprises » de `plan.md`.

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/
    │   └── 0020.sql                   ✅ vuln_match_state, vuln_match_components, vuln_match_items, vuln_waivers (numéro : prochain libre à la fusion ; F3 0018, F4 0019 prévus)
    ├── src/
    │   ├── store.rs                   ✏️ entrée 20 de MIGRATIONS, SCHEMA_VULNS_MATCH ; remove_key purge vuln_match_* et vuln_waivers ; tests de dernière version et instantané du schéma
    │   ├── capability.rs              ✏️ Control::Vulns (« vulns ») en fin de Control::ALL (15) ; Needs::InventorySource (F5) ; en-tête du module complété
    │   ├── tick.rs                    ✏️ Options { vulns_budget: 10 s, vulns_max_batches } ; étape « rapprochement des failles » après l'analyse de logs ; Summary.vulns_components ; purge et masquage
    │   ├── alert.rs                   ✏️ incident vulns : objet = première ligne du détail ; corps : commande vigie site vulns, mention « usage interne »
    │   └── vulns/
    │       └── matching/
    │           ├── epoch.rs           ✅ match_epoch (générations actives des sources de failles, dernière correction F3), enrich_epoch (kev, epss)
    │           ├── store.rs           ✅ état par site, réservation de run, lots, bascule en compare-and-swap, purge par lots, lectures pour l'API et la CLI
    │           └── pass.rs            ✅ run(store, config, tables, now, deadline, max_batches) -> PassReport : sites à refaire, à tour de rôle, lots de 500, cache par purl, réconciliation
    └── tests/
        ├── vulns_match_pass.rs        ✅ bout en bout sur base réelle : inventaires F5 et failles F1 écrits par les bibliothèques, tick::run_with, FakeClock, MemoryNotifier
        ├── vulns_match_budget.rs      ✅ #[ignore] : 200 sites × 2 000 composants, mesuré en release
        ├── capability.rs              ✏️ Control::ALL à 15, vulns surveillé ssi [sites.inventory]
        └── store_concurrency.rs       ✏️ rapprochement en lots pendant les écritures de serve et une synchronisation
```

## Test Scope

```mermaid
journey
  section Setup
    Base à la version précédente => migration 20 appliquée, instantané du schéma à jour: 5: system
  section Ouverture et résolution
    Inventaire site-a avec exemple-plugin 1.2.3, puis tick => incident site-a/vulns/pkg:wordpress/plugin/exemple-plugin, e-mail d'ouverture: 5: tick
    Inventaire suivant (complet) avec 1.2.4, puis tick => incident clos rétabli: 5: tick
    Inventaire suivant complet sans exemple-plugin => clos rétabli: 5: tick
    Inventaire suivant incomplet sans exemple-plugin => incident gardé, « absent d'un relevé partiel », rapproché sur 1.2.3: 1: tick
    Module PrestaShop à quatre composants sur site-b => ouvert, puis clos à la version corrigée: 5: tick
  section Un incident par composant
    Extension à 30 failles => un seul incident, un seul e-mail: 5: tick
    CVE d'une faille ouverte ajouté à KEV (nouvelle génération kev), tick => même incident, gravité critique, nouvel e-mail d'ouverture, aucun incident créé: 5: tick
    enrich_epoch seule changée => aucune plage relue (compteur de candidates à 0), gravités réévaluées: 1: tick
  section Déclenchement
    Nouvel inventaire reçu par serve => rapproché au passage de tick suivant: 5: tick
    Nouvelle génération osv-packagist => tous les sites refaits, les plus anciens d'abord: 5: tick
    Correction de plage F3 ajoutée => match_epoch changée, sites refaits: 1: tick
    Rien de changé => aucun lot, aucune écriture: 5: tick
  section Budget et reprise
    vulns_max_batches = 1, site de 1 200 composants => un lot par passage, curseur gardé, bascule au troisième passage, l'API ne voit que l'ancien run jusque-là: 1: tick
    match_epoch changée en cours de run => run abandonné, site repris au début: 1: tick
    Deux sites à refaire, budget d'un site => le plus ancien d'abord, l'autre au passage suivant: 1: tick
  section Péremption
    seen_at à 7 jours + 1 s => avertissement inventaire-perime, constats de composants gardés: 5: tick
    Nouvel inventaire => inventaire-perime clos rétabli: 5: tick
    [sites.inventory] déclarée, aucun inventaire depuis 7 jours + 1 s (méta vulns.inventory.declared) => inventaire-perime: 1: tick
  section Dérogation
    Dérogation écrite en base (phase 3 simulée par la bibliothèque) => groupe retiré, incident passé en information, aucun e-mail: 5: tick
    Expiration (FakeClock) => gravité rendue, e-mail d'ouverture sur le même incident: 5: tick
  section Registre et clôtures
    Control vulns => nom unique, Control::ALL à 15, jamais surveillé sans [sites.inventory]: 5: lib
    [sites.inventory] retirée => incidents vulns clos plus surveillé, résultats supprimés au passage suivant: 1: tick
    Site retiré de la configuration => idem: 1: tick
    site remove => vuln_match_* et vuln_waivers vides pour le site: 1: lib
  section Minimisation
    Incident vulns clos depuis 30 jours + 1 s => détail et clé masqués ; un incident ouvert jamais touché: 1: tick
  section E-mails
    Objet => [vigie] site-a : première ligne du détail, sur une ligne: 5: tick
    Groupe Wordfence => corps porte « usage interne » et l'attribution: 1: tick
  section Base antérieure
    Base sans tables de failles ou d'inventaire => tick inchangé, aucune erreur: 1: tick
  section Volume, en release
    200 sites × 2 000 composants, 20 000 failles fictives => chaque passage ≤ budget + un lot ; tous les sites rapprochés en N passages (N relevé) ; transaction d'écriture la plus longue < 100 ms: 1: ci
  section Contention
    Rapprochement en lots pendant les écritures de serve et un chargement F1 => aucun SQLITE_BUSY, aucune écriture perdue: 1: lib
```

## Tasks to do

1. **Migration 0020** (prochain numéro libre ; `SCHEMA_VULNS_MATCH`, commentaire de `MIGRATIONS`) :
   - `vuln_match_state (site TEXT PRIMARY KEY, inventory_id INTEGER, match_epoch TEXT, enrich_epoch TEXT, active_run INTEGER, pending_run INTEGER, pending_inventory_id INTEGER, pending_match_epoch TEXT, cursor_base TEXT, cursor_path TEXT, dirty_since INTEGER, matched_at INTEGER, next_waiver_check INTEGER, next_run INTEGER NOT NULL DEFAULT 1)` ;
   - `vuln_match_components (site, run, base, path, purl, version, ecosystem, scope, severity CHECK IN ('info','warning','critical') OR NULL, groups INTEGER, PRIMARY KEY (site, run, base, path)) WITHOUT ROWID` ; index `(site, run, severity, base)` ;
   - `vuln_match_items (site, run, base, path, group_key, verdict CHECK IN ('affected','unknown'), reason, severity, rule, fixed, members TEXT (JSON : id, source, lien, licence, attribution, `corrected`), facts TEXT (JSON, `GroupFacts`), kev INTEGER, epss_ppm INTEGER, score_tenths INTEGER, redistribution CHECK IN ('internal','facts_only','free'), PRIMARY KEY (site, run, base, path, group_key)) WITHOUT ROWID` ; index `(site, run, severity, base, path, group_key)` pour la pagination ;
   - `vuln_waivers (id INTEGER PRIMARY KEY AUTOINCREMENT, site, base, advisory_ref, version, reason, until, operator, created_at, revoked_at, revoke_reason, audit_hash)` ; index `(site, base)` ; `CHECK` de longueur (motif ≤ 500, base ≤ 256, référence ≤ 64, version ≤ 128) et `until - created_at <= 90 * 86400` ;
   - montée d'une base remplie depuis la version précédente sans perte ; instantané `migration_files_build_the_expected_schema`.
2. **`capability.rs`** : `Control::Vulns`, nom `vulns`, en fin de `Control::ALL` (15) ; `cms()` → `ALL_CMS` ; `needs()` → `Needs::InventorySource` ; `watched` : `inventory_source(site).is_some()` ; `is_agent()` → `false` ; `match` sans joker partout ; en-tête du module complété.
3. **`matching/epoch.rs`** : `match_epoch(store)` = SHA-256 de la liste triée `(source, active_generation)` des sources de failles et du dernier `id` de `vuln_range_corrections` (prérequis F1-3, F3-3) ; `enrich_epoch(store)` = générations actives de `kev` et `epss` ; une lecture, aucune écriture.
4. **`matching/store.rs`** :
   - `due_sites(now)` : sites de la configuration avec `[sites.inventory]` dont l'inventaire le plus récent (`inventory_heads`, prérequis F5-1), la `match_epoch`, l'`enrich_epoch` ou `next_waiver_check` diffère de l'état, triés par `dirty_since` puis identifiant ;
   - `begin_run(site)` : réserve `next_run` en IMMEDIATE, fixe `pending_*` et le curseur ; un run en cours dont l'époque ou l'inventaire a changé est abandonné (rangées purgées) ;
   - `push(site, run, &[ComponentResult])` : une transaction IMMEDIATE par lot de 500 composants, curseur avancé dans la même transaction, run revérifié (`pending_run`) ;
   - `commit_run(site, run)` : compare-and-swap `active_run = run WHERE pending_run = run`, état mis à jour ; puis purge par lots de l'ancien run ;
   - `reassess(site, tables)` : `enrich_epoch` seule changée → relit `facts` des items de l'`active_run`, réévalue par F4, met à jour gravités en place (transaction par lot) ;
   - lectures : `components_page`, `items_page`, `site_summary`, `report_rows` (phases 3 et 4) ;
   - `purge_unwatched(config)` : état et rangées des sites absents de la configuration ou sans `[sites.inventory]` ;
   - `mask_closed(now)` : `UPDATE incidents SET detail = MASKED, key = site || '/vulns/masque-' || id WHERE check_name = 'vulns' AND closed_at < now - 30 j AND detail <> MASKED`.
5. **`matching/pass.rs`** : `run(store, config, tables, now, deadline, max_batches) -> PassReport` :
   1. sites dus ; pour chacun, tant que l'échéance n'est pas atteinte : composants du dernier inventaire par lots de 500 depuis le curseur (`inventory_components`, prérequis F5-1), filtrés par `admitted` ; pour un inventaire **incomplet**, ajout des composants de l'`active_run` absents de l'inventaire, sur leur dernière version, marqués « absent d'un relevé partiel » ;
   2. candidats par purl sans version (`candidates`, prérequis F1-2), cache `HashMap` de 10 000 entrées vidé au changement d'époque ; phase 1 (`group`, `assess`) ;
   3. au dernier lot : `commit_run`, puis `reconcile(site, "vulns", findings, now)` avec les constats de composants (`component_finding`, dérogations de `vuln_waivers` lues pour le site) et `stale_finding` ; `record_result` ; `next_waiver_check` = plus proche `until` à venir ;
   4. un site dont seule l'`enrich_epoch` a changé passe par `reassess`, puis `reconcile`.
6. **`tick.rs`** : `Options.vulns_budget` (10 s) et `vulns_max_batches` ; étape après l'analyse de logs : échéance `min(Instant::now() + vulns_budget, start + send_budget)` ; `StoreTables::open` (F4) une fois par passage ; méta `vulns.inventory.declared.<site>` écrite au premier passage qui voit `[sites.inventory]`, supprimée quand elle disparaît ; `purge_unwatched` et `mask_closed` avec les autres purges, erreurs journalisées sans arrêter le passage ; `close_unwatched` existant (prédicat de F2) clôt « plus surveillé » ; base antérieure à `SCHEMA_VULNS_MATCH` : étape sautée ; journal du passage : sites rapprochés, composants, lots, durée ; « budget atteint, la suite au passage suivant » comme l'analyse de logs.
7. **`alert.rs`** : pour `check_name == "vulns"`, objet = `[vigie] <site> : ` + première ligne du détail (`one_line`, 200 caractères) ; corps : en-tête existant, puis « Détail : `vigie site vulns <site>` » et, si le détail porte « usage interne », la phrase « contenu Wordfence ou Friends-Of-Presta : usage interne, ne pas transmettre ». Tests : objet sur une ligne, aucune clôture « rétabli » pour un incident passé en information par dérogation.
8. **`store.rs`** : `remove_key` purge `vuln_match_state`, `vuln_match_components`, `vuln_match_items`, `vuln_waivers` du site (l'inventaire est purgé par F5).
9. **Tests** :
   - `vulns_match_pass.rs` : chaque cas « tick » du Test Scope, base remplie par les bibliothèques de F1 (`Load`), F4 (`EnrichLoad`) et F5 (`accept_inventory`) sur fixtures fictives de la phase 1 ; `tick::run_with` avec `FakeClock`, `MemoryNotifier` ; compteur d'appels de `candidates` pour l'époque d'enrichissement ;
   - `vulns_match_budget.rs` (`#[ignore]`, pas CI Linux `cargo test --release --locked --test vulns_match_budget -- --ignored`) : 200 sites, 2 000 composants chacun (40 % partagés entre sites), 20 000 failles fictives générées en flux, budget de production ; affirme la durée de chaque passage (≤ budget + durée du lot le plus long), le nombre de passages pour tout rapprocher (relevé dans la PR), la transaction d'écriture la plus longue (< 100 ms) ;
   - `capability.rs` (registre), `store_concurrency.rs` (contention), tests de migration.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1, 8 | Migration depuis la version précédente verte ; `MIGRATIONS.len() == SCHEMA_VULNS_MATCH` ; rejouée sans effet ; instantané à jour ; `site remove` vide les quatre tables pour le site |
| 2 | `Control::ALL` à 15, noms uniques ; `vulns` surveillé ssi `[sites.inventory]` ; aucun incident `vulns` sur un site sans source d'inventaire |
| 3-5 | Cas « Ouverture et résolution », « Un incident par composant », « Déclenchement », « Budget et reprise », « Péremption », « Dérogation » verts ; un lecteur ne voit jamais un run partiel ; une faille entrée dans KEV fait monter le même incident au passage suivant |
| 6 | Le rapprochement ne commence aucun lot après l'échéance ; un passage sans changement n'écrit rien ; base antérieure : `tick` inchangé |
| 7 | Objets sur une ligne ; aucun e-mail pour un incident d'information ; « usage interne » présent quand un groupe est `Internal` ou `FactsOnly` |
| 9 | Test de volume vert en release, chiffres consignés dans la PR ; contention sans `SQLITE_BUSY` ni écriture perdue sur Linux et Windows |
| 1-9 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
