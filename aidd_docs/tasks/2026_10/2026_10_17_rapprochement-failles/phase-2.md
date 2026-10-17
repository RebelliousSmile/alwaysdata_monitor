---
status: pending
---

# Instruction: Résultats stockés, passage de tick borné, contrôle vulns, péremption, e-mails

**Prérequis** : F1, F2, F3, F4, F5 **et F6** fusionnés (F6 fusionne avant F7 : `inventory_heads()` par (site, source) avec `InventoryHead.source`, `inventory_sources(site)`, `last_inventory(site, source)`, colonne `site_inventory.source`, `inventory::stale_after(source)`). Avant de commencer, relire les plans tels qu'implémentés et reporter tout écart dans « Interfaces reprises » de `plan.md` ; la constante provisoire de péremption de la phase 1, s'il y en a une, est remplacée par `inventory::stale_after`.

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/
    │   └── 0020.sql                   ✅ vuln_match_runs, vuln_match_state, vuln_match_components, vuln_match_items, vuln_waivers, toutes clés par source (numéro : prochain libre à la fusion ; 0021 si F6 fusionne avant)
    ├── src/
    │   ├── store.rs                   ✏️ entrée de MIGRATIONS, SCHEMA_VULNS_MATCH ; reconcile_in en pub(crate) ; remove_key purge vuln_match_*, vuln_waivers et check_runs de vulns ; tests de dernière version et instantané du schéma
    │   ├── capability.rs              ✏️ Control::Vulns (« vulns ») en fin de Control::ALL (15) ; Needs::InventorySource (inventory_sources(site) non vide, sans condition de clé)
    │   ├── tick.rs                    ✏️ Options { vulns_budget: 10 s, send_reserve: 10 s, vulns_max_batches } ; étape F7 après l'analyse de logs, jamais d'erreur propagée ; Summary.vulns_components, vulns_errors ; notify : synthèse vulns par site au-delà de 5 ouvertures
    │   ├── alert.rs                   ✏️ objet vulns = première ligne du détail ; vulns_grouped_open, vulns_grouped_reminder, vulns_grouped_close (site, incidents) ; mention « usage interne »
    │   └── vulns/
    │       └── matching/
    │           ├── epoch.rs           ✅ match_epoch (active_generations des sources déclarées, latest_range_correction_id), enrich_epoch (kev, epss), waiver_epoch(site) = (max(id), max(revoked_at), count)
    │           ├── store.rs           ✅ état par (site, source), runs à séquence globale, lots à compare-and-swap du curseur, commit_run + reconcile_in dans une transaction, réévaluation en nouveau run, purges, lectures
    │           └── pass.rs            ✅ run(store, config, tables, now, deadline, max_batches) -> PassReport : (site, source) dus, à tour de rôle, au moins un lot, Result par site, reconstruction complète des constats du site
    └── tests/
        ├── vulns_match_pass.rs        ✅ bout en bout sur base réelle (F1, F4, F5 écrits par leurs bibliothèques), tick::run_with, FakeClock, MemoryNotifier
        ├── vulns_match_budget.rs      ✅ #[ignore] : 200 sites × 2 000 composants, données réalistes, mesuré en release
        ├── capability.rs              ✏️ Control::ALL à 15, vulns surveillé ssi inventory_sources(site) non vide
        └── store_concurrency.rs       ✏️ lots pendant les écritures de serve, un chargement F1 et un second tick
```

## Test Scope

```mermaid
journey
  section Setup
    Base à la version précédente => migration appliquée, instantané du schéma à jour: 5: system
  section Ouverture et résolution
    Inventaire agent de site-a avec exemple-plugin 1.2.3, puis tick => incident site-a/vulns/pkg:wordpress/plugin/exemple-plugin, e-mail d'ouverture: 5: tick
    Inventaire agent suivant (complet) avec 1.2.4 => clos rétabli: 5: tick
    Inventaire agent complet sans exemple-plugin => clos rétabli: 5: tick
    Inventaire agent incomplet sans exemple-plugin => incident gardé, « absent d'un relevé partiel », rapproché sur 1.2.3: 1: tick
    Reporté : last_seen_at (dernier inventaire, même partiel, qui le contenait) à 7 j + 1 s => plus reporté, clos plus surveillé, jamais rétabli: 1: tick
    Inventaires partiels alternant avec et sans exemple-plugin pendant 20 jours => un seul incident, jamais clos ni rouvert: 1: tick
    Composant vu la première fois dans un inventaire partiel, absent du suivant => reporté depuis sa première vue: 1: tick
    Module PrestaShop à quatre composants sur site-b => ouvert, puis clos à la version corrigée: 5: tick
  section Deux sources (vraies tables de F5 et F6, sources agent et ci déclarées)
    agent 1.2.3 touché, ci 1.2.4 complet => incident ouvert, détail « agent : 1.2.3 ; ci : 1.2.4 »: 5: tick
    ci complet sans le composant, agent le voit encore => incident gardé: 1: tick
    agent complet sans le composant, ci le voit encore à une version touchée => incident gardé: 1: tick
    Les deux complets sans le composant => clos rétabli: 1: tick
    Dérogation sur la version ci => sans effet sur la vue agent: 1: tick
  section Seuils et battement
    Composant à failles d'information seulement => aucun incident: 5: tick
    EPSS 0,09 → 0,11 → 0,09 (trois générations epss) => un seul incident, ouvert à 0,11, passé en information à 0,09, aucun e-mail rétabli: 1: tick
  section Un incident par composant, synthèse
    Extension à 30 failles => un seul incident, un seul e-mail: 5: tick
    5 ouvertures vulns en attente sur site-a => 5 e-mails: 5: tick
    6 ouvertures vulns en attente sur site-a => 1 e-mail groupé (comptes par gravité, 10 plus graves), 6 incidents marqués notifiés dans une transaction: 5: tick
    6 rappels vulns dus sur site-a => 1 rappel groupé, mark_reminded sur les 6 dans une transaction: 5: tick
    6 clôtures vulns à annoncer sur site-a => 1 e-mail de clôture groupé: 5: tick
    Envoi groupé réussi puis marquage en échec (injecté) => e-mail groupé renvoyé au passage suivant (doublon documenté), jamais 6 e-mails: 1: tick
    Synthèse en échec d'envoi => rien de marqué ; passage suivant => 1 synthèse, jamais 6 e-mails: 1: tick
    CVE ajouté à KEV touchant 6 composants ouverts => 1 synthèse, même incidents, gravité critique, aucun incident créé: 5: tick
    CVE ajouté à KEV touchant 1 composant => même incident, critique, 1 e-mail d'ouverture: 5: tick
    enrich_epoch seule changée => aucune plage relue (compteur de candidates à 0), nouveau run basculé: 1: tick
  section Déclenchement
    Nouvel inventaire reçu par serve => rapproché au passage suivant: 5: tick
    Renvoi inchangé (seul seen_at avance) => aucun nouveau run, inventaire-perime-agent clos rétabli s'il était ouvert: 5: tick
    Nouvelle génération osv-packagist => tous les (site, source) refaits, les plus anciens d'abord: 5: tick
    Correction de plage F3 => match_epoch changée, refait: 1: tick
    Dérogation ajoutée par la bibliothèque de la phase 3 => waiver_epoch changée, vue au passage suivant: 5: tick
    Deux dérogations retirées l'une après l'autre (count(revoked_at)) => chacune vue au passage suivant: 1: tick
    Dérogation retirée => vue au passage suivant, gravité rendue: 5: tick
    Rien de changé => aucun lot, aucune écriture: 5: tick
  section Budget, reprise, concurrence
    vulns_max_batches = 1, site de 1 200 composants => un lot par passage, curseur after_rowid gardé, bascule au troisième passage, l'API ne voit que l'ancien run jusque-là: 1: tick
    match_epoch changée entre le début du run et commit_run => compare-and-swap refusé, run abandonné, repris au début: 1: tick
    Deux tick concurrents sur le même run => un seul lot écrit par position de curseur: 1: lib
    Contrôles et analyse de logs qui consomment tout le temps jusqu'à start + send_budget − send_reserve (sources lentes injectées) => un lot de F7 au plus, aucun si now ≥ start + send_budget − send_reserve / 2, e-mails envoyés avant start + send_budget: 1: tick
    Processus tué entre bascule et réconciliation (panique injectée dans la transaction) => ni bascule ni incidents écrits: 1: lib
  section Erreurs isolées
    Ligne corrompue dans vuln_match_items d'un site (JSON illisible) => erreur journalisée et comptée, autres sites rapprochés, e-mails envoyés, tick en succès: 1: tick
    Faille candidate illisible pour un composant => site en erreur, retenté au passage suivant: 1: tick
  section Péremption
    Agent silencieux : seen_at à 7 j + 1 s => inventaire-perime-agent, constats de composants gardés: 5: tick
    Source ci : seen_at à 7 j + 1 s => rien ; à 35 j + 1 s => inventaire-perime-ci: 1: tick
    Source déclarée, aucun inventaire depuis 7 j + 1 s (méta de déclaration) => inventaire-perime-agent: 1: tick
  section Aucun inventaire, retrait
    site remove avec [sites.inventory] gardée => résultats purgés, incidents de composants gardés tels quels, jamais rétabli: 1: tick
    [sites.inventory] retirée ensuite => incidents vulns clos plus surveillé: 1: tick
    Source de failles retirée de [vulns], constat qui n'en dépendait que d'elle => clos plus surveillé: 1: tick
    Source ci retirée de [sites.inventory], agent gardée => site dû, état et run ci supprimés, constats vus seulement par ci clos plus surveillé, constats vus par agent gardés: 1: tick
    Aucun inventaire, incidents ouverts => reconcile_in reçoit des Finding identiques, aucune ligne d'incident modifiée: 1: tick
    Deux sources, site remove, puis inventaire complet de l'agent seul (paquet composer vu seulement par ci, provenance perdue) => l'incident reste ouvert, aucun rétabli: 1: tick
    Même cas, puis inventaire complet de ci sans le composant => clos rétabli: 1: tick
    Même cas sans nouvel inventaire ci pendant 35 j + 1 s après le site remove => clos plus surveillé, jamais rétabli: 1: tick
    agent + ci incomplète (--omit-dev), extension WordPress vue par l'agent seul puis retirée, inventaire agent complet => clos rétabli (ci ne porte pas wordpress): 5: tick
    Paquet composer vu par agent et ci, retiré : agent complet sans lui, ci toujours incomplète => gardé ; ci à last_seen_at + 35 j + 1 s => clos plus surveillé: 1: tick
    Provenance perdue, aucune autre date : clos plus surveillé à lost_view_at + stale_after, jamais rétabli: 1: tick
    Composant revu après avoir perdu sa vue => lost_view_at remis à NULL, provenance gardée: 1: tick
    Paquet composer vu par agent et ci, ci retirée de la configuration, paquet supprimé, inventaire agent complet => clos rétabli (ci plus requise): 1: tick
    Composant sans faille candidate => aucune ligne dans vuln_match_seen: 1: tick
  section Registre
    Control vulns => nom unique, Control::ALL à 15 ; non surveillé si inventory_sources(site) est vide: 5: lib
  section Minimisation
    Incident vulns clos depuis 30 j + 1 s => détail et clé masqués ; check_runs.detail de vulns masqué ; incident ouvert intact: 1: tick
    site remove => vuln_match_*, vuln_waivers et check_runs de vulns vides pour le site: 1: lib
  section Base antérieure
    Base sans tables de failles ou d'inventaire => étape sautée, aucune erreur: 1: tick
  section Volume, en release
    200 sites × 2 000 composants (40 % partagés), 20 000 failles fictives dont des lignes Packagist à 2 340 versions[] => chaque passage ≤ échéance + un lot ; lot le plus long ≤ 1 s ; tout couvert en N passages (relevé) ; transaction d'écriture la plus longue < 100 ms: 1: ci
```

## Tasks to do

1. **Migration 0020** (prochain numéro libre ; `SCHEMA_VULNS_MATCH`) :
   - `vuln_match_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, site, source, started_at)` : séquence globale des runs ;
   - `vuln_match_state (site, source CHECK IN ('agent','ci'), inventory_id, seen_at, declared_sources, match_epoch, enrich_epoch, waiver_epoch, next_stale_check, next_waiver_check, active_run, pending_run, pending_inventory_id, pending_match_epoch, cursor_rowid INTEGER NOT NULL DEFAULT 0, due_since, error_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (site, source))` ;
   - `vuln_match_components (site, source, run, base, path, purl, version, ecosystem, scope, carried, first_seen_at, last_seen_at, severity NULL ou CHECK, groups, PRIMARY KEY (site, source, run, base, path)) WITHOUT ROWID` (`last_seen_at` = date du dernier inventaire de la source, complet ou partiel, qui contenait le composant ; initialisé à la première vue, recopié d'un run à l'autre) ;
   - `vuln_match_items (site, source, run, base, path, group_key, verdict CHECK IN ('affected','unknown'), reason, severity, rule, fixed, members TEXT (JSON : identifiant, source, `corrected` ; jamais d'attribution), facts TEXT (JSON `GroupFacts`), covered_ids TEXT (JSON), kev, epss_ppm, score_tenths, redistribution, PRIMARY KEY (site, source, run, base, path, group_key)) WITHOUT ROWID` ; index `(site, run, severity, base, path, group_key)` pour la pagination ;
   - `vuln_match_seen (site, key, source CHECK IN ('agent','ci'), first_seen_at, last_seen_at, PRIMARY KEY (site, key, source)) WITHOUT ROWID` : provenance d'un purl sans version, hors des runs ;
   - `vuln_match_keys (site, key, lost_view_at, PRIMARY KEY (site, key)) WITHOUT ROWID` : date où l'incident a perdu sa dernière vue ;
   - `vuln_waivers (id INTEGER PRIMARY KEY AUTOINCREMENT, site, source, base, advisory_ref, version, covered_ids, reason, until, operator, created_at, revoked_at, revoke_reason, audit_hash)` ; index `(site, base)` ; `CHECK` de longueur et `until - created_at <= 90 * 86400` ;
   - montée d'une base remplie depuis la version précédente sans perte ; instantané du schéma.
2. **`capability.rs`** : `Control::Vulns` en fin de `Control::ALL` (15), `ALL_CMS`, `Needs::InventorySource` : surveillé ssi `inventory_sources(site)` (F6) est non vide ; aucune condition de clé ; `match` sans joker.
3. **`matching/epoch.rs`** : `match_epoch` (SHA-256 de `active_generations()` restreint aux sources déclarées, et de `latest_range_correction_id()`), `enrich_epoch`, `waiver_epoch(site)` = (`max(id)`, `max(revoked_at)`, `count(*)`, `count(revoked_at)`), `declared_sources(site)` (triées) ; lectures seules.
4. **`matching/store.rs`** :
   - `due(now)` : par (site, source) déclaré, tête d'inventaire (`inventory_heads`, F6), époques, ensemble des sources déclarées, `seen_at`, `next_stale_check = max(seen_at, déclaration) + inventory::stale_after(source)`, `next_waiver_check` ; une source qui n'est plus déclarée rend le site dû et voit son état et son run supprimés (dans `commit_and_reconcile`) ; triés par `due_since` puis site ; un (site, source) en erreur passe après les autres ;
   - `begin_run` : id de `vuln_match_runs` (séquence globale) en IMMEDIATE, `pending_*`, `cursor_rowid = 0` ;
   - `push(site, source, run, expected_cursor, &[ComponentResult], new_cursor)` : une transaction IMMEDIATE par lot de 500, `UPDATE … SET cursor_rowid = new WHERE pending_run = run AND cursor_rowid = expected` (zéro ligne → abandon du lot) ;
   - `build_findings(site, now) -> SiteSnapshot` : **lecture hors transaction** : runs actifs de toutes les sources, dérogations, incidents `vulns` ouverts (`already_open`), état ; rend les constats et l'empreinte de ce qui a été lu ;
   - `commit_and_reconcile(site, source, run, snapshot)` : **une** transaction IMMEDIATE : revérifie l'empreinte (runs actifs et en cours, `pending_match_epoch` = `match_epoch` relue, `waiver_epoch`, sources déclarées, ids des incidents ouverts ; écart → rien d'écrit, site dû) ; compare-and-swap `active_run = run WHERE pending_run = run` ; suppression de l'état et du run d'une source d'inventaire retirée ; **d'abord** clôture `unwatched` des constats qui ne tenaient qu'à une source retirée (inventaire ou failles) ou à un report échu, **puis** `reconcile_in(site, "vulns", findings, now)` ; puis, hors transaction, purge par lots de l'ancien run ;
   - `reassess(site, source, tables)` : nouveau run copié par lots depuis l'actif, gravités recalculées depuis `facts` (F4), puis `commit_and_reconcile` ;
   - `refresh(site, tables)` : sans nouveau run (`waiver_epoch`, `seen_at`, échéances, sources déclarées) : `build_findings`, puis même transaction sans bascule ;
   - **provenance** : à chaque bascule, **dans la transaction de `commit_and_reconcile`**, `vuln_match_seen` est mise à jour pour chaque (purl sans version, source) vu par le run **et ayant au moins une faille candidate** (les autres clés n'y entrent jamais) (`first_seen_at`, `last_seen_at`) ; ses lignes ne sont pas supprimées quand le composant disparaît ; purge à la clôture de l'incident (dans `commit_and_reconcile`) ou quand `now − last_seen_at` dépasse `inventory::stale_after(source)` sans incident ouvert ; `vuln_match_keys.lost_view_at` posé quand la clé quitte tous les runs actifs, remis à NULL quand elle y revient ;
   - `source_carries(source, ecosystem)` : `match` sans joker (`agent` : `wordpress`, `prestashop`, `composer`, `npm` ; `ci` : `composer`, `npm`, `cargo`, F5 `plan.md` l. 45 et F6 « hors périmètre ») ;
   - **incident sans vue** : pour chaque incident `vulns` de composant ouvert absent de **tous** les runs actifs, `build_findings` rend un `Finding` **identique** (clé, gravité, détail) ; sources requises = sources de `vuln_match_seen` pour la clé ∩ sources déclarées ∩ `source_carries`, ou, sans provenance, toutes les sources déclarées qui portent l'écosystème ; clos « rétabli » si chaque source requise a un inventaire complet, postérieur à son `last_seen_at` (ou à `lost_view_at`), sans le composant ; sinon gardé, puis clos « plus surveillé » dans `commit_and_reconcile` quand `now` atteint `inventory::stale_after(source requise manquante)` compté depuis son `last_seen_at`, ou depuis `lost_view_at` sans provenance ; plus les constats de péremption ;
   - lectures pour l'API et la CLI : `components_page`, `items_page`, `site_summary`, `report_rows` ;
   - purges : `purge_unwatched(config)` ; `mask_closed(now)` : incidents `vulns` clos depuis 30 jours (détail, clé `<site>/vulns/masque-<id>`) et `check_runs.detail` du contrôle `vulns` plus vieux que 30 jours.
5. **`matching/pass.rs`** : pour chaque (site, source) dû, dans un `Result` propre (erreur journalisée sans texte de la base, comptée, `error_count` et `due_since` mis à jour, passage au suivant) :
   1. inventaire changé ou `match_epoch` changée : lots de `inventory_components(id, cursor_rowid, 500)` filtrés par `admitted`, `last_seen_at` mis à la date de l'inventaire (complet ou partiel) ; pour un inventaire incomplet, composants de l'actif absents ajoutés comme reportés tant que `now − last_seen_at` < `inventory::stale_after(source)` ; candidats (`candidates`, F1) par le cache borné en poids ; phase 1 ; dernier lot → `build_findings` puis `commit_and_reconcile` ;
   2. `enrich_epoch` seule : `reassess` ;
   3. sinon : `refresh` ;
   4. un lot obligatoire par passage, sauf si `now ≥ start + send_budget − send_reserve / 2` ; puis échéance vérifiée entre deux lots.
6. **`tick.rs`** : `Options.vulns_budget` (10 s), `send_reserve` (10 s), `vulns_max_batches` ; `deadline_envois = start + send_budget − send_reserve` ; échéance de F7 `min(Instant::now() + vulns_budget, deadline_envois)` ; **l'analyse de logs est bornée elle aussi à `deadline_envois`** (`tick.rs` l. 321-322, au lieu de `start + send_budget`) ; `StoreTables::open` une fois ; méta `vulns.inventory.declared.<site>.<source>` écrite au premier passage qui voit la source déclarée, supprimée quand elle disparaît ; purges ; l'étape entière est enveloppée : toute erreur (y compris l'ouverture de `StoreTables`) est journalisée et le passage continue vers `close_unwatched` et `notify` ; base antérieure : étape sautée. **`main.rs`** : `vigie status` imprime `error_count` par site, avec l'avertissement « rapprochement en échec depuis N passages » s'il n'est pas nul.
7. **`notify` et `alert.rs`** : pour le contrôle `vulns`, regroupement **par site** de ce qui est en attente (« même passage » = « en attente pour le site », consigné dans `decisions.md`) : `pending_opens` > 5 → `vulns_grouped_open` puis `mark_open_notified` de tous dans une transaction ; `due_reminders` > 5 → `vulns_grouped_reminder` puis `mark_reminded` de tous ; `pending_closes` > 5 → `vulns_grouped_close` (rétablis et plus surveillés séparés dans le corps) puis `mark_close_notified` de tous ; échec d'envoi → rien de marqué ; marquage en échec après envoi → doublon possible au passage suivant (écrit) ; 5 ou moins → chemin actuel, un e-mail par incident ; objet d'un incident `vulns` = première ligne du détail (`one_line`, 200 caractères).
8. **`store.rs`** : `reconcile_in` en `pub(crate)` ; `remove_key` purge `vuln_match_state`, `vuln_match_components`, `vuln_match_items`, `vuln_match_seen`, `vuln_waivers` et les lignes `check_runs` du contrôle `vulns` du site (l'inventaire est purgé par F5) ; aucun incident n'est touché par `remove_key` ; `remove_key` purge `vuln_match_seen` du site (provenance perdue), pose `vuln_match_keys.lost_view_at` = date du retrait là où il est NULL, et écrit la méta `vulns.removed.<site>` (supprimée quand plus aucune clé du site n'est sans vue).
9. **Tests** :
   - `vulns_match_pass.rs` : chaque cas « tick » du Test Scope ; **deux sources sur les vraies tables de F5 et F6** (inventaires `agent` et `ci` écrits par `accept_inventory`) ; panique injectée dans la transaction de bascule ; ligne corrompue écrite par le test ; marquage en échec injecté ;
   - `vulns_match_budget.rs` (`#[ignore]`, pas CI Linux `cargo test --release --locked --test vulns_match_budget -- --ignored`) : 200 sites × 2 000 composants (40 % partagés), 20 000 failles fictives dont lignes Packagist à 2 340 `versions[]` et WordPress à 40 plages ; affirme la durée de chaque passage (≤ échéance + lot le plus long), la durée du lot le plus long (≤ 1 s), le nombre de passages pour tout couvrir (relevé dans la PR), la transaction d'écriture la plus longue (< 100 ms), **dont `commit_and_reconcile` (écritures de `vuln_match_seen` comprises) et `refresh` d'un site à 2 000 composants** (durée et nombre de lignes de `vuln_match_seen` relevés) ;
   - `capability.rs`, `store_concurrency.rs` (deux `tick` concurrents, `serve`, chargement F1), tests de migration.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1, 8 | Migration verte depuis la version précédente ; `MIGRATIONS.len() == SCHEMA_VULNS_MATCH` ; instantané à jour ; `site remove` vide les tables de F7 et `check_runs` de `vulns` sans toucher aux incidents |
| 2 | `Control::ALL` à 15 ; `vulns` non surveillé si `inventory_sources(site)` est vide ; clos « plus surveillé » quand la déclaration disparaît |
| 3-5 | Cas « Ouverture et résolution », « Deux sources », « Seuils et battement », « Déclenchement », « Budget, reprise, concurrence », « Péremption », « Aucun inventaire, retrait » verts ; aucun run partiel lu ; un run actif et ses incidents changent dans la même transaction ; aucun constat clos « rétabli » sans verdict `NotAffected` dans toutes les vues, ou sans inventaire complet sans le composant de **chaque source requise** (sources qui l'ont vu et peuvent porter son écosystème ; toutes les sources déclarées qui le peuvent si la provenance est perdue) ; tout incident sans vue a une date de départ (`last_seen_at` ou `lost_view_at`) et finit clos « rétabli » ou « plus surveillé » |
| 5-6 | Cas « Erreurs isolées » verts : l'étape ne propage jamais d'erreur, les e-mails partent ; au moins un lot par passage ; aucun lot ne commence après `start + send_budget − send_reserve / 2` ; au-delà de `start + send_budget − send_reserve`, au plus le lot obligatoire ; l'analyse de logs ne commence aucun lot après `start + send_budget − send_reserve` ; les e-mails partent avant `start + send_budget` |
| 7 | Ouvertures en attente pour un site : 5 → 5 e-mails, 6 → 1 e-mail groupé, montée KEV de 6 → 1 ; 6 rappels → 1, 6 clôtures → 1 ; un e-mail groupé n'est jamais remplacé par des e-mails un à un après un échec d'envoi ; si l'attente redescend de 6 à 5 entre deux passages, 5 e-mails (accepté) ; doublon possible seulement après un marquage en échec ; objets sur une ligne |
| 9 | Test de volume vert en release, chiffres consignés dans la PR ; contention sans `SQLITE_BUSY` ni écriture perdue sur Linux et Windows |
| 1-9 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
