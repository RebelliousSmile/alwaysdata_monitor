---
status: pending
---

# Instruction: Résultats stockés, passage de tick borné, contrôle vulns, péremption, e-mails

**Prérequis** : F1, F2, F3, F4 et F5 fusionnés ; F6 facultatif. Avant de commencer, relire les plans tels qu'implémentés (en particulier F6 : `inventory_heads` par source, seuils de péremption, `inventory_sources`) et reporter tout écart dans « Interfaces reprises » de `plan.md`. Sans F6, seule la source `agent` existe ; le schéma est néanmoins clé par source.

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/
    │   └── 0020.sql                   ✅ vuln_match_runs, vuln_match_state, vuln_match_components, vuln_match_items, vuln_waivers, toutes clés par source (numéro : prochain libre à la fusion ; 0021 si F6 fusionne avant)
    ├── src/
    │   ├── store.rs                   ✏️ entrée de MIGRATIONS, SCHEMA_VULNS_MATCH ; reconcile_in en pub(crate) ; remove_key purge vuln_match_*, vuln_waivers et check_runs de vulns ; tests de dernière version et instantané du schéma
    │   ├── capability.rs              ✏️ Control::Vulns (« vulns ») en fin de Control::ALL (15) ; Needs::InventorySource (sources déclarées ou clé d'inventaire) ; Ctx.inventory_key
    │   ├── tick.rs                    ✏️ Options { vulns_budget: 10 s, send_reserve: 10 s, vulns_max_batches } ; étape F7 après l'analyse de logs, jamais d'erreur propagée ; Summary.vulns_components, vulns_errors ; notify : synthèse vulns par site au-delà de 5 ouvertures
    │   ├── alert.rs                   ✏️ objet vulns = première ligne du détail ; vulns_digest_email(site, incidents) ; mention « usage interne »
    │   └── vulns/
    │       └── matching/
    │           ├── epoch.rs           ✅ match_epoch (active_generations des sources déclarées, latest_range_correction_id), enrich_epoch (kev, epss), waiver_epoch(site) = (max(id), max(revoked_at), count)
    │           ├── store.rs           ✅ état par (site, source), runs à séquence globale, lots à compare-and-swap du curseur, commit_run + reconcile_in dans une transaction, réévaluation en nouveau run, purges, lectures
    │           └── pass.rs            ✅ run(store, config, tables, now, deadline, max_batches) -> PassReport : (site, source) dus, à tour de rôle, au moins un lot, Result par site, reconstruction complète des constats du site
    └── tests/
        ├── vulns_match_pass.rs        ✅ bout en bout sur base réelle (F1, F4, F5 écrits par leurs bibliothèques), tick::run_with, FakeClock, MemoryNotifier
        ├── vulns_match_budget.rs      ✅ #[ignore] : 200 sites × 2 000 composants, données réalistes, mesuré en release
        ├── capability.rs              ✏️ Control::ALL à 15, vulns surveillé ssi source d'inventaire déclarée ou clé d'inventaire
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
    Reporté depuis plus de 7 jours (dernier inventaire complet qui l'a vu) => plus reporté, clos plus surveillé, jamais rétabli: 1: tick
    Module PrestaShop à quatre composants sur site-b => ouvert, puis clos à la version corrigée: 5: tick
  section Deux sources (base de test avec la colonne source de F6, ou source ci simulée)
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
    5 composants ouverts dans un passage => 5 e-mails: 5: tick
    6 composants ouverts dans un passage => 1 e-mail de synthèse (comptes par gravité, 10 plus graves), 6 incidents marqués notifiés dans une transaction: 5: tick
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
    Dérogation retirée => vue au passage suivant, gravité rendue: 5: tick
    Rien de changé => aucun lot, aucune écriture: 5: tick
  section Budget, reprise, concurrence
    vulns_max_batches = 1, site de 1 200 composants => un lot par passage, curseur after_rowid gardé, bascule au troisième passage, l'API ne voit que l'ancien run jusque-là: 1: tick
    match_epoch changée entre le début du run et commit_run => compare-and-swap refusé, run abandonné, repris au début: 1: tick
    Deux tick concurrents sur le même run => un seul lot écrit par position de curseur: 1: lib
    Contrôles et analyse de logs qui consomment tout le temps (sources lentes injectées) => exactement un lot de F7, e-mails envoyés avant send_budget: 1: tick
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
  section Registre
    Control vulns => nom unique, Control::ALL à 15 ; non surveillé sans source déclarée ni clé d'inventaire: 5: lib
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
   - `vuln_match_state (site, source CHECK IN ('agent','ci'), inventory_id, seen_at, match_epoch, enrich_epoch, waiver_epoch, next_stale_check, next_waiver_check, active_run, pending_run, pending_inventory_id, pending_match_epoch, cursor_rowid INTEGER NOT NULL DEFAULT 0, due_since, error_count, PRIMARY KEY (site, source))` ;
   - `vuln_match_components (site, source, run, base, path, purl, version, ecosystem, scope, carried, last_complete_at, severity NULL ou CHECK, groups, PRIMARY KEY (site, source, run, base, path)) WITHOUT ROWID` ;
   - `vuln_match_items (site, source, run, base, path, group_key, verdict CHECK IN ('affected','unknown'), reason, severity, rule, fixed, members TEXT (JSON : identifiant, source, `corrected` ; jamais d'attribution), facts TEXT (JSON `GroupFacts`), covered_ids TEXT (JSON), kev, epss_ppm, score_tenths, redistribution, PRIMARY KEY (site, source, run, base, path, group_key)) WITHOUT ROWID` ; index `(site, run, severity, base, path, group_key)` pour la pagination ;
   - `vuln_waivers (id INTEGER PRIMARY KEY AUTOINCREMENT, site, source, base, advisory_ref, version, covered_ids, reason, until, operator, created_at, revoked_at, revoke_reason, audit_hash)` ; index `(site, base)` ; `CHECK` de longueur et `until - created_at <= 90 * 86400` ;
   - montée d'une base remplie depuis la version précédente sans perte ; instantané du schéma.
2. **`capability.rs`** : `Control::Vulns` en fin de `Control::ALL` (15), `ALL_CMS`, `Needs::InventorySource` : surveillé ssi `inventory_sources(site)` (F6 ; `inventory_source` de F5 avant F6) est non vide, ou `ctx.inventory_key` (clé d'inventaire enregistrée, `failles.md` l. 638-640) ; `match` sans joker.
3. **`matching/epoch.rs`** : `match_epoch` (SHA-256 de `active_generations()` restreint aux sources déclarées, et de `latest_range_correction_id()`), `enrich_epoch`, `waiver_epoch(site)` ; lectures seules.
4. **`matching/store.rs`** :
   - `due(now)` : par (site, source) déclaré, tête d'inventaire (`inventory_heads`, par source avec F6), époques, `seen_at`, `next_stale_check = max(seen_at, déclaration) + seuil`, `next_waiver_check` ; triés par `due_since` puis site ; un (site, source) en erreur passe après les autres ;
   - `begin_run` : id de `vuln_match_runs` (séquence globale) en IMMEDIATE, `pending_*`, `cursor_rowid = 0` ;
   - `push(site, source, run, expected_cursor, &[ComponentResult], new_cursor)` : une transaction IMMEDIATE par lot de 500, `UPDATE … SET cursor_rowid = new WHERE pending_run = run AND cursor_rowid = expected` (zéro ligne → abandon du lot) ;
   - `commit_and_reconcile(site, source, run, findings_builder)` : **une** transaction IMMEDIATE : `match_epoch` relue et comparée à `pending_match_epoch`, compare-and-swap `active_run = run WHERE pending_run = run`, puis reconstruction des constats du site depuis les runs actifs de toutes ses sources (lecture des incidents `vulns` ouverts du site pour `already_open`, dérogations du site, constats de péremption) et `reconcile_in(site, "vulns", findings, now)` ; constats qui ne tenaient qu'à une source de failles retirée, ou à un composant dont le report a cessé, clos `unwatched` dans la même transaction ; puis purge par lots de l'ancien run ;
   - `reassess(site, source, tables)` : nouveau run copié par lots depuis l'actif, gravités recalculées depuis `facts` (F4), puis `commit_and_reconcile` ;
   - `refresh(site, tables)` : sans nouveau run (`waiver_epoch`, `seen_at`, échéances) : même reconstruction et `reconcile_in` dans une transaction ;
   - **aucun inventaire et aucun run actif** pour toutes les sources d'un site : la reconstruction rend les incidents de composants ouverts **tels quels** (aucun constat de composant clos), plus les constats de péremption ;
   - lectures pour l'API et la CLI : `components_page`, `items_page`, `site_summary`, `report_rows` ;
   - purges : `purge_unwatched(config)` ; `mask_closed(now)` : incidents `vulns` clos depuis 30 jours (détail, clé `<site>/vulns/masque-<id>`) et `check_runs.detail` du contrôle `vulns` plus vieux que 30 jours.
5. **`matching/pass.rs`** : pour chaque (site, source) dû, dans un `Result` propre (erreur journalisée sans texte de la base, comptée, `error_count` et `due_since` mis à jour, passage au suivant) :
   1. inventaire changé ou `match_epoch` changée : lots de `inventory_components(id, cursor_rowid, 500)` filtrés par `admitted` ; pour un inventaire incomplet, composants de l'actif absents ajoutés comme reportés si leur `last_complete_at` est plus jeune que le seuil ; candidats (`candidates`, F1) par le cache borné en poids ; phase 1 ; dernier lot → `commit_and_reconcile` ;
   2. `enrich_epoch` seule : `reassess` ;
   3. sinon : `refresh` ;
   4. au moins un lot par passage, puis échéance vérifiée entre deux lots.
6. **`tick.rs`** : `Options.vulns_budget` (10 s), `send_reserve` (10 s), `vulns_max_batches` ; échéance `min(Instant::now() + vulns_budget, start + send_budget − send_reserve)` ; `StoreTables::open` une fois ; méta `vulns.inventory.declared.<site>.<source>` écrite au premier passage qui voit la source déclarée, supprimée quand elle disparaît ; purges ; l'étape entière est enveloppée : toute erreur (y compris l'ouverture de `StoreTables`) est journalisée et le passage continue vers `close_unwatched` et `notify` ; base antérieure : étape sautée.
7. **`notify` et `alert.rs`** : avant les e-mails d'ouverture un à un, regroupement des `pending_opens` de contrôle `vulns` par site ; plus de 5 → `vulns_digest_email(site, incidents)` (comptes par gravité, les 10 plus graves avec leur première ligne, `vigie site vulns <site>`, mention « usage interne » si besoin), puis `mark_open_notified` de **tous** dans une transaction ; échec d'envoi → rien de marqué ; 5 ou moins → chemin actuel ; objet d'un incident `vulns` = première ligne du détail (`one_line`, 200 caractères).
8. **`store.rs`** : `reconcile_in` en `pub(crate)` ; `remove_key` purge `vuln_match_state`, `vuln_match_components`, `vuln_match_items`, `vuln_waivers` et les lignes `check_runs` du contrôle `vulns` du site (l'inventaire est purgé par F5) ; aucun incident n'est touché par `remove_key`.
9. **Tests** :
   - `vulns_match_pass.rs` : chaque cas « tick » du Test Scope ; deux sources par la colonne `source` de F6 si fusionnée, sinon par une ligne `ci` insérée par le test dans le schéma de F7 (lecture par la même fonction) ; panique injectée dans la transaction de bascule ; ligne corrompue écrite par le test ;
   - `vulns_match_budget.rs` (`#[ignore]`, pas CI Linux `cargo test --release --locked --test vulns_match_budget -- --ignored`) : 200 sites × 2 000 composants (40 % partagés), 20 000 failles fictives dont lignes Packagist à 2 340 `versions[]` et WordPress à 40 plages ; affirme la durée de chaque passage (≤ échéance + lot le plus long), la durée du lot le plus long (≤ 1 s), le nombre de passages pour tout couvrir (relevé dans la PR), la transaction d'écriture la plus longue (< 100 ms) ;
   - `capability.rs`, `store_concurrency.rs` (deux `tick` concurrents, `serve`, chargement F1), tests de migration.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1, 8 | Migration verte depuis la version précédente ; `MIGRATIONS.len() == SCHEMA_VULNS_MATCH` ; instantané à jour ; `site remove` vide les tables de F7 et `check_runs` de `vulns` sans toucher aux incidents |
| 2 | `Control::ALL` à 15 ; `vulns` non surveillé sans source ni clé d'inventaire ; clos « plus surveillé » quand la déclaration disparaît |
| 3-5 | Cas « Ouverture et résolution », « Deux sources », « Seuils et battement », « Déclenchement », « Budget, reprise, concurrence », « Péremption », « Aucun inventaire, retrait » verts ; aucun run partiel lu ; un run actif et ses incidents changent dans la même transaction ; aucun constat clos « rétabli » sans inventaire complet de la même source ni verdict `NotAffected` |
| 5-6 | Cas « Erreurs isolées » verts : l'étape ne propage jamais d'erreur, les e-mails partent ; au moins un lot par passage ; le rapprochement ne déborde jamais `start + send_budget − send_reserve` de plus d'un lot |
| 7 | 5 → 5 e-mails, 6 → 1 synthèse, montée KEV de 6 → 1 synthèse ; synthèse jamais remplacée par des e-mails un à un après un échec ; objets sur une ligne |
| 9 | Test de volume vert en release, chiffres consignés dans la PR ; contention sans `SQLITE_BUSY` ni écriture perdue sur Linux et Windows |
| 1-9 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
