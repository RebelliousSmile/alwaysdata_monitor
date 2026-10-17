---
status: pending
---

# Instruction: Stockage par générations, CLI vigie vulns et documentation

## Architecture projection

```txt
.
├── CHANGELOG.md                       ✏️ entrée F1 (#15) sous Unreleased
└── vigie/
    ├── README.md                      ✏️ lignes vigie vulns sources | show | match
    ├── migrations/
    │   └── 0015.sql                   ✅ vuln_sources, vuln_advisories, vuln_aliases, vuln_affected et leurs index (numéro : prochain libre à l'implémentation)
    ├── src/
    │   ├── store.rs                   ✏️ entrée 15 de MIGRATIONS, SCHEMA_VULNS ; tests de migration existants et instantané du schéma mis à jour
    │   ├── main.rs                    ✏️ Command::Vulns { Sources, Show { id }, Match { purl } } ; UsageError → code 2
    │   └── vulns/
    │       └── store.rs               ✅ upsert_source ; Load (begin sous bail, push par lots, commit en compare-and-swap) ; purge ; lectures
    ├── tests/
    │   ├── vulns_store.rs             ✅ remplacement atomique, deux Load concurrents, bail expiré, chargement interrompu, purge, compteurs, taille du WAL
    │   ├── vulns_cli.rs               ✅ vigie vulns sur une base remplie par la bibliothèque
    │   └── store_concurrency.rs       ✏️ chargement de failles en contention avec l'écrivain de serve, tick et une lecture du rapprochement
    └── docs/
        ├── failles.md                 ✏️ complète « Modèle interne et versions » : bornes mesurées, comparateurs, verdicts et agrégation, licences, stockage, CLI, fixtures, limites connues
        └── decisions.md               ✏️ sous-section « Modèle des failles (issue #15) » de « Failles connues »
```

## Test Scope

```mermaid
journey
  section Setup
    Base en version 14 => migration 15 appliquée, instantané du schéma à jour: 5: system
  section Happy path
    Chargement des fixtures => vigie vulns sources : licence, âge, entrées, écartées par raison, out_of_scope: 5: cli
    vigie vulns show GHSA-… => alias, résumé, score et origine, CWE, références, licence, attribution, source_url: 5: cli
    vigie vulns show CVE-… => failles portant cet alias: 5: cli
    vigie vulns match pkg:composer/exemple/paquet@1.2.0 => faille attendue et version corrigée: 5: cli
    vigie vulns match pkg:prestashop/module/exemplemodule@1.2.0 => faille Packagist, verdict Composer: 5: cli
    vigie vulns match pkg:npm/%40exemple/paquet@2.0.0-rc.1 => préversion touchée: 5: cli
  section Edge case
    match avec dev-main ou sans version => failles du paquet en « version inconnue », jamais « aucune faille »: 1: cli
    match d'une plage unevaluable => « plage inconnue »: 1: cli
    match ou show d'un purl ou id mal formé => message clair, code 2: 1: cli
    Base absente ou en version 14 => « aucune base de failles »: 1: cli
    Faille MAL- => « paquet malveillant » ; informational => indiqué: 1: cli
  section Générations
    Second chargement de la même source => un lecteur ne voit que l'ancien ou le nouveau jeu complet: 1: lib
    Deux Load concurrents => le second refusé tant que le bail court ; aucune génération réutilisée: 1: lib
    Bail expiré => repris par un nouveau Load ; le commit de l'ancien échoue (compare-and-swap), aucune donnée mélangée: 1: lib
    Chargement interrompu entre deux lots => génération active intacte ; orpheline purgée au chargement suivant: 1: lib
    Purge => épargne l'active et celle sous bail ; jamais plus d'un lot par transaction: 1: lib
    Chargement de 20 000 failles pendant les écritures de serve et de tick => aucun SQLITE_BUSY, aucune écriture perdue ; WAL ramené après checkpoint: 1: lib
  section Teardown
    Dossier temporaire supprimé => état initial: 5: system
```

## Tasks to do

1. **Migration 0015** (prochain numéro libre à l'implémentation ; `SCHEMA_VULNS` et commentaire de `MIGRATIONS` en conséquence) :
   - `vuln_sources` : `id TEXT PRIMARY KEY`, `url`, `license`, `attribution`, `active_generation INTEGER NOT NULL DEFAULT 0`, `next_generation INTEGER NOT NULL DEFAULT 1`, `loading_generation`, `loading_since`, `last_success_at`, `last_attempt_at`, `dump_sha256`, `entries`, `dropped`, `dropped_detail` (JSON par raison), `out_of_scope`, `last_error` ;
   - `vuln_advisories` (rowid) : `source`, `generation`, `id`, `aliases` (JSON), `summary`, `severity` (JSON : type, vecteur, score v3 calculé), `score`, `score_origin` (`CHECK` : `wordfence`, `friends_of_presta`, `cvss_v31`, `ghsa_severity`), `informational`, `malicious`, `license`, `attribution`, `cwe` (JSON), `published` (NULL admis), `modified`, `refs` (JSON), `source_url` ; unique `(source, generation, id)` ;
   - `vuln_aliases` (rowid) : `source`, `generation`, `advisory_id`, `alias` ; index `(source, generation, advisory_id)` et `(alias)` ;
   - `vuln_affected` (rowid) : `source`, `generation`, `advisory_id`, `purl_type`, `purl_namespace` (`''` sans espace de noms), `purl_name`, `scheme` (`CHECK` : `semver`, `composer`, `php`), `ranges` (JSON), `versions` (JSON), `last_known` (JSON ou NULL), `unevaluable` ; index `(source, generation, advisory_id)` et `(purl_type, purl_namespace, purl_name, source, generation)` ;
   - `CHECK` sur les booléens et les longueurs ; pas de clé étrangère en cascade (la purge supprime enfants puis parents par lots).
2. **`vulns/store.rs`** :
   - `upsert_source(meta)` ;
   - `Load::begin(store, source, now)` en IMMEDIATE : bail en cours non expiré (6 h) → `LoadBusy` ; sinon réserve `g = next_generation`, `next_generation = g + 1`, `loading_generation = g`, `loading_since = now`, retient `active_generation` attendue ;
   - `push(&[Advisory])` : une transaction IMMEDIATE par lot de `VULN_BATCH` failles (réglé par la mesure du test de contention), lignes de la génération `g` ;
   - `commit(tally, sha256)` : une transaction courte, `UPDATE vuln_sources SET active_generation = g, loading_generation = NULL, … WHERE id = ? AND active_generation = <attendue> AND loading_generation = g` ; zéro ligne → `Supplanted`, `g` reste orpheline ; puis purge et `PRAGMA wal_checkpoint(PASSIVE)` ;
   - `purge(source, now)` : par lots, `DELETE FROM <table> WHERE rowid IN (SELECT rowid FROM <table> WHERE source = ? AND generation NOT IN (active, bail en cours) LIMIT n)`, enfants d'abord ; appelée aussi par `begin` ;
   - lectures : `sources()`, `advisory(id_ou_alias)` (alias normalisé), `candidates(&Purl)` en une requête jointe sur `active_generation`, puis `range::match_advisory` en mémoire.
3. **CLI** dans `main.rs` : `vigie vulns sources | show <id|alias> | match <purl>`, `Store::open_read`, schéma vérifié contre `SCHEMA_VULNS` ; `match` imprime une ligne par faille (`id`, verdict, version corrigée, score et origine, drapeaux `divergence`, `beyond_last_known`, « paquet malveillant », « informational »), « version inconnue » ou « plage inconnue » pour `Unknown` ; `show` n'imprime que des champs assainis et bornés, licence et attribution comprises. `UsageError` typée, mappée sur le code 2 comme `ConfigError`.
4. **Tests** : migration depuis la version 14 (`MIGRATIONS[..14]`, comme les tests existants) ; mise à jour des tests de `store.rs` qui figent `SCHEMA_REGISTRY` comme dernière version et de l'instantané `migration_files_build_the_expected_schema` ; `vulns_store.rs` (cas « Générations », lecteur sur `Store::open_read`, horloge injectée pour le bail, taille du WAL avant et après checkpoint) ; `vulns_cli.rs` (cas `cli`, sortie sans caractère de contrôle) ; `store_concurrency.rs` étendu.
5. **Documentation** :
   - `failles.md`, section « Modèle interne et versions » complétée : bornes et tableau des mesures du 2026-10-17, règles de chaque comparateur avec exemples, domaine accepté de `version_compare`, plancher, verdicts, agrégation, licences par préfixe, générations et bail, CLI, fixtures (`NOTICE`), **limites connues** : aucun score v4 ; v3.0 calculé par la formule 3.1 ; dépôts `Packagist:<url>` (Drupal) hors périmètre ; versions de plus de 64 caractères ignorées (MAL npm mesurée à 74) ; borne basse exclusive Wordfence traduite en inclusive ; `last_known_affected_version_range` informatif ; contraintes Composer d'origine non conservées ; plages `GIT` ignorées ;
   - `decisions.md` : sous-section « Modèle des failles (issue #15) », une ligne par décision du plan et sa raison ;
   - `README.md`, `CHANGELOG.md`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration depuis 14 verte ; `MIGRATIONS.len() == SCHEMA_VULNS` ; migrations rejouées sans effet ; instantané du schéma à jour |
| 2 | Cas « Générations » verts : aucun lecteur ne voit un jeu partiel, aucune génération réutilisée, commit supplanté sans mélange, purge épargnant active et bail, aucune transaction d'écriture au-delà d'un lot |
| 3 | Cas `cli` verts ; `match` ne dit jamais « aucune faille » pour une version ou une plage inconnue ; code 2 sur erreur d'usage |
| 4 | `store_concurrency` : aucun `SQLITE_BUSY` remonté, aucune écriture perdue, sur Linux et Windows |
| 5 | `failles.md` et `decisions.md` couvrent chaque décision et limite du plan |
| 1-5 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; différentiel PHP vert ; `Cargo.toml` inchangé ; aucune donnée de production dans les fichiers ajoutés |
