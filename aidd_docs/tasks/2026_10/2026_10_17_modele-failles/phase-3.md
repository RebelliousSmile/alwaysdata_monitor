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
    │   └── 0015.sql                   ✅ vuln_sources, vuln_advisories, vuln_aliases, vuln_affected (numéro : prochain libre à l'implémentation)
    ├── src/
    │   ├── store.rs                   ✏️ entrée 15 de MIGRATIONS, SCHEMA_VULNS ; tests de migration depuis 14
    │   ├── main.rs                    ✏️ Command::Vulns { action: VulnsAction { Sources, Show { id }, Match { purl } } }
    │   └── vulns/
    │       └── store.rs               ✅ upsert_source, Load (begin, push par lots, commit, abandon), purge, lectures sources / show / candidates(purl)
    ├── tests/
    │   ├── vulns_store.rs             ✅ chargement, remplacement atomique, chargement interrompu, compteurs, lectures
    │   ├── vulns_cli.rs               ✅ vigie vulns sur une base remplie par la bibliothèque
    │   └── store_concurrency.rs       ✏️ chargement de failles en contention avec l'écrivain de serve, tick et une lecture du rapprochement
    └── docs/
        ├── failles.md                 ✏️ sections Modèle, Comparateurs, Stockage, CLI, Fixtures et licences, Limites connues (après les sections F0)
        └── decisions.md               ✏️ section « Modèle des failles (issue #15) »
```

## Test Scope

```mermaid
journey
  section Setup
    Base migrée en version 14 => migration 15 appliquée, tables présentes: 5: system
  section Happy path
    Chargement des fixtures pour la source test => vigie vulns sources : âge, entrées, écartées, out_of_scope: 5: cli
    vigie vulns show GHSA-… => alias, résumé assaini, gravité, CWE, références, source_url: 5: cli
    vigie vulns show CVE-… => failles portant cet alias: 5: cli
    vigie vulns match pkg:composer/exemple/paquet@1.2.0 => faille attendue et version corrigée: 5: cli
    vigie vulns match pkg:npm/%40exemple/paquet@2.0.0-rc.1 => préversion touchée: 5: cli
  section Edge case
    match avec dev-main ou sans version => failles du paquet en « version inconnue », jamais « aucune faille »: 1: cli
    match d'un purl invalide => message clair, code 2: 1: cli
    Base absente ou en version 14 => « aucune base de failles »: 1: cli
    Faille withdrawn dans le jeu chargé => absente de show et de match, comptée withdrawn dans sources: 1: cli
    match pkg:prestashop/module/exemplemodule@1.2.0 sur une plage Packagist => verdict selon Composer: 1: cli
    Faille MAL- => marquée « paquet malveillant » dans show et match: 1: cli
  section Atomicité
    Second chargement de la même source => lecteur concurrent ne voit que l'ancien ou le nouveau jeu complet: 1: lib
    Chargement interrompu entre deux lots => génération active intacte ; orpheline purgée au chargement suivant: 1: lib
    Chargement de 20 000 failles pendant les écritures de serve et de tick => aucun SQLITE_BUSY, aucune écriture perdue: 1: lib
  section Teardown
    Dossier temporaire supprimé => état initial: 5: system
```

## Tasks to do

1. **Migration 0015** (prochain numéro libre à l'implémentation ; adapter `SCHEMA_VULNS` et le commentaire de `MIGRATIONS`) :
   - `vuln_sources` : `id TEXT PRIMARY KEY`, `url`, `license`, `attribution`, `active_generation INTEGER NOT NULL DEFAULT 0`, `last_success_at`, `last_attempt_at`, `dump_sha256`, `entries`, `dropped`, `dropped_detail` (JSON des compteurs par raison), `out_of_scope`, `last_error` ;
   - `vuln_advisories` : `source`, `generation`, `id`, `aliases` (JSON), `summary`, `severity` (JSON : type et vecteur, score calculé pour v3), `score` et `score_origin` (`wordfence`, `friends_of_presta`, `cvss_v31`, `ghsa_severity` ; `CHECK`), `malicious`, `cwe` (JSON), `published`, `modified`, `refs` (JSON), `source_url` ; unique `(source, generation, id)` ; pas de colonne `withdrawn` (entrées retirées ignorées à l'import) ;
   - `vuln_aliases` : `(source, generation, advisory_id, alias)`, index `(alias)` ;
   - `vuln_affected` : `source`, `generation`, `advisory_id`, `purl_type`, `purl_namespace` (`''` sans espace de noms), `purl_name`, `scheme` (`semver`, `composer`, `php` ; `CHECK`), `ranges` (JSON), `versions` (JSON), `last_known` (JSON ou NULL), `unevaluable` ; index `(purl_type, purl_namespace, purl_name)` ;
   - clés étrangères vers `vuln_advisories` en `ON DELETE CASCADE` (le `PRAGMA foreign_keys=ON` est déjà posé) ; `CHECK` sur les booléens et les longueurs.
2. **`vulns/store.rs`** : `upsert_source(meta)` ; `Load::begin(store, source)` purge par lots les générations orphelines puis réserve `active_generation + 1` ; `push(&[Advisory])` écrit par transactions IMMEDIATE de `VULN_BATCH` failles (constante, même ordre de grandeur que `fold::BATCH_SIZE`, réglée par la mesure du test de contention) ; `commit(tally, sha256)` bascule `active_generation` et les compteurs en une transaction courte, puis purge l'ancienne génération par lots ; `Drop` sans `commit` n'efface rien de visible. Lectures : `sources()`, `advisory(id_ou_alias)`, `candidates(&Purl)` par une seule requête jointe sur `active_generation`, puis `range::match_version` en mémoire.
3. **CLI** dans `main.rs` : `vigie vulns sources | show <id> | match <purl>`, ouverture par `Store::open_read`, schéma vérifié contre `SCHEMA_VULNS` ; `match` imprime une ligne par faille (`id`, verdict, version corrigée, score et origine, drapeaux `divergence`, `beyond_last_known`, « paquet malveillant »), « version inconnue » pour `Unknown` ; `show` n'imprime que des champs assainis et bornés, sans `details`. Code 2 pour un purl ou un identifiant mal formé, comme les autres erreurs d'usage.
4. **Tests** : migration depuis une base en version 14 (fixture construite avec `MIGRATIONS[..14]`, comme les tests existants) ; `vulns_store.rs` (remplacement, lecteur concurrent sur un `Store::open_read`, interruption simulée en abandonnant un `Load`, compteurs) ; `vulns_cli.rs` (cas du Test Scope, sortie sans caractère de contrôle) ; `store_concurrency.rs` étendu au chargement de failles.
5. **Documentation** :
   - `failles.md` : modèle retenu et bornes, table écosystème de la source → comparateur → purl (dont les traductions `prestashop/*` et `wpackagist-*`), règles de chaque comparateur avec exemples, domaine accepté de `version_compare`, ordre de choix du score et son origine, verdicts et sens de `Unknown`, générations et remplacement atomique, CLI, fixtures (renvoi à `tests/fixtures/vulns/osv/NOTICE` ; `composer/semver` MIT pour les vecteurs de normalisation), **limites connues** (aucun score v4 calculé : une faille qui n'a qu'un vecteur v4 prend la gravité qualitative GHSA ou reste sans score ; v3.0 calculé par la formule 3.1 ; npm et Cargo sensibles à la casse, Cargo sans équivalence `-`/`_` ; contraintes Composer d'origine non conservées ; plages `GIT` ignorées ; `last_known_affected_version_range` informatif seulement ; comparateur PHP plus strict que PHP hors domaine) ;
   - `decisions.md` : section « Modèle des failles (issue #15) », une ligne par décision du plan avec sa raison ;
   - `README.md` et `CHANGELOG.md`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration d'une base en version 14 verte ; `MIGRATIONS.len() == SCHEMA_VULNS` ; migrations rejouées sans effet |
| 2 | Aucun lecteur ne voit un jeu partiel ; génération orpheline purgée ; aucune transaction d'écriture ne couvre plus d'un lot |
| 3 | Chaque cas `cli` du Test Scope est un test du binaire ; `match` ne dit jamais « aucune faille » pour une version inconnue |
| 4 | `store_concurrency` : aucun `SQLITE_BUSY` remonté, aucune écriture perdue, sur Linux et Windows |
| 5 | `failles.md` couvre modèle, comparateurs, stockage, CLI, licences des fixtures et limites connues ; section #15 dans `decisions.md` |
| 1-5 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; différentiel PHP vert ; `Cargo.toml` inchangé ; aucune donnée de production dans les fichiers ajoutés |
