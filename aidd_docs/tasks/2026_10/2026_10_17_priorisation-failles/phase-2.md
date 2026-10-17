---
status: pending
---

# Instruction: Stockage KEV et EPSS par générations, lecture pour F7

Prérequis : F1 phase 3 livrée (`vuln_sources` à générations et bail, `Load`, purge par lots, `vuln_aliases` indexée par `alias`) et F2 (plan commité en 1b5a76e) : migration 0017 (validateurs, `last_outcome`, `loader_version`, `recent_entries`, `last_request_at`, `retry_after_until`), `Load::begin(.., lease)`, `finish_unchanged(source, g, expected, validators: ValidatorsUpdate::{Keep, Set(..)}, outcome, now)` (primitive générique, une seule instruction en compare-and-swap, partagée par `Load` et `EnrichLoad` ; `mark_fresh` n'existe pas), `Load::release`, `Load::commit(tally, SyncMeta)`, `claim_request`, `record_outcome`.

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/
    │   └── 00NN.sql                   ✅ vuln_kev, vuln_epss (WITHOUT ROWID), vuln_dataset ; vuln_sources : validator_url, stale_count (numéro : prochain libre)
    ├── src/
    │   ├── store.rs                   ✏️ entrée de MIGRATIONS, SCHEMA_ENRICHMENT ; tests de dernière version et instantané du schéma mis à jour
    │   └── vulns/
    │       ├── generation.rs          ✅ seulement si F1 a gardé ses primitives privées : reserve, check_lease, commit_cas, release, purge_batches(&[(table, KeyShape)]) extraits sans changement de comportement
    │       ├── store.rs               ✏️ appelle generation.rs si extrait ; commit et la primitive finish_unchanged de F2 écrivent validator_url avec les validateurs (Set) ou le laissent (Keep), finish_unchanged incrémente stale_count, dans leur instruction unique
    │       └── enrich_store.rs        ✅ EnrichLoad { begin, push_kev, push_epss, commit, finish_unchanged, release } ; ENRICH_BATCH ; active(source) ; StoreTables (impl Exploitation) ; datasets()
    └── tests/
        ├── vulns_enrich_store.rs      ✅ remplacement atomique, bail, release, compare-and-swap, purge par clé, montée de gravité entre deux générations
        └── store_concurrency.rs       ✏️ chargement de 400 000 lignes EPSS pendant les écritures de serve et tick et des lectures StoreTables
```

## Test Scope

```mermaid
journey
  section Setup
    Base à la version précédente => migration appliquée, instantané du schéma à jour: 5: system
  section Happy path
    Chargement KEV fictif (3 CVE-2099) => StoreTables.kev rend dateAdded, échéance, known_ransomware: 5: lib
    Chargement EPSS fictif => StoreTables.epss rend score, percentile en millionièmes et génération ; TablesState porte version et date: 5: lib
    Faille à CVE-2099-90001, KEV gen 1 sans ce CVE puis gen 2 avec => assess passe d'avertissement à critique sans autre changement: 5: lib
  section Générations
    Second chargement => un lecteur ne voit que l'ancien ou le nouveau jeu complet: 1: lib
    Deux EnrichLoad concurrents sur epss => le second refusé tant que le bail court ; aucune génération réutilisée: 1: lib
    Bail expiré => repris ; le commit de l'ancien échoue (compare-and-swap), aucune ligne mélangée: 1: lib
    finish_unchanged (304 ou empreinte identique) => une seule instruction : bail rendu, succès daté, actif intact, nouveau begin immédiat accepté: 1: lib
    finish_unchanged avec validators Keep et stale => stale_count + 1, etag, http_last_modified et validator_url de l'actif inchangés, dans la même instruction: 1: lib
    finish_unchanged ou release après reprise du bail ou bascule concurrente => zéro ligne, rien écrit: 1: lib
    Chargement interrompu entre deux lots => génération active intacte ; orpheline purgée ensuite: 1: lib
    kev et epss chargés en même temps => baux indépendants par source: 1: lib
  section Purge
    Même CVE dans l'active et dans une orpheline => purge de l'orpheline, la ligne de l'active survit: 1: lib
    Trois orphelines de 12 000 lignes => supprimées génération par génération, jamais plus d'un lot par transaction: 1: lib
    Aucun bail en cours => seule l'active est épargnée (pas de NOT IN avec NULL): 1: lib
    Tables de F1 purgées par rowid et source => tests de F1 inchangés et verts: 1: lib
  section Validateurs
    commit servi par l'URL A avec ETag => etag et validator_url = A écrits dans la transaction de bascule: 1: lib
    finish_unchanged avec Set(..) servi par l'URL B sans ETag => etag et validator_url effacés: 1: lib
  section Edge case
    Base sans aucun chargement => TablesState vide, kev et epss rendent None, aucune erreur: 1: lib
    Même CVE poussé deux fois dans une génération => second ignoré, compté duplicate: 1: lib
  section Contention
    400 000 lignes EPSS pendant serve (writer) et tick => aucun SQLITE_BUSY, aucune écriture perdue, transaction la plus longue sous 100 ms en release: 1: lib
    Lectures StoreTables pendant le chargement => toujours la génération active complète (une seule génération par EpssFact): 1: lib
    WAL après commit et checkpoint PASSIVE => ramené sous le seuil du test: 1: lib
  section Teardown
    Dossier temporaire supprimé => état initial: 5: system
```

## Tasks to do

1. **Migration** (prochain numéro libre ; `SCHEMA_ENRICHMENT` et commentaire de `MIGRATIONS`) :
   - `vuln_kev (generation INTEGER NOT NULL, cve TEXT NOT NULL, date_added TEXT NOT NULL, due_date TEXT NOT NULL, known_ransomware INTEGER NOT NULL CHECK (known_ransomware IN (0, 1)), name TEXT NOT NULL CHECK (length(name) <= 200), PRIMARY KEY (generation, cve)) WITHOUT ROWID` ; `CHECK (length(cve) BETWEEN 13 AND 28)`, dates `AAAA-MM-JJ` ;
   - `vuln_epss (generation INTEGER NOT NULL, cve TEXT NOT NULL, epss_ppm INTEGER NOT NULL CHECK (epss_ppm BETWEEN 0 AND 1000000), percentile_ppm INTEGER NOT NULL CHECK (percentile_ppm BETWEEN 0 AND 1000000), PRIMARY KEY (generation, cve)) WITHOUT ROWID` ;
   - `vuln_dataset (source TEXT NOT NULL CHECK (source IN ('kev', 'epss')), generation INTEGER NOT NULL, version TEXT NOT NULL CHECK (length(version) <= 32), released TEXT NOT NULL, rows INTEGER NOT NULL, PRIMARY KEY (source, generation))` ;
   - `ALTER TABLE vuln_sources ADD COLUMN validator_url TEXT CHECK (validator_url IS NULL OR length(validator_url) <= 2048)` et `ADD COLUMN stale_count INTEGER NOT NULL DEFAULT 0` ; la montée remplit `validator_url` avec `url` là où un ETag ou un `Last-Modified` existe déjà (sources OSV de F2) ;
   - les lignes `kev` et `epss` de `vuln_sources` sont créées par `upsert_source` au premier passage, comme les sources de F2.
2. **Primitives de génération** : réutiliser celles de F1 ; si elles sont privées, les extraire dans `vulns/generation.rs` sans changer leur comportement. `purge_batches(store, source, &[(table, KeyShape)])` avec `KeyShape::RowidBySource` et `KeyShape::GenerationCve` (requêtes du plan) ; la liste exclue est construite sans `NULL` (active seule si aucun bail) ; `vuln_dataset` purgée par `DELETE … WHERE source = ? AND generation NOT IN (…)` (une ligne par génération). Tests de F1 inchangés et verts.
3. **`enrich_store.rs`** :
   - `EnrichLoad::begin(store, source: EnrichSource, now, lease)` (bail de F2 : plafond de durée de la source + 30 min, pris par le moteur avant toute requête et avant `claim_request`) ;
   - `push_kev(&[KevRow])` / `push_epss(&[EpssRow])` : tampon vidé par transactions IMMEDIATE de `ENRICH_BATCH` lignes (5 000 au départ, réglé par la mesure du test de contention), bail revérifié dans chaque transaction, `INSERT OR IGNORE` avec comptage des doublons ;
   - `commit(info: DatasetInfo, tally, SyncMeta)` (signature de F2) : `vuln_dataset` de `g`, puis bascule en compare-and-swap, validateurs, `validator_url`, `dump_sha256`, `loader_version`, `recent_entries` dans la même transaction courte ; zéro ligne touchée → `Supplanted` ; puis purge par lots et `PRAGMA wal_checkpoint(PASSIVE)` ;
   - `finish_unchanged` : la primitive générique de F2 `finish_unchanged(source, g, expected, validators: ValidatorsUpdate::{Keep, Set(..)}, outcome, now) -> bool` (une seule instruction en compare-and-swap, partagée par `Load` et `EnrichLoad`, colonnes extensibles) ; F4 y ajoute deux colonnes : `validator_url` (écrite avec `Set(..)`, laissée avec `Keep`) et `stale_count` (`+ 1` sur le chemin périmé) ; zéro ligne → `false`, rien écrit (issue `busy`) ;
   - `release(self)` : celle de F2 appliquée à la source (abandon) ; aucune ligne active touchée ;
   - `active(source) -> Option<ActiveDataset { released, rows }>` (pour l'`EnrichSink` de la phase 3) ;
   - `StoreTables::open(&Store)` : `TablesState` et KEV entier de la génération active dans une même transaction de lecture ; `epss(&Cve)` par une instruction préparée jointe sur `active_generation` (`EpssFact.generation` rempli), cache `HashMap` pour la durée d'un passage ;
   - `datasets()` pour `vigie vulns sources`.
4. **Tests** : `vulns_enrich_store.rs` (cas « Happy path », « Générations », « Purge », « Validateurs », « Edge case », horloge injectée pour le bail) ; montée de gravité par `StoreTables` avant et après le commit de la génération 2 ; `store_concurrency.rs` étendu (cas « Contention », durée maximale d'une transaction d'écriture affirmée en release seulement) ; tests de migration et instantané du schéma.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration depuis la version précédente verte ; `MIGRATIONS.len() == SCHEMA_ENRICHMENT` ; rejouée sans effet ; instantané à jour ; `validator_url` rempli pour les sources OSV qui avaient un ETag |
| 2 | Tests de F1 et F2 verts sans modification de leurs attentes ; purge `GenerationCve` sans jamais toucher l'active, même CVE commun compris |
| 3 | Aucun lecteur ne voit un jeu partiel ; aucune génération réutilisée ; commit supplanté sans mélange ; `finish_unchanged` et `release` sans effet sur un bail repris ; aucun chemin « inchangé » n'écrit en plus d'une instruction ; aucune transaction d'écriture au-delà d'un lot ; un ETag n'est jamais écrit sans la génération ou le succès qui lui correspond, ni sans son URL |
| 4 | Montée d'avertissement à critique prouvée par le stockage réel ; contention sans `SQLITE_BUSY` ni écriture perdue, sur Linux et Windows |
| 1-4 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
