---
status: pending
---

# Instruction: Stockage KEV et EPSS par générations, lecture pour F7

Prérequis : F1 phase 3 livrée (`vuln_sources` à générations et bail, `Load`, purge par lots, `vuln_aliases` indexée par `alias`), et migrations de F2 si elles sont déjà posées (numéro suivant).

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/
    │   └── 00NN.sql                   ✅ vuln_kev, vuln_epss (WITHOUT ROWID), vuln_dataset ; lignes kev et epss de vuln_sources (numéro : prochain libre)
    ├── src/
    │   ├── store.rs                   ✏️ entrée de MIGRATIONS, SCHEMA_ENRICHMENT ; tests de dernière version et instantané du schéma mis à jour
    │   └── vulns/
    │       ├── generation.rs          ✅ seulement si F1 a gardé ses primitives privées : reserve, check_lease, commit_cas, purge_batches(tables) extraits de vulns/store.rs sans changement de comportement
    │       ├── store.rs               ✏️ appelle generation.rs si extrait ; rien d'autre
    │       └── enrich_store.rs        ✅ EnrichLoad { begin, push_kev, push_epss, commit } ; ENRICH_BATCH ; purge ; StoreTables (impl Exploitation) ; datasets()
    └── tests/
        ├── vulns_enrich_store.rs      ✅ remplacement atomique, bail, compare-and-swap, purge, montée de gravité entre deux générations
        └── store_concurrency.rs       ✏️ chargement de 400 000 lignes EPSS pendant les écritures de serve et tick et des lectures StoreTables
```

## Test Scope

```mermaid
journey
  section Setup
    Base à la version précédente => migration appliquée, instantané du schéma à jour: 5: system
  section Happy path
    Chargement KEV fictif (3 CVE) => StoreTables.kev rend dateAdded, échéance, rançongiciel: 5: lib
    Chargement EPSS fictif => StoreTables.epss rend score et percentile en millionièmes ; TablesState porte version et date: 5: lib
    Faille à CVE-2026-90001, KEV gen 1 sans ce CVE puis gen 2 avec => assess passe d'avertissement à critique sans autre changement: 5: lib
  section Générations
    Second chargement => un lecteur ne voit que l'ancien ou le nouveau jeu complet: 1: lib
    Deux EnrichLoad concurrents sur epss => le second refusé tant que le bail court ; aucune génération réutilisée: 1: lib
    Bail expiré => repris ; le commit de l'ancien échoue (compare-and-swap), aucune ligne mélangée: 1: lib
    Chargement interrompu entre deux lots => génération active intacte ; orpheline purgée ensuite: 1: lib
    Purge => épargne l'active et celle sous bail ; jamais plus d'un lot par transaction: 1: lib
    kev et epss chargés en même temps => baux indépendants par source: 1: lib
  section Edge case
    Base sans aucun chargement => TablesState vide, kev et epss rendent None, aucune erreur: 1: lib
    Même CVE poussé deux fois dans une génération => second ignoré, compté duplicate: 1: lib
  section Contention
    400 000 lignes EPSS pendant serve (writer) et tick => aucun SQLITE_BUSY, aucune écriture perdue, transaction la plus longue mesurée sous 100 ms en release: 1: lib
    Lectures StoreTables pendant le chargement => toujours la génération active complète: 1: lib
    WAL après commit et checkpoint PASSIVE => ramené sous le seuil du test: 1: lib
  section Teardown
    Dossier temporaire supprimé => état initial: 5: system
```

## Tasks to do

1. **Migration** (prochain numéro libre ; `SCHEMA_ENRICHMENT` et commentaire de `MIGRATIONS`) :
   - `vuln_kev (generation INTEGER NOT NULL, cve TEXT NOT NULL, date_added TEXT NOT NULL, due_date TEXT NOT NULL, ransomware INTEGER, name TEXT NOT NULL, PRIMARY KEY (generation, cve)) WITHOUT ROWID` ; `CHECK` : longueur de `cve` ≤ 28, `ransomware IN (0, 1)` ou NULL, `length(name) <= 200`, dates `AAAA-MM-JJ` ;
   - `vuln_epss (generation INTEGER NOT NULL, cve TEXT NOT NULL, epss_ppm INTEGER NOT NULL CHECK (epss_ppm BETWEEN 0 AND 1000000), percentile_ppm INTEGER NOT NULL CHECK (…), PRIMARY KEY (generation, cve)) WITHOUT ROWID` ;
   - `vuln_dataset (source TEXT NOT NULL, generation INTEGER NOT NULL, version TEXT NOT NULL, released TEXT NOT NULL, rows INTEGER NOT NULL, PRIMARY KEY (source, generation))` ; `CHECK (source IN ('kev', 'epss'))` ;
   - `INSERT` des lignes `kev` et `epss` dans `vuln_sources` (URL, licence, attribution du plan), si le schéma de F1/F2 ne les crée pas à la première synchronisation (suivre ce que F2 fait pour ses sources).
2. **Primitives de génération** : réutiliser celles de F1 ; si elles sont privées à `vulns/store.rs`, les extraire dans `vulns/generation.rs` (réserver une génération sous bail en IMMEDIATE, revérifier le bail dans un lot, commit en compare-and-swap, purge par lots d'une liste de tables) sans changer leur comportement ; tests de F1 inchangés et verts. La purge accepte une table `WITHOUT ROWID` (sous-requête sur la clé au lieu de `rowid`).
3. **`enrich_store.rs`** :
   - `EnrichLoad::begin(store, source: EnrichSource, now)` (bail de 6 h, comme F1) ;
   - `push_kev(&[KevRow])` / `push_epss(&[EpssRow])` : tampon interne vidé par transactions IMMEDIATE de `ENRICH_BATCH` lignes (5 000 au départ, réglé par la mesure du test de contention), bail revérifié dans chaque transaction, `INSERT OR IGNORE` avec comptage des doublons ;
   - `commit(info: DatasetInfo, rows, sha256)` : écrit `vuln_dataset` de `g`, puis bascule en compare-and-swap dans la même transaction courte ; zéro ligne touchée → `Supplanted` ; puis purge par lots (`vuln_kev` ou `vuln_epss`, et `vuln_dataset`) et `PRAGMA wal_checkpoint(PASSIVE)` ;
   - `active_rows(source)` pour la garde de rétrécissement de la phase 3 ;
   - `StoreTables::open(&Store)` : `TablesState` et KEV entier (génération active) lus dans une même transaction de lecture ; `epss(&Cve)` par une instruction préparée jointe sur `active_generation`, cache `HashMap` pour la durée de vie de l'objet (un passage de F7) ;
   - `datasets()` pour `vigie vulns sources`.
4. **Tests** : `vulns_enrich_store.rs` (cas « Happy path », « Générations », « Edge case », horloge injectée pour le bail) ; montée de gravité : mêmes `AdvisoryFacts`, `assess` avec `StoreTables` avant et après le commit de la génération 2 ; `store_concurrency.rs` étendu (cas « Contention », durée maximale d'une transaction d'écriture mesurée et affirmée en release seulement, comme les mesures existantes) ; tests de migration et instantané du schéma.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration depuis la version précédente verte ; `MIGRATIONS.len() == SCHEMA_ENRICHMENT` ; rejouée sans effet ; instantané à jour |
| 2 | Tests de F1 (`vulns_store.rs`) verts sans modification de leurs attentes |
| 3 | Aucun lecteur ne voit un jeu partiel ; aucune génération réutilisée ; commit supplanté sans mélange ; purge épargnant active et bail ; aucune transaction d'écriture au-delà d'un lot |
| 4 | Montée d'avertissement à critique prouvée par le stockage réel ; contention sans `SQLITE_BUSY` ni écriture perdue, sur Linux et Windows |
| 1-4 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
