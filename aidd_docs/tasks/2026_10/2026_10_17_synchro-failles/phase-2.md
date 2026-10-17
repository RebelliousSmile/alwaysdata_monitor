---
status: pending
---

# Instruction: Cadre de synchronisation, source OSV, état par source et vigie vulns sync

Prérequis : F1 (#15) fusionné (`Advisory::from_osv`, `Tally`, `SourceEcosystem::osv_name`, `vulns/store.rs` avec `upsert_source`, `Load`, purge, migration 0015). Rien n'est réécrit de F1 : F2 ajoute `Load::release`, les validateurs au commit et l'état de synchronisation.

## Architecture projection

```txt
.
└── vigie/
    ├── config.example.toml            ✏️ [vulns] sources commentée, renvoi à docs/failles.md
    ├── migrations/
    │   └── 0017.sql                   ✅ ALTER TABLE vuln_sources ADD COLUMN etag, http_last_modified, dump_bytes, unpacked_bytes, last_duration_ms, last_outcome (CHECK) ; numéro : prochain libre à la fusion
    ├── src/
    │   ├── config.rs                  ✏️ Config.vulns: Option<Vulns> ; Vulns { sources: Vec<String> } (deny_unknown_fields) validé contre sync::registry::KNOWN
    │   ├── store.rs                   ✏️ entrée 17 de MIGRATIONS, SCHEMA_VULNS_SYNC ; tests figeant la dernière version et instantané du schéma mis à jour
    │   ├── main.rs                    ✏️ Vulns::Sync { source: Option<String>, accept_shrink: bool } ; vulns sources affiche l'état de synchronisation
    │   └── vulns/
    │       ├── store.rs               ✏️ (F1) Load::release ; Load::commit(tally, SyncMeta) ; mark_fresh ; record_outcome ; sync_state(source)
    │       ├── sources/
    │       │   ├── mod.rs             ✅
    │       │   └── osv.rs             ✅ OsvSource { ecosystem } : id, meta (hôte codé en dur), fetch (zip → from_osv → Sink)
    │       └── sync/
    │           ├── mod.rs             ✏️ trait VulnSource, SourceMeta, SyncContext, NotReady, Sink, FetchOutcome ; SyncOptions ; run(store_path, config, options, clock) -> SyncReport
    │           ├── registry.rs        ✅ KNOWN (identifiants fermés), build(id) -> Box<dyn VulnSource>, declared(config) dans l'ordre crates.io, Packagist, npm
    │           └── engine.rs          ✅ une source : bail, Download, fetch, garde de rétrécissement, bascule ou abandon, état
    └── tests/
        ├── vulns_sync.rs              ✅ synchronisation complète contre le serveur local : idempotence, 304, empreinte identique, échecs, hostiles, rétrécissement, bail, divergence Packagist
        ├── vulns_cli.rs               ✏️ (F1) vulns sync et vulns sources avec état de synchronisation
        ├── config_edges.rs            ✏️ [vulns] : identifiant inconnu, doublon, liste vide, clé inconnue
        └── fixtures/vulns/fictif/
            └── packagist-divergence.json ✅ faille fictive dont versions[] liste une version hors des plages
```

## Test Scope

```mermaid
journey
  section Setup
    Base en version 16 => migration 17 appliquée, instantané du schéma à jour: 5: system
    Serveur HTTPS local servant trois all.zip construits depuis les fixtures F1: 5: system
  section Happy path
    vulns sync => trois sources chargées, last_outcome loaded, ETag, Last-Modified, SHA-256, tailles et durée gardés: 5: cli
    vulns match sur un purl des fixtures => faille trouvée après synchronisation: 5: cli
    vulns sources => âge de la dernière réussite, issue, entrées, écartées par raison, tailles: 5: cli
    vulns sync --source osv-npm => seule la source npm est demandée au serveur: 5: cli
  section Idempotence
    Second vulns sync, serveur en 304 => not_modified, active_generation identique, aucune ligne de faille écrite, bail rendu, last_success_at avancé: 5: lib
    Second vulns sync, serveur sans ETag et même dump => unchanged, active_generation identique, aucune ligne de faille écrite: 5: lib
    Dump modifié => nouvelle génération active, ancienne purgée: 5: lib
  section Packagist
    Faille fictive dont versions[] contient une version hors plage => match Affected avec divergence, plage évaluée par Composer: 1: lib
  section Échec, base précédente intacte
    Serveur en 500, réseau coupé, échéance dépassée => failed, last_error assaini, génération active et ETag inchangés: 1: lib
    Zip à CRC faux, bombe menteuse, recouvrement, trop d'entrées => failed, aucune faille ajoutée ni retirée: 1: lib
    Content-Length géant ou corps sans fin => failed sans écrire plus que le plafond: 1: lib
    Entrée JSON invalide ou de 5 Mio dans un zip sain => source chargée, raisons comptées: 1: lib
    Une source en échec => les deux autres chargées, code de sortie 1: 1: cli
  section Rétrécissement
    Dump valide de 10 failles après un actif de 1 000 => refused_shrink, actif gardé, code 1: 1: lib
    Même dump avec --accept-shrink => chargé, journal le dit: 5: cli
  section Concurrence
    Bail détenu par une autre synchronisation => busy, aucune requête au serveur, code 0: 1: lib
    Bail perdu pendant le chargement (horloge avancée de 7 h) => failed, aucune donnée mélangée: 1: lib
  section Configuration
    Sans section vulns => vulns sync dit aucune source déclarée, code 2: 1: cli
    sources avec osv-pypi, doublon ou clé inconnue => erreur de configuration, code 2: 1: cli
    --source absente de la configuration => erreur d'usage, code 2: 1: cli
  section Teardown
    Dossier vulns-work vide après chaque synchronisation, réussie ou non: 5: system
```

## Tasks to do

1. **Migration 0017** (prochain numéro libre à la fusion, après F1 0015 et F5 0016) : `ALTER TABLE vuln_sources ADD COLUMN` `etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 256)`, `http_last_modified TEXT`, `dump_bytes INTEGER`, `unpacked_bytes INTEGER`, `last_duration_ms INTEGER`, `last_outcome TEXT CHECK (last_outcome IS NULL OR last_outcome IN ('loaded','unchanged','not_modified','failed','busy','refused_shrink'))` ; `SCHEMA_VULNS_SYNC`, commentaire de `MIGRATIONS` ; tests de `store.rs` (dernière version, montée d'une base remplie depuis la version précédente, instantané `migration_files_build_the_expected_schema`).
2. **`vulns/store.rs`** (ajouts à F1, sans changer ses règles) :
   - `Load::release(self)` : transaction courte, `UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL WHERE id = ? AND loading_generation = g` (aucun effet si le bail a été repris) ;
   - `Load::commit(tally, SyncMeta { sha256, etag, http_last_modified, dump_bytes, unpacked_bytes, duration_ms })` : les validateurs et `last_outcome = 'loaded'`, `last_success_at`, `last_error = NULL` sont écrits **dans la même instruction** que la bascule en compare-and-swap de F1 ;
   - `mark_fresh(source, outcome ∈ {not_modified, unchanged}, validators, now)` : `last_success_at`, `last_attempt_at`, `last_outcome`, validateurs (ETag nouveau si l'empreinte est identique), `last_error = NULL` ; aucune ligne de faille touchée ;
   - `record_outcome(source, outcome ∈ {failed, busy, refused_shrink}, error, now)` : `last_attempt_at`, `last_outcome`, `last_error` assaini (`LogText`, 500 caractères) ; `last_success_at` et validateurs **inchangés** ;
   - `sync_state(source) -> Option<SyncState>` (validateurs, `dump_sha256`, `entries` de l'active, dates, issue).
3. **`sync/mod.rs`** :
   - `trait VulnSource { fn id(&self) -> &'static str; fn meta(&self) -> SourceMeta; fn ready(&self, ctx: &SyncContext) -> Result<(), NotReady> { Ok(()) } fn fetch(&self, dl: &mut Download, sink: &mut dyn Sink, tally: &mut Tally) -> Result<FetchOutcome, SyncError>; }` ;
   - `SourceMeta { url: &'static str, hosts: &'static [&'static str], license, attribution, limits: Limits }` ; `SyncContext { now, state: Option<SyncState> }` ; `FetchOutcome { Unchanged, Loaded { unpacked_bytes } }` ; `Sink::push(Advisory) -> Result<(), SyncError>` ;
   - `SyncOptions { trust, endpoint_override: Option<Url>, limits_override: Option<Limits>, free_space_override: Option<u64> }`, `Default` = production ;
   - `run(config, options, clock, only: Option<&str>, accept_shrink) -> SyncReport` : `Store::open` (écrivain, migre), sources de `registry::declared`, une à une ; journal d'une ligne par source (issue, entrées lues, retenues, écartées par raison, Mo téléchargés, durée, génération).
4. **`sync/engine.rs`**, pour une source :
   1. `ready` → `NotReady` : `record_outcome(failed, raison)`, aucune requête ;
   2. `Load::begin` (F1) → `LoadBusy` : `record_outcome(busy)`, aucune requête, pas un échec ;
   3. `WorkDir::prepare`, `Download` avec les validateurs de `sync_state`, l'URL de la source (ou `endpoint_override`) et l'échéance `now + limits.duration` ;
   4. `fetch` : `Fetched::NotModified` → `Unchanged` ; dump dont la SHA-256 égale `dump_sha256` de l'active → `Unchanged` sans ouvrir le zip ; sinon lecture et `Sink` (lots de `VULN_BATCH`, `Load::push` de F1) ;
   5. `Unchanged` → `Load::release` puis `mark_fresh` ; `Loaded` → garde de rétrécissement (retenues < 80 % de l'active de 100 failles ou plus, sauf `accept_shrink`) → `Load::release` + `record_outcome(refused_shrink)`, sinon `Load::commit(SyncMeta)` ; `Supplanted` / `LeaseExpired` de F1 → `failed` ;
   6. toute erreur → génération abandonnée (F1 la purge), `record_outcome(failed)`, dossier de travail vidé (`Drop`).
5. **`sources/osv.rs`** : `OsvSource { ecosystem: SourceEcosystem }` pour `Packagist`, `Npm`, `CratesIo` ; `id()` = `osv-packagist`, `osv-npm`, `osv-crates-io` ; `OSV_HOST = "osv-vulnerabilities.storage.googleapis.com"` ; URL `https://{OSV_HOST}/{osv_name}/all.zip` (`crates.io` tel quel dans le chemin) ; licence « par enregistrement » et attribution « OSV.dev, licence de chaque enregistrement selon son préfixe » (F1 garde la licence par faille) ; `fetch` : `Download::get_to_file`, puis `ZipReader`, chaque `Entry::Data` → `Advisory::from_osv(bytes, ecosystem)` → `Sink` ou `Tally` ; `Entry::Skipped` → `Tally` (`too_large`, `bad_entry_name`, raison ajoutée au `Tally` de F1).
6. **`sync/registry.rs`** : `KNOWN = ["osv-crates-io", "osv-packagist", "osv-npm"]` (liste fermée, `match` sans joker dans `build`) ; `declared(config)` : sources de `[vulns] sources` dans l'ordre de `KNOWN` ; point d'extension documenté pour F3 et F4.
7. **`config.rs`** : `[vulns]` facultative, `sources` non vide, chaque identifiant dans `KNOWN`, sans doublon ; erreurs en `ConfigError` (code 2) ; `config.example.toml` commenté.
8. **`main.rs`** : `vigie vulns sync [--source <id>] [--accept-shrink]` (`--accept-shrink` exige `--source`) ; `--source` hors de `[vulns] sources` → `UsageError` (code 2) ; aucune option d'URL ni de plafond ; code 1 si une source est `failed` ou `refused_shrink`, 0 sinon (`busy` compris) ; `vigie vulns sources` (F1) ajoute par source : dernière réussite et son âge, dernière tentative et son issue, dernière erreur, tailles, durée, présence d'ETag.
9. **Fixtures** : `fictif/packagist-divergence.json` (paquet `exemple/paquet`, plage `introduced 1.0.0, fixed 1.2.0`, `versions[]` contenant aussi `1.5.0`) ; les zips de test sont construits par `zipgen` depuis `fixtures/vulns/osv/` (vrais enregistrements, `NOTICE` de F1) et `fictif/`.
10. **Tests** : `vulns_sync.rs` (tous les cas lib du Test Scope ; `FakeClock` pour le bail ; vérification « aucune ligne écrite » par compte de lignes et `active_generation`, « base intacte » par comparaison des lignes de l'active avant et après) ; `vulns_cli.rs` et `config_edges.rs` (cas cli).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration depuis 16 verte ; `MIGRATIONS.len() == SCHEMA_VULNS_SYNC` ; migrations rejouées sans effet ; instantané à jour |
| 2, 4 | Un ETag n'est jamais écrit sans la génération qui lui correspond (test : échec simulé entre `push` et `commit`) ; `release` ne touche pas un bail repris ; échec, `busy` et `refused_shrink` laissent `active_generation`, ses lignes, `dump_sha256` et les validateurs identiques |
| 3, 5-6 | Cas « Happy path », « Idempotence », « Packagist », « Échec », « Rétrécissement », « Concurrence » verts ; le serveur local ne reçoit aucune requête dans les cas `busy` et `NotReady` ; aucune URL hors de `OSV_HOST` n'est constructible sans `SyncOptions::endpoint_override` |
| 7-8 | Cas « Configuration » verts ; codes 0, 1, 2 conformes ; sortie de `vulns sources` sans caractère de contrôle |
| 1-10 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucun test n'appelle un hôte réel ; aucune donnée de production dans les fichiers ajoutés |
