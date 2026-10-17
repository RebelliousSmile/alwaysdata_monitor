---
status: pending
---

# Instruction: Cadre de synchronisation, source OSV, état par source et vigie vulns sync

Prérequis : F1 (#15) fusionné (`Advisory::from_osv`, `Tally`, `SourceEcosystem::osv_name`, `vulns/store.rs` avec `upsert_source`, `Load`, purge, migration 0015). F2 modifie l'API de `Load` sans changer ses règles : **`lease` devient un paramètre de `begin`**, **nouvelle signature de `commit(tally, SyncMeta)`**, ajouts `release` et de la primitive générique `finish_unchanged` ; `Tally` gagne `bad_entry_name` (F2), `bad_json` et `no_affected_out_of_scope` (demandés à F1), et `Reason::is_drop()` (F1). Il n'existe **pas** de `mark_fresh`.

## Architecture projection

```txt
.
└── vigie/
    ├── config.example.toml            ✏️ [vulns] sources commentée, renvoi à docs/failles.md
    ├── migrations/
    │   └── 0017.sql                   ✅ ALTER TABLE vuln_sources ADD COLUMN etag, http_last_modified, dump_bytes, unpacked_bytes, last_duration_ms, last_outcome (CHECK), loader_version, last_request_at, retry_after_until, recent_entries ; numéro : prochain libre à la fusion
    ├── src/
    │   ├── config.rs                  ✏️ Config.vulns: Option<Vulns> ; Vulns { sources: Vec<String> } (deny_unknown_fields) validé contre sync::registry::KNOWN
    │   ├── store.rs                   ✏️ entrée 17 de MIGRATIONS, SCHEMA_VULNS_SYNC ; tests figeant la dernière version et instantané du schéma mis à jour
    │   ├── main.rs                    ✏️ Vulns::Sync { source: Option<String>, accept_shrink: bool } ; vulns sources affiche l'état de synchronisation et l'âge du bail
    │   └── vulns/
    │       ├── advisory.rs            ✏️ (F1) Tally : bad_entry_name, no_affected_out_of_scope
    │       ├── store.rs               ✏️ (F1) Load::begin(.., lease) ; Load::release ; finish_unchanged (primitive générique de bail) ; Load::commit(tally, SyncMeta) ; claim_request ; record_outcome ; sync_state(source)
    │       ├── sources/
    │       │   ├── mod.rs             ✅
    │       │   └── osv.rs             ✅ OsvSource { ecosystem } : id, meta (origine codée en dur, LOADER_VERSION, min_interval 0), fetch (zip → from_osv → Sink)
    │       └── sync/
    │           ├── mod.rs             ✏️ trait VulnSource, SourceMeta, SyncContext, NotReady, Sink, FetchOutcome ; SyncOptions ; run(config, options, clock, only, accept_shrink) -> SyncReport
    │           ├── registry.rs        ✅ KNOWN (identifiants fermés), build(id) -> Box<dyn VulnSource>, declared(config) dans l'ordre crates.io, Packagist, npm
    │           └── engine.rs          ✅ une source : upsert, bail, débit, Download, fetch, seuil d'écart, garde de rétrécissement, bascule ou abandon, état
    └── tests/
        ├── vulns_sync.rs              ✅ synchronisation complète contre le serveur local : idempotence, 304, empreinte identique, échecs, hostiles, écarts, rétrécissement, bail, débit, LOADER_VERSION, divergence Packagist
        ├── vulns_cli.rs               ✏️ (F1) vulns sync et vulns sources avec état de synchronisation
        ├── config_edges.rs            ✏️ [vulns] : identifiant inconnu, doublon, clé inconnue
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
    vulns sync => trois sources chargées, last_outcome loaded, ETag, Last-Modified, SHA-256, LOADER_VERSION, tailles et durée gardés: 5: cli
    vulns match sur un purl des fixtures => faille trouvée après synchronisation: 5: cli
    vulns sources => âge de la dernière réussite, issue, entrées, écartées par raison, tailles, bail en cours: 5: cli
    vulns sync --source osv-npm => seule la source npm est demandée au serveur: 5: cli
  section Idempotence
    Second vulns sync, serveur en 304 => not_modified, active_generation identique, aucune ligne de faille écrite, bail rendu, last_success_at avancé: 5: lib
    Second vulns sync, serveur sans ETag et même dump => unchanged par SameDigest, aucune ligne de faille écrite: 5: lib
    Bascule concurrente injectée entre le 304 et finish_unchanged => zéro ligne, rien écrit, issue busy: 1: lib
    Dump modifié => nouvelle génération active, ancienne purgée: 5: lib
    LOADER_VERSION incrémentée, même dump et serveur prêt au 304 => requête sans conditionnels, nouvelle génération chargée: 1: lib
  section Packagist
    Faille fictive dont versions[] contient une version hors plage => match Affected avec divergence, plage évaluée par Composer: 1: lib
  section Échec, base précédente intacte
    Serveur en 500, réseau coupé, échéance dépassée => failed, last_error assaini, génération active et ETag inchangés: 1: lib
    Zip à CRC faux, bombe menteuse, recouvrement, trop d'entrées => failed, aucune faille ajoutée ni retirée: 1: lib
    Content-Length géant ou corps sans fin => failed sans écrire plus que le plafond: 1: lib
    Une source en échec => les deux autres chargées, code de sortie 1: 1: cli
  section Seuil d'écart
    Zip sain avec 0,5 % d'entrées JSON invalides => chargé, bad_json compté: 5: lib
    Zip sain avec 2 % d'entrées JSON invalides => failed, génération abandonnée, compteurs dans last_error: 1: lib
    Zip sain avec 5 % d'entrées portant une référence refusée => chargé (bad_reference est une Note): 5: lib
    Toutes les raisons de Tally classées par is_drop => match sans joker, test de table: 5: lib
    Zip avec 10 % de withdrawn et 5 % de failles dont tous les affected sont d'un autre écosystème => chargé: 5: lib
  section Rétrécissement
    Dump valide de 10 failles après des chargements de 1 000 => refused_shrink, actif gardé, code 1: 1: lib
    Chargements successifs à 1 000, 850, 700 => le troisième refusé (moins de 80 % du maximum des 7 derniers): 1: lib
    Même dump avec --accept-shrink => chargé, journal le dit: 5: cli
    1 000, puis 500 accepté par --accept-shrink, puis 500 le lendemain sans option => chargé (recent_entries remplacé par 500): 1: lib
  section Débit et concurrence
    Bail détenu par une autre synchronisation => busy, aucune requête au serveur, code 0: 1: lib
    Bail perdu pendant le chargement (horloge avancée au-delà du bail) => failed, aucune donnée mélangée: 1: lib
    Source de test à min_interval 30 min, seconde synchro 10 min après => rate_limited, aucune requête, last_request_at inchangé: 1: lib
    429 avec Retry-After 1 h => retry_after_until écrit ; synchro suivante avant l'heure => rate_limited sans requête: 1: lib
    Refus de ready() => aucune requête, last_request_at inchangé: 1: lib
  section Configuration
    Sans section vulns => vulns sync dit aucune source de failles déclarée, code 0: 5: cli
    Source en rate_limited (Retry-After OSV) => code 0, issue affichée: 5: cli
    sources avec osv-pypi, doublon ou clé inconnue => erreur de configuration, code 2: 1: cli
    --source absente de la configuration => erreur d'usage, code 2: 1: cli
  section Teardown
    Dossier vulns-work vide après chaque synchronisation, réussie ou non: 5: system
```

## Tasks to do

1. **Migration 0017** (prochain numéro libre à la fusion, après F1 0015 et F5 0016) : `ALTER TABLE vuln_sources ADD COLUMN` `etag TEXT CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 256)`, `http_last_modified TEXT`, `dump_bytes INTEGER`, `unpacked_bytes INTEGER`, `last_duration_ms INTEGER`, `last_outcome TEXT CHECK (last_outcome IS NULL OR last_outcome IN ('loaded','unchanged','not_modified','failed','busy','refused_shrink','rate_limited'))`, `loader_version INTEGER`, `last_request_at INTEGER`, `retry_after_until INTEGER`, `recent_entries TEXT` (tableau JSON de 7 entiers au plus), `revision TEXT` (NULL admis ; commit Friends-Of-Presta en F3) ; `SCHEMA_VULNS_SYNC`, commentaire de `MIGRATIONS` ; tests de `store.rs` (dernière version, montée d'une base remplie depuis la version précédente, instantané `migration_files_build_the_expected_schema`).
2. **`vulns/store.rs`** (ajouts et changements à F1, ses règles intactes) :
   - `Load::begin(store, source, now, lease)` : la durée du bail devient un paramètre (moteur : plafond de durée de la source + 30 min) ;
   - `claim_request(source, now, min_interval) -> bool` : compare-and-swap `UPDATE vuln_sources SET last_request_at = :now, last_attempt_at = :now WHERE id = :id AND (last_request_at IS NULL OR last_request_at <= :now - :min_interval) AND (retry_after_until IS NULL OR retry_after_until <= :now)` ; zéro ligne → `false`, rien écrit ;
   - `Load::release(self)` : `UPDATE … SET loading_generation = NULL, loading_since = NULL WHERE id = ? AND loading_generation = g` ;
   - `finish_unchanged(conn, source, g, expected, validators: Validators::{Keep, Set(..)}, outcome ∈ {not_modified, unchanged}, now) -> bool` : **primitive générique de bail**, appelée par `Load::finish_unchanged` et par l'`EnrichLoad` de F4 ; **une seule instruction** `UPDATE vuln_sources SET loading_generation = NULL, loading_since = NULL, last_success_at = :now, last_attempt_at = :now, last_outcome = :outcome, last_error = NULL[, etag = :etag, http_last_modified = :lm, …] WHERE id = :id AND loading_generation = :g AND active_generation = :expected` ; colonnes de validateurs écrites seulement avec `Set`, liste extensible (F4 ajoute `validator_url`) ; zéro ligne → `false`, rien écrit ;
   - `Load::commit(tally, SyncMeta { sha256, etag, http_last_modified, dump_bytes, unpacked_bytes, duration_ms, loader_version, retained })` (**changement de signature** de F1) : validateurs, `loader_version`, `recent_entries` (ajout de `retained`, 7 derniers ; **avec `accept_shrink`, remplacé par `[retained]`**), `last_outcome = 'loaded'`, `last_success_at`, `last_error = NULL` écrits **dans la même instruction** que la bascule en compare-and-swap ;
   - `record_outcome(source, outcome ∈ {failed, busy, refused_shrink, rate_limited}, error, retry_after_until, now)` : `last_attempt_at`, `last_outcome`, `last_error` assaini (`LogText`, 500 caractères), `retry_after_until` s'il est donné ; `last_success_at`, validateurs et `last_request_at` **inchangés** ;
   - `sync_state(source) -> Option<SyncState>` (validateurs, `dump_sha256` et `entries` de l'active, `loader_version`, `recent_entries`, dates, bail en cours et son âge, issue).
3. **`sync/mod.rs`** :
   - `trait VulnSource { fn id(&self) -> &'static str; fn meta(&self) -> SourceMeta; fn ready(&self, ctx: &SyncContext) -> Result<(), NotReady> { Ok(()) } fn fetch(&self, dl: &mut Download, sink: &mut dyn Sink, tally: &mut Tally) -> Result<FetchOutcome, SyncError>; }` ;
   - `SourceMeta { url: &'static str, origins: &'static [(&'static str, u16)], license, attribution, limits: Limits, min_interval: Duration, loader_version: u32 }`, structure extensible (F3 y ajoute `Redistribution`) ; `SyncContext { now, state: Option<SyncState> }` ; `FetchOutcome { Unchanged { not_modified: bool }, Loaded { unpacked_bytes } }` ; `Sink::push(Advisory) -> Result<(), SyncError>` ;
   - `SyncOptions { trust, endpoint_override: Option<Url>, limits_override: Option<Limits>, free_space_override: Option<u64> }`, `Default` = production ; `endpoint_override` épingle l'origine complète ;
   - `run(config, options, clock, only: Option<&str>, accept_shrink) -> SyncReport` : `Store::open` (écrivain, migre), sources de `registry::declared`, une à une ; journal d'une ligne par source (issue, entrées lues, retenues, écartées par raison, Mo téléchargés, durée, génération).
4. **`sync/engine.rs`**, pour une source :
   1. `upsert_source(meta)` (F1) ;
   2. `ready` → `NotReady` : `record_outcome(failed, raison)` (écrit `last_attempt_at`, jamais `last_request_at`), aucune requête ;
   3. `Load::begin(.., lease)` → `LoadBusy` : `record_outcome(busy)`, aucune requête, pas un échec ;
   4. `claim_request(now, meta.min_interval)` → `false` : `Load::release`, `record_outcome(rate_limited)`, aucune requête ;
   5. `Download` : origines de la source (ou `endpoint_override`), `WorkDir::prepare`, échéance `now + limits.duration`, validateurs de `sync_state` avec `conditional = (loader_version enregistrée == meta.loader_version)` ;
   6. `fetch` : `NotModified` ou `SameDigest` → `FetchOutcome::Unchanged` ; sinon lecture et `Sink` (lots de `VULN_BATCH`, `Load::push` de F1), second contrôle disque après le répertoire central ;
   7. `Unchanged` → `Load::finish_unchanged` (faux → issue `busy` journalisée, rien d'autre) ; `Loaded` → **seuil d'écart** (`dropped / lues > limits.max_dropped_ratio`, où `dropped` = somme des raisons `Reason::is_drop()` moins `withdrawn` et `no_affected_out_of_scope` ; les raisons Note ne comptent jamais ; `max_dropped_ratio` surchargeable par la source dans ses `Limits`) → `failed` ; puis **garde de rétrécissement** (retenues < 80 % du maximum de `recent_entries`, ce maximum ≥ 100, sauf `accept_shrink`) → `refused_shrink` ; sinon `Load::commit(SyncMeta)` ; `Supplanted` / `LeaseExpired` de F1 → `failed` ;
   8. toute erreur → `Load::release` (génération orpheline purgée par F1), `record_outcome(failed | rate_limited)` avec `retry_after_until` si `Status { retry_after: Some(_) }` ; dossier de travail vidé (`Drop`).
5. **`sources/osv.rs`** : `OsvSource { ecosystem: SourceEcosystem }` pour `Packagist`, `Npm`, `CratesIo` ; `id()` = `osv-packagist`, `osv-npm`, `osv-crates-io` ; `OSV_ORIGIN = ("osv-vulnerabilities.storage.googleapis.com", 443)` ; URL `https://osv-vulnerabilities.storage.googleapis.com/{osv_name}/all.zip` (`crates.io` tel quel dans le chemin) ; `LOADER_VERSION = 1` (commentaire : à incrémenter à chaque changement du lecteur, de `from_osv` ou des bornes F1) ; `min_interval` 0 ; licence « par enregistrement » et attribution « OSV.dev, licence de chaque enregistrement selon son préfixe » (F1 garde la licence par faille) ; `fetch` : `Download::get_to_file`, puis `ZipReader`, chaque `Entry::Data` → `Advisory::from_osv(bytes, ecosystem)` → `Sink` ou `Tally` ; `Entry::Skipped` → `Tally` (`too_large`, `bad_entry_name`).
6. **`sync/registry.rs`** : `KNOWN = ["osv-crates-io", "osv-packagist", "osv-npm"]` (liste fermée, `match` sans joker dans `build`) ; `declared(config)` : sources de `[vulns] sources` dans l'ordre de `KNOWN` ; point d'extension documenté pour F3 et F4.
7. **`config.rs`** : `[vulns]` facultative ; `sources` : chaque identifiant dans `KNOWN`, sans doublon ; erreurs en `ConfigError` (code 2) ; liste vide admise (équivaut à l'absence) ; `config.example.toml` commenté.
8. **`main.rs`** : `vigie vulns sync [--source <id>] [--accept-shrink]` (`--accept-shrink` exige `--source`) ; aucune source déclarée → « aucune source de failles déclarée », **code 0** ; `--source` hors de `[vulns] sources` → `UsageError` (code 2) ; aucune option d'URL ni de plafond ; code 1 si une source est `failed` ou `refused_shrink`, 0 sinon (`busy` et `rate_limited` compris) ; `vigie vulns sources` (F1) ajoute par source : dernière réussite et son âge, dernière tentative et son issue, dernière erreur, tailles, durée, présence d'ETag, `loader_version`, bail en cours et son âge, `retry_after_until`.
9. **Fixtures** : `fictif/packagist-divergence.json` (paquet `exemple/paquet`, plage `introduced 1.0.0, fixed 1.2.0`, `versions[]` contenant aussi `1.5.0`) ; les zips de test sont construits par `zipgen` depuis `fixtures/vulns/osv/` (vrais enregistrements, `NOTICE` de F1, qui couvre aussi toute entrée `MAL-` réelle ajoutée) et `fictif/` ; une source fictive de test (`min_interval` 30 min) pour les cas de débit.
10. **Tests** : `vulns_sync.rs` (cas lib du Test Scope ; `FakeClock` pour le bail et le débit ; bascule concurrente injectée par un second `Store` entre `fetch` et `finish_unchanged` ; « aucune ligne écrite » par compte de lignes et `active_generation`, « base intacte » par comparaison des lignes de l'active avant et après) ; `vulns_cli.rs` et `config_edges.rs` (cas cli).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration depuis 16 verte ; `MIGRATIONS.len() == SCHEMA_VULNS_SYNC` ; migrations rejouées sans effet ; instantané à jour |
| 2, 4 | Un ETag n'est jamais écrit sans la génération qui lui correspond (test : échec simulé entre `push` et `commit`) ; `finish_unchanged` et `release` n'écrivent rien quand le bail a été repris ou l'active a basculé ; échec, `busy`, `rate_limited` et `refused_shrink` laissent `active_generation`, ses lignes, `dump_sha256` et les validateurs identiques ; `last_request_at` ne bouge que par `claim_request` réussi |
| 3, 5-6 | Cas « Happy path », « Idempotence », « Packagist », « Échec », « Seuil d'écart », « Rétrécissement », « Débit et concurrence » verts ; le serveur local ne reçoit aucune requête dans les cas `busy`, `rate_limited` et `NotReady` ; aucune URL hors de `OSV_ORIGIN` n'est admise sans `SyncOptions::endpoint_override` |
| 7-8 | Cas « Configuration » verts ; codes 0, 1, 2 conformes ; sortie de `vulns sources` sans caractère de contrôle |
| 1-10 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucun test n'appelle un hôte réel ; aucune donnée de production dans les fichiers ajoutés |
