---
status: pending
---

# Instruction: Sources KEV et EPSS dans le cadre F2, CLI et documentation

Prérequis : F2 livrée (`vulns/sync/` : `VulnSource`, `SourceMeta`, `SyncContext`, `Sink`, `FetchOutcome`, `SyncOptions`, `registry.rs`, `engine.rs` ; `vulns/sync/download.rs` ; `Load::release`, `mark_fresh`, `record_outcome` ; `[vulns] sources` ; `tests/support/dump_server.rs` ; `flate2` en dépendance). Avant de commencer, relire F2 tel qu'il a été fusionné et ajuster les noms ci-dessous sans dupliquer ce qu'il fournit.

## Architecture projection

```txt
.
├── CHANGELOG.md                       ✏️ entrée F4 (#18) sous Unreleased
└── vigie/
    ├── config.example.toml            ✏️ [vulns] : kev et epss ajoutés d'office, commentaire
    ├── README.md                      ✏️ sources kev et epss
    ├── src/
    │   ├── config.rs                  ✏️ kev et epss dans la liste fermée ; kev ou epss sans source de failles → ConfigError
    │   ├── main.rs                    ✏️ vulns show : faits KEV et EPSS, gravité et règle ; vulns sources : jeux, stale_count
    │   └── vulns/
    │       ├── sources/
    │       │   ├── kev.rs             ✅ miroir puis cisa.gov ; lecture en mémoire ; seuil 1 %, régression, rétrécissement avant poussée ; KevRow
    │       │   └── epss.rs            ✅ hôtes et redirection ; MultiGzDecoder en flux ; commentaire, en-tête, lignes ; EpssRow
    │       └── sync/
    │           ├── mod.rs             ✏️ SourceMeta.shrink_floor_pct ; FetchOutcome::{Stale, RefusedShrink} et URL servie dans Loaded et Unchanged
    │           ├── enrichment.rs      ✅ trait EnrichmentSource ; EnrichSink (vers EnrichLoad, active(), accept_shrink()) ; raisons ajoutées au Tally
    │           ├── download.rs        ✏️ Request.conditional ; DumpFile porte l'URL demandée
    │           ├── registry.rs        ✏️ KNOWN += kev, epss (en dernier) ; Registered { Vulns, Enrichment } ; declared() les ajoute d'office
    │           └── engine.rs          ✏️ variante Enrichment (EnrichLoad) ; validateurs envoyés seulement si l'URL = validator_url ; seuil de rétrécissement par source ; Stale
    ├── tests/
    │   ├── vulns_enrich_sync.rs       ✅ par dump_server : succès, 304, release, secours, régression, rétrécissement, hostiles, constat à 3 jours, ordre et déclenchement
    │   ├── config_edges.rs            ✏️ kev et epss d'office, explicites, seuls
    │   ├── vulns_cli.rs               ✏️ sources et show avec KEV et EPSS
    │   └── fixtures/vulns/
    │       ├── kev/                   ✅ fictifs (CVE-2099-…) : catalogues N et N+1, entrées invalides, champ requis absent, doublon, count faux, champ inconnu, tronqué, rétréci
    │       └── epss/                  ✅ fictifs, petits ; gros fichiers et bombe gzip générés en flux par le test
    └── docs/
        ├── failles.md                 ✏️ « CISA KEV », « FIRST EPSS », « Gravité », « Hôtes », « À vérifier » ; sous-section « Priorisation (F4) »
        ├── decisions.md               ✏️ sous-section « Priorisation KEV et EPSS (issue #18) » dans « Failles connues »
        └── hebergement.md             ✏️ espace disque (deux générations EPSS), relevé masqué du VPS
```

## Test Scope

```mermaid
journey
  section Setup
    dump_server avec routes du miroir et de cisa.gov (chemins distincts) et d'EPSS ; SyncOptions endpoint_override et limits_override: 5: system
  section Configuration
    [vulns] sources = osv-npm => kev et epss déclarés d'office, après osv-npm: 5: lib
    sources = osv-npm, kev => accepté, kev une seule fois: 1: lib
    sources = kev seul => ConfigError, code 2: 1: lib
    Source de failles retirée => kev et epss plus déclarés, incidents vulns-sync clos plus surveillé: 1: lib
  section Happy path
    vigie vulns sync => sources de failles puis kev puis epss ; journal d'une ligne par source: 5: cli
    kev chargé => 3 entrées, catalogVersion et dateReleased, CC0, attribution CISA KEV, validator_url = miroir: 5: cli
    epss chargé => lignes, model_version et score_date, attribution See EPSS at https://www.first.org/epss: 5: cli
    Issue loaded de kev ou epss => SyncReport le signale pour le rapprochement F7: 1: lib
    vigie vulns show CVE-2099-90001 => KEV, usage par rançongiciel connu non, EPSS, gravité critique (Kev): 5: cli
  section Idempotence et bail
    Second sync, ETag inchangé => 304, release, succès daté, aucune ligne écrite: 5: cli
    Corps identique sans ETag => empreinte inchangée, release, aucune ligne écrite: 5: cli
    Bail kev détenu => busy, aucune requête reçue par le serveur: 1: lib
  section Secours KEV
    Miroir en 500 => cisa.gov chargé, requête vers cisa.gov sans If-None-Match, validator_url = cisa.gov: 1: lib
    Sync suivant, miroir rétabli => requête inconditionnelle au miroir (validator_url différent): 1: lib
    Miroir rétréci (80 % de l'actif) => cisa.gov essayé et chargé: 1: lib
    Miroir N après cisa N+1 actif, cisa.gov N+1 inchangé => miroir refusé, inchangé (périmé), stale_count + 1, actif N+1 gardé: 1: lib
    Miroir N et cisa.gov N après N+1 => inchangé (périmé), succès daté, aucun constat: 1: lib
    Même cas avec --accept-shrink => N chargé, journal le dit: 1: cli
    Miroir et cisa.gov en échec => failed, génération active intacte, code 1: 1: lib
    Redirection vers un hôte hors liste => refusée: 1: lib
  section Edge case - KEV hostile
    cveID hors grammaire, date illisible, champ requis absent, doublon => entrée écartée, comptée: 1: lib
    count différent du nombre d'entrées, ransomware inattendu => comptés, chargement fait: 1: lib
    Champ inconnu (forensicTriage, futur champ) => ignoré: 1: lib
    JSON tronqué ou document de 17 Mio => échec du miroir, secours, puis failed si cisa.gov pareil: 1: lib
    2 % d'entrées écartées => source en échec: 1: lib
  section Edge case - EPSS hostile
    Première ligne sans #model_version ou en-tête cve,epss,score => failed: 1: lib
    Fins de ligne CRLF et ligne vide finale => chargé: 1: lib
    score_date 2099-01-15T00:00:00+0000 et 2099-01-15 => date lue par son préfixe: 1: lib
    Valeur 1.23e-05 => 12 ppm ; ligne epss 1.5, -0.1, CVE invalide => écartée, comptée: 1: lib
    Ligne de 10 000 octets sans fin de ligne => arrêtée à 128 octets, failed: 1: lib
    Bombe gzip générée en flux (64 Mio + 1 décompressés) => arrêtée au plafond, failed: 1: lib
    gzip en deux membres => lu en entier: 1: lib
    EPSS à 70 % de l'actif => refused_shrink après le seuil de 1 %, génération abandonnée: 1: lib
  section Constats
    epss en échec 3 jours (FakeClock) => _veilleur/vulns-sync/epss en avertissement ; résolu au succès suivant: 1: tick
    Un 304 ou un inchangé (périmé) => succès, aucun constat: 1: tick
  section Réseau
    Hôtes appelés en test => serveur local seulement ; aucune URL hors des hôtes codés en dur constructible sans endpoint_override: 1: lib
  section Teardown
    Dossier de travail supprimé, serveur arrêté => état initial: 5: system
```

## Tasks to do

1. **Cadre F2 étendu** (`vulns/sync/`) :
   - `SourceMeta.shrink_floor_pct: u8` (OSV 80, comme F2 ; KEV 90 ; EPSS 80) appliqué par `engine.rs` à la place du 80 % fixe ;
   - `Request.conditional: bool` dans `download.rs` ; `engine.rs` construit les validateurs depuis `sync_state` et ne les attache qu'à une requête dont l'URL complète est égale à `validator_url` ; `DumpFile` porte l'URL demandée ; `FetchOutcome::Loaded` et `Unchanged` la portent jusqu'à `commit` / `mark_fresh` ;
   - `FetchOutcome::Stale { served, active }` → `release`, `mark_fresh(unchanged)` sans toucher aux validateurs, `bump_stale` ; `FetchOutcome::RefusedShrink` → `release`, `record_outcome(refused_shrink)` ;
   - `enrichment.rs` : `trait EnrichmentSource { fn id(&self) -> &'static str; fn meta(&self) -> SourceMeta; fn ready(&self, &SyncContext) -> Result<(), NotReady> { Ok(()) } fn fetch(&self, &mut Download, &mut dyn EnrichSink, &mut Tally) -> Result<FetchOutcome, SyncError>; }` ; `EnrichSink { push_kev, push_epss, active() -> Option<ActiveDataset>, accept_shrink() -> bool }` ; raisons ajoutées au `Tally` (`bad_cve`, `bad_date`, `bad_value`, `missing_field`, `duplicate` écartées ; `unknown_ransomware`, `count_mismatch` comptées seulement) et `Tally::dropped_ratio_exceeds(1 %)` sur les lignes lues ;
   - `registry.rs` : `KNOWN` = sources de failles (F2, F3) puis `kev`, `epss` ; `Registered { Vulns(Box<dyn VulnSource>), Enrichment(Box<dyn EnrichmentSource>) }` ; `declared(config)` ajoute `kev` et `epss` d'office dès qu'une source de failles est déclarée, sans doublon ; `config.rs` : `kev` ou `epss` sans source de failles → `ConfigError` ;
   - `engine.rs` : même parcours que F2 (bail avant toute requête, `Download`, `fetch`, contrôles, bascule ou abandon, état) avec `EnrichLoad` ; ordre des contrôles : 1 % → (KEV : régression, dans la source) → rétrécissement → bascule ; `SyncReport` signale toute issue `loaded`, enrichissement compris, pour déclencher le rapprochement de F7.
2. **`kev.rs`** : URL miroir puis `www.cisa.gov` (hôtes codés en dur ; avec `endpoint_override`, les deux chemins sur le serveur local) ; pour chaque URL tant qu'aucun jeu n'est accepté : `get_to_file` (304 au miroir → `Unchanged`), empreinte égale à l'active → `Unchanged`, document de 16 Mio au plus, `serde` en `Option<String>` puis validation (`Cve::parse`, dates `jiff::civil::Date`, `known_ransomware`, `LogText` 200 pour le nom ; `catalogVersion` ≤ 32 caractères ; `dateReleased` RFC 3339), 20 000 entrées au plus, seuil de 1 %, régression de `dateReleased` par rapport à `sink.active()` sauf `accept_shrink`, rétrécissement sous 90 % sauf `accept_shrink` ; premier jeu accepté poussé par lots puis `Loaded` ; sinon l'issue la plus sévère.
3. **`epss.rs`** : URL et hôtes du plan ; fichier téléchargé par `Download` ; `MultiGzDecoder` derrière un `Read` qui compte et coupe à 64 Mio ; `read_until` borné à 128 octets, `\r` final et dernière ligne vide tolérés ; commentaire (version ≤ 32 caractères, `score_date` par préfixe `AAAA-MM-JJ`), en-tête exact, lignes `Cve` + `parse_ppm` × 2 ; 2 000 000 lignes au plus ; lignes poussées au fil de l'eau ; seuil de 1 % à la fin ; le rétrécissement est contrôlé par le moteur.
4. **CLI** : `vigie vulns sources` montre `kev` et `epss` (version et date du jeu, lignes, écartées par raison, `stale_count`, `validator_url`, âge, licence, attribution) ; `vigie vulns show` imprime pour chaque CVE KEV (`dateAdded`, `dueDate`, « usage par rançongiciel connu : oui / non ») et EPSS (score et percentile en décimal, date du modèle), puis « gravité : <niveau> (<règle>) » par `assess` sur `StoreTables` ; `show <CVE>` marche aussi pour un CVE présent seulement dans KEV ou EPSS.
5. **Tests** : `vulns_enrich_sync.rs` (cas « lib » et « tick » du Test Scope par `tests/support/dump_server.rs`, `SyncOptions { endpoint_override, limits_override }`, `FakeClock` ; fichiers EPSS volumineux et bombe gzip écrits en flux dans un dossier temporaire, jamais commités) ; `config_edges.rs` (cas « Configuration ») ; `vulns_cli.rs` (cas « cli », sortie sans caractère de contrôle). Fixtures fictives seulement, CVE `CVE-2099-…`, aucun texte repris d'une vraie entrée KEV.
6. **Documentation** :
   - `failles.md` : « CISA KEV » complétée par les mesures du 2026-10-17, les deux hôtes, la régression de `dateReleased` et le secours ; « FIRST EPSS » : format toléré, plafonds provisoires, millionièmes tronqués ; « Gravité » : renvoi à `vulns/severity.rs`, règles nommées, groupes fusionnés, inconnues ; sous-section « Priorisation (F4) » : tables, générations, `validator_url`, ordre des contrôles, seuil de 1 % (dénominateur et raisons), rétrécissement par source, déclaration d'office, ordre de synchronisation, `StoreTables` ; « À vérifier » : points 3 et 4 cochés et datés après le relevé ;
   - `decisions.md` : sous-section « Priorisation KEV et EPSS (issue #18) », une ligne par décision du plan et sa raison, dont les écarts à l'issue (règle, `model_date`) ;
   - `hebergement.md` : espace disque (deux générations EPSS le temps d'un chargement, mesuré par le test de contention) ; relevé masqué d'une synchronisation réelle (URL finale, ETag ou `Last-Modified`, poids, durée, lignes) ;
   - `config.example.toml`, `README.md`, `CHANGELOG.md`.
7. **Relevé VPS** (exploitant, hors CI) : `vigie vulns sync --source kev` puis `--source epss`, deux fois chacun (le second : 304 ou empreinte inchangée).
8. **Grammaire EPSS figée** après le relevé : forme réelle des nombres, de `score_date` et des fins de ligne consignée dans `failles.md` ; parseur et fixtures resserrés à ce qui est observé (les tolérances ci-dessus gardées) ; plafonds ajustés si le poids réel les approche à moins d'un facteur 2, décision consignée.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | KEV et EPSS passent par le même moteur, le même bail, le même état et le même constat que les sources de F2, sans être des `Advisory` ; tests de F2 verts (seuil OSV toujours 80 %) ; un validateur n'est jamais envoyé à une autre URL que celle qui l'a servi |
| 1, config | `kev` et `epss` déclarés d'office ; seuls → `ConfigError` ; retirés avec la dernière source de failles → incidents clos « plus surveillé » |
| 2 | Régression refusée et secours essayé ; miroir rétréci → secours ; issues `loaded`, `unchanged`, inchangé (périmé), `refused_shrink`, `failed` conformes au Test Scope ; aucune ligne poussée avant que le jeu soit accepté |
| 2, 3 | Chaque fixture hostile donne exactement l'issue attendue, sans panique ni allocation au-delà des plafonds ; ordre 1 % → régression → rétrécissement → bascule |
| 4 | `show` explique la gravité (niveau et règle) ; `sources` imprime licences, attributions et `stale_count` |
| 5 | Aucun appel réseau hors du serveur local ; constats `vulns-sync/kev` et `vulns-sync/epss` ouverts à 3 jours et résolus au succès suivant |
| 6-8 | `failles.md` et `decisions.md` couvrent chaque décision et limite du plan ; relevé daté et masqué ; grammaire EPSS figée |
| 1-8 | fmt, clippy, tests verts sur Linux et Windows ; musl et `check-tls-deps.sh` verts ; `Cargo.toml` inchangé ; critères transmis à F7 (#21) : rapprochement déclenché par une issue `loaded` de KEV ou EPSS, constat ouvert passé en critique au passage suivant, gravité d'un groupe par `assess_group`, inconnues par `assess_unknown` et maximum par composant |
