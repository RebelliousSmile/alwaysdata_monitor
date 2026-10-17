---
status: pending
---

# Instruction: Sources KEV et EPSS dans le cadre F2, CLI et documentation

Prérequis : F2 livrée (registre de sources, `Download` borné, état et conditionnels dans `vuln_sources`, constat `vulns-sync/<source>`, serveur HTTP de test, `vigie vulns sync`). Avant de commencer, relire le plan F2 réellement livré et adapter les noms ci-dessous (`EnrichmentSource`, `EnrichSink`, `Download`) à son interface, sans dupliquer ce qu'il fournit.

## Architecture projection

```txt
.
├── CHANGELOG.md                       ✏️ entrée F4 (#18) sous Unreleased
└── vigie/
    ├── Cargo.toml                     ✏️ flate2 (rust_backend) passé en [dependencies], sauf si F2 l'a fait
    ├── README.md                      ✏️ sources kev et epss, --accept-shrink
    ├── src/
    │   ├── main.rs                    ✏️ vulns sync --accept-shrink ; vulns show : faits KEV et EPSS, gravité F0 et règle
    │   └── vulns/
    │       ├── sync.rs                ✏️ (module du cadre F2) registre : variante Enrichment(Box<dyn EnrichmentSource>) à côté des VulnSource ; garde de rétrécissement ; seuil de 1 %
    │       └── sources/
    │           ├── enrichment.rs      ✅ trait EnrichmentSource { id, meta, load(&mut Download, &mut EnrichSink) } ; EnrichSink (vers EnrichLoad) ; EnrichTally
    │           ├── kev.rs             ✅ URL miroir puis cisa.gov ; analyse JSON bornée ; KevRow
    │           └── epss.rs            ✅ URL et hôtes de redirection ; MultiGzDecoder en flux ; commentaire, en-tête, lignes ; EpssRow
    ├── tests/
    │   ├── vulns_enrich_sync.rs       ✅ synchronisation par le serveur HTTP de test de F2 : succès, 304, secours, plafonds, hostiles, rétrécissement, constat à 3 jours
    │   ├── vulns_cli.rs               ✏️ sources et show avec KEV et EPSS
    │   └── fixtures/vulns/
    │       ├── kev/                   ✅ fictifs : catalogue valide, entrées invalides, doublon, count faux, champ inconnu, tronqué, 17 Mio, rétréci
    │       └── epss/                  ✅ fictifs (générés par le test quand ils sont gros) : valide, commentaire absent, en-tête changé, lignes invalides, ligne sans fin, bombe gzip, multi-membres, rétréci
    └── docs/
        ├── failles.md                 ✏️ sections « CISA KEV », « FIRST EPSS », « Gravité », « Hôtes », « À vérifier » ; nouvelle sous-section « Priorisation (F4) »
        ├── decisions.md               ✏️ sous-section « Priorisation KEV et EPSS (issue #18) » dans « Failles connues »
        └── hebergement.md             ✏️ espace disque (deux générations EPSS), relevé masqué du VPS
```

## Test Scope

```mermaid
journey
  section Setup
    Serveur HTTP de test de F2 avec les fixtures => sources kev et epss pointées dessus par le point d'injection de F2: 5: system
  section Happy path
    vigie vulns sync --source kev => 3 entrées, catalogVersion et dateReleased, licence CC0, attribution CISA KEV: 5: cli
    vigie vulns sync --source epss => lignes chargées, model_version et score_date, attribution See EPSS at https://www.first.org/epss: 5: cli
    Second sync, ETag inchangé => 304, succès daté, aucune écriture: 5: cli
    Corps identique sans ETag => empreinte inchangée, aucune écriture: 5: cli
    vigie vulns show CVE-2026-90001 => fait KEV, EPSS, gravité critique, règle KEV: 5: cli
  section Secours KEV
    Miroir en 500 => cisa.gov servi, chargé ; requête inconditionnelle vers le nouvel hôte: 1: lib
    Miroir et cisa.gov en échec => source en échec, génération active intacte: 1: lib
    Redirection vers un hôte hors liste => refusée, source en échec: 1: lib
  section Edge case - KEV hostile
    cveID hors grammaire, date illisible, doublon => entrée écartée, comptée: 1: lib
    count différent du nombre d'entrées => compté count_mismatch, chargement fait: 1: lib
    Champ inconnu (forensicTriage, futur champ) => ignoré: 1: lib
    JSON tronqué ou document de 17 Mio => source en échec, ancien jeu gardé: 1: lib
    Plus de 1 % d'entrées écartées => source en échec: 1: lib
  section Edge case - EPSS hostile
    Première ligne sans #model_version ou en-tête cve,epss,score => source en échec: 1: lib
    Ligne epss 1.5, -0.1, 1e-5, CVE invalide => écartée, comptée: 1: lib
    Ligne de 10 000 octets sans fin de ligne => arrêtée à 128 octets, source en échec: 1: lib
    Bombe gzip (1 Mio → 1 Gio) => arrêtée au plafond décompressé, aucune allocation au-delà: 1: lib
    gzip en deux membres => lu en entier: 1: lib
  section Rétrécissement
    KEV à 80 % de l'actif => refusé, source en échec, ancien jeu gardé: 1: lib
    Même sync avec --accept-shrink => accepté, inscrit au journal: 1: cli
  section Constats
    epss en échec 3 jours (FakeClock) => constat vulns-sync/epss en avertissement ; résolu au succès suivant: 1: lib
    Un 304 => compte comme succès, aucun constat: 1: lib
  section Réseau
    Hôtes appelés en test => serveur local seulement ; jamais api.first.org ni api.osv.dev: 1: lib
  section Teardown
    Dossier de travail 0700 supprimé, serveur arrêté => état initial: 5: system
```

## Tasks to do

1. **`sources/enrichment.rs`** : trait `EnrichmentSource` (`id() -> &'static str` : `kev` ou `epss` ; `meta()` : URL, hôtes codés en dur, licence, attribution, plafonds ; `load(&self, &mut Download, &mut EnrichSink) -> Result<EnrichTally, SourceError>`) ; `EnrichSink` qui alimente `EnrichLoad` (phase 2) par lots ; `EnrichTally` par raison (`bad_cve`, `bad_date`, `bad_value`, `duplicate`, `unknown_ransomware`, `count_mismatch`), sans texte de la source. Le registre de F2 gagne une variante pour ces sources ; `vigie vulns sync` les traite dans le même parcours, avec le même état, les mêmes conditionnels et le même constat `vulns-sync/<source>`.
2. **`kev.rs`** : URL miroir, puis `www.cisa.gov` en secours (règles du plan) ; document de 16 Mio au plus ; `serde` : en-tête requis, entrées en `Vec` de structures dont les champs non retenus sont `IgnoredAny` ; 20 000 entrées au plus ; `Cve::parse`, dates par `jiff::civil::Date`, `knownRansomwareCampaignUse`, `vulnerabilityName` par `LogText` (200) ; `DatasetInfo` depuis `catalogVersion` (borné à 32 caractères) et `dateReleased` (RFC 3339).
3. **`epss.rs`** : URL et hôtes de redirection du plan ; fichier téléchargé par `Download` dans le dossier de travail ; `MultiGzDecoder` derrière un `Read` qui compte et coupe au plafond décompressé ; `BufRead::read_until` borné à 128 octets ; commentaire `#model_version:<v>,score_date:<RFC 3339>` (version bornée à 32 caractères), en-tête exact, lignes `Cve` + `parse_ppm` × 2 ; 2 000 000 lignes au plus ; lignes poussées dans le puits sans tout garder en mémoire.
4. **Cadre** : seuil de rejet (> 1 % écartées → échec) ; garde de rétrécissement (KEV < 90 %, EPSS < 80 % de `active_rows`) et option `--accept-shrink` de `vigie vulns sync`, journalisée ; `flate2` en dépendance si besoin.
5. **CLI** : `vigie vulns sources` montre `kev` et `epss` (version et date du jeu, lignes, écartées par raison, âge, licence, attribution) ; `vigie vulns show` imprime, pour chaque CVE de la faille, KEV (`dateAdded`, `dueDate`, rançongiciel) et EPSS (score et percentile en décimal, date du modèle), puis « gravité : <niveau> (<règle>) » par `assess` sur `StoreTables` ; `show <CVE>` fonctionne aussi pour un CVE présent seulement dans KEV ou EPSS (faits seuls, sans faille).
6. **Tests** : `vulns_enrich_sync.rs` (tous les cas « lib » du Test Scope par le serveur HTTP de test de F2 ; fixtures EPSS volumineuses et bombe gzip générées dans un dossier temporaire par le test, jamais commitées) ; `vulns_cli.rs` (cas « cli », sortie sans caractère de contrôle). Fixtures fictives seulement, CVE `CVE-2026-9xxxx`, aucun texte repris d'une vraie entrée KEV.
7. **Documentation** :
   - `failles.md` : « CISA KEV » complétée par les mesures du 2026-10-17 (en-têtes, ETag et 304, pas de `Last-Modified`, gzip servi, schéma et champs requis, valeurs observées) et la règle de secours ; « FIRST EPSS » : format, plafonds provisoires, troncature en millionièmes ; « Gravité » : renvoi à `vulns/severity.rs`, règles nommées, règle des inconnues (version ou plage inconnue sur une faille critique → avertissement) ; nouvelle sous-section « Priorisation (F4) » : tables, générations, garde de rétrécissement, seuil de 1 %, `StoreTables` ; « À vérifier depuis le VPS » : points 3 et 4 cochés avec la date une fois le relevé fait ;
   - `decisions.md` : sous-section « Priorisation KEV et EPSS (issue #18) », une ligne par décision du plan et sa raison, dont l'écart à la règle de l'issue et l'écart `model_date` ;
   - `hebergement.md` : espace disque (deux générations EPSS le temps d'un chargement, ordre de grandeur mesuré par le test de contention), relevé masqué d'une synchronisation réelle depuis le VPS (URL finale, ETag présent ou non, poids, durée, lignes) ;
   - `README.md`, `CHANGELOG.md`.
8. **Relevé VPS** (exploitant, hors CI) : `vigie vulns sync --source kev` puis `--source epss`, deux fois chacun (le second doit faire 304 ou « empreinte inchangée ») ; plafonds ajustés si le poids réel d'EPSS les approche à moins d'un facteur 2, décision consignée.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | KEV et EPSS passent par le même parcours, le même état et le même constat que les sources de failles de F2, sans être des `Advisory` |
| 2, 3 | Chaque fixture hostile donne exactement l'issue attendue (ligne écartée et comptée, ou source en échec avec ancien jeu gardé), sans panique ni allocation au-delà des plafonds |
| 4 | Rétrécissement refusé sans `--accept-shrink`, accepté avec, journalisé ; > 1 % d'écartées → échec |
| 5 | `show` explique la gravité (niveau et règle) ; `sources` imprime licences et attributions |
| 6 | Aucun appel réseau hors du serveur local ; constat `vulns-sync/kev` et `vulns-sync/epss` ouvert à 3 jours et résolu au succès suivant |
| 7 | `failles.md` et `decisions.md` couvrent chaque décision et limite du plan ; aucune donnée de production ; relevé VPS masqué |
| 8 | Relevé consigné et daté ; « À vérifier » mis à jour |
| 1-8 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `check-tls-deps.sh` vert ; seule modification de `Cargo.toml` : `flate2` en dépendance (déjà au `Cargo.lock`) ; critère transmis à F7 (#21) : une faille entrée dans KEV fait passer le constat ouvert en critique au passage suivant |
