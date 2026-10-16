---
status: done
---

# Instruction: Runtime, capacités et liste des commandes

## Architecture projection

```txt
.
└── vigie/
    ├── config.example.toml        ✏️ runtime documenté
    ├── README.md                  ✏️ colonne runtime de `site list`
    ├── migrations/
    │   └── 0007.sql               ✅ table meta (clé, valeur)
    ├── src/
    │   ├── config.rs              ✏️ enum Runtime, Site.runtime, Site::runtime() effectif, validation CMS ⇒ runtime, SiteKind::as_str, load_with_raw, typology_fingerprint
    │   ├── capability.rs          ✅ CommandKind (liste fermée), from_name, runtimes(), permit(command, site) fail-closed
    │   ├── checks/mod.rs          ✏️ CheckKind::cms() ; applies lit la table
    │   ├── store.rs               ✏️ SCHEMA_META = 7, meta get/set
    │   ├── serve.rs               ✏️ écrit son empreinte en base au démarrage
    │   ├── tick.rs                ✏️ écrit l'empreinte et journalise le détail quand elle change
    │   ├── api.rs                 ✏️ runtime effectif publié ; kind_name remplacé par SiteKind::as_str
    │   ├── main.rs                ✏️ `site list` : runtime en fin de ligne ; `status` : trois empreintes ; `site add` : avertissement sans runtime
    │   └── lib.rs                 ✏️ déclare capability
    └── docs/
        ├── api-console.md         ✏️ champ runtime (effectif)
        ├── agent-php.md           ✏️ site PHP en generic : poser runtime = "php"
        ├── hebergement.md         ✏️ ordre de déploiement et retour arrière
        ├── decisions.md           ✏️ section #2 : runtime et non kind, registre non signé mais empreinte
        └── protocole-commandes.md ✅ enveloppe d'une commande, champ runtime, refus côté agent et côté veilleur
```

## User Journey

```mermaid
flowchart TD
  A[config.toml : kind et runtime] --> B{runtime contraire au CMS ?}
  B -->|oui| X[Erreur de configuration, code 2]
  B -->|non| C[Site::runtime : déclaré, sinon php pour wordpress et prestashop, sinon aucun]
  C --> D[Contrôles : CheckKind::cms contient le kind ?]
  C --> E[Commande : permit(command, site)]
  E -->|runtime absent ou non admis| R[Refus fail-closed]
  E -->|admis| OK[Commande autorisée]
```

## Test Scope

```mermaid
journey
  section Happy path
    wordpress sans runtime => runtime php: 5: config
    htaccess-apply pour un site php => autorisée: 5: capability
  section Edge case - dérive de privilèges
    matrice CommandKind::ALL × {aucun, php, node, static} contre une table littérale: 1: capability
    htaccess-apply pour static et pour node => refusée: 1: capability
    generic sans runtime => toute commande refusée: 1: capability
    nom inconnu => from_name refuse: 1: capability
  section Edge case - configuration
    wordpress avec runtime node => erreur nommant le site: 1: config
    runtime python => erreur de lecture: 1: config
  section Empreinte
    modification d'un runtime => une ligne de journal au tick suivant, une seule ; commentaire ajouté => empreinte inchangée: 5: tick
    status sur une base v6 => pas d'erreur, empreintes « inconnues »: 1: cli
    status sur une base v7 sans typology.serve => « serve à redémarrer »: 1: cli
  section Contrôles
    installer pour generic => non ; pour wordpress et prestashop => oui: 5: checks
```

## Tasks to do

### `1)` Runtime

1. `enum Runtime { Php, Node, Static }`, `serde(rename_all = "lowercase")`, `as_str`, sans `Default`.
2. `Site.runtime: Option<Runtime>` ; `Site::effective_runtime() -> Option<Runtime>` : déclaré, sinon `Php` pour `wordpress` et `prestashop`, sinon `None`.
3. `validate` : `wordpress`/`prestashop` avec un runtime autre que `php` → erreur nommant le site.
4. `SiteKind::as_str` ; `api.rs` perd `kind_name`.

### `2)` Capacités

1. `capability.rs` : `enum CommandKind { Ping, RotateKey, HtaccessApply, HtaccessRollback }`, `ALL`, `name()` (`ping`, `rotate-key`, `htaccess-apply`, `htaccess-rollback`), `from_name()` (`None` pour l'inconnu), `runtimes()` par `match` sans joker : `&[Runtime::Php]` pour les quatre.
2. `permit(command, site) -> Result<(), Refusal>` ; `Refusal::NoRuntime`, `Refusal::RuntimeNotAllowed { runtime }`.
3. `CheckKind::cms() -> &'static [SiteKind]` par `match` sans joker : `installer` → `wordpress`, `prestashop` ; les autres → les trois. `applies(site)` = `cms().contains(&site.kind)`.

### `3)` Empreinte

1. `config::load` garde son contrat ; `typology_fingerprint(&Config)` hache, triés par `id`, `id`, `kind`, runtime effectif (ou `-`) de chaque site : déplacer un bloc `[[sites]]` ne change rien.
2. Migration 0007 (`meta`), `SCHEMA_META = 7`, `Store::meta`/`set_meta` en IMMEDIATE.
3. `serve` : au démarrage, après la migration, écrit `typology.serve` (empreinte et heure) ; un échec (base absente, que `serve` ne crée pas, migration en échec, base occupée) est journalisé et `serve` continue. `tick` : compare à `typology.tick`, journalise la liste des sites dont le CMS ou le runtime a changé, écrit la nouvelle.
4. `vigie status` : empreinte du fichier, de `tick`, de `serve` ; « serve à redémarrer » si celle de `serve` diffère de celle du fichier ou manque sur une base en v7 (ancien `serve` encore en mémoire) ; garde `SCHEMA_META` pour une base plus ancienne.
5. Test de schéma `migration_files_build_the_expected_schema` mis à jour.

### `4)` Exposition et documentation

1. `api.rs` : `runtime` effectif (`php`, `node`, `static` ou `null`) dans `overview`, `sites/{id}` et `settings`.
2. `vigie site list` : runtime en dernière colonne. `site add` : avertissement si `permit` refuse toutes les commandes.
3. `protocole-commandes.md` : enveloppe d'une commande telle que #10 la servira (`v`, `site`, `id`, `seq`, `name`, `runtime`, `params`, `issued_at`, `expires_at`), schéma strict qui refuse tout champ inconnu, signature sur les octets exacts du corps sans réencodage ; refus côté agent : `v` inconnu, `site` différent du sien (la clé de commandes est commune à tous les sites), runtime différent du sien, valeur ou commande inconnue ; revérification de `permit` à la délivrance ; liste et runtimes.
4. `hebergement.md`, `agent-php.md`, `decisions.md`, `api-console.md`, `README.md` comme dans l'arborescence.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1    | Les cas de configuration échouent avec un message qui nomme le site ; `config.example.toml` se lit toujours |
| 2    | La matrice complète est testée ; `permit` n'accepte rien sans runtime |
| 3    | Une modification de typologie produit une ligne de journal au tick suivant, et une seule ; `status` signale un `serve` en retard |
| 4    | La console existante lit toujours les réponses ; `protocole-commandes.md` fixe l'enveloppe et le champ `runtime` |
