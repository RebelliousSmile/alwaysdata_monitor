---
status: pending
---

# Instruction: Veilleur : source `ci`, clé d'inventaire et réception par source

Prérequis : F5 (#19) fusionné. Avant la première tâche, relire les noms réels de F5 (`inventory/bom.rs`, `inventory/receive.rs`, `Store::accept_inventory`, `InventoryOutcome`, `InventorySource`, `capability::inventory_source`, numéro de la migration de F5) et ajuster cette phase ; tout écart va dans `decisions.md` en phase 4.

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/00NN.sql        ✅ (prochain numéro libre à la fusion, après F2 0017) site_inventory_keys ; site_inventory.source ; index (site, source, id)
    ├── config.example.toml        ✏️ [sites.inventory] sources = ["ci"] commenté, à côté de l'exemple agent-php
    ├── src/
    │   ├── config.rs              ✏️ InventorySource { AgentPhp, Ci } ; [sites.inventory] source (forme F5) ou sources (1 ou 2 distinctes), pas les deux ; agent-php seul exige runtime php
    │   ├── capability.rs          ✏️ inventory_sources(site) -> &[InventorySource] (match sans joker) ; Needs::InventorySource vrai si au moins une source déclarée
    │   ├── inventory/
    │   │   ├── mod.rs             ✏️ Source { Agent, Ci } (valeur stockée et champ d'enveloppe), conversion depuis InventorySource
    │   │   ├── bom.rs             ✏️ enveloppe : champ facultatif source ∈ {agent, ci}, absent = agent
    │   │   └── receive.rs         ✏️ porte : une source déclarée a sa clé ; signature essayée clé d'agent puis clé d'inventaire, la clé qui vérifie fixe la source ; source d'enveloppe égale
    │   ├── ingest.rs              ✏️ raison fixe « schéma : source » (aucun texte reçu)
    │   ├── store.rs               ✏️ add/rotate/remove/inventory_key ; accept_inventory par (site, source) ; last_inventory(site, source) ; purge_inventory par source ; remove_key purge inventory_keys et tout inventaire ; MIGRATIONS, SCHEMA_INVENTORY_KEYS
    │   ├── serve.rs               ✏️ lecture de la clé d'inventaire par la connexion de lecture, avant le corps
    │   ├── tick.rs                ✏️ purge_inventory avec les sources déclarées par site
    │   └── main.rs                ✏️ SiteAction::InventoryKey { id, action: add|rotate|remove, --pubkey } ; site remove sans clé d'agent ; site list : clé d'inventaire oui/non
    └── tests/
        ├── inventory_ci_receive.rs ✅ parcours de réception par source, clés Rust, FakeClock
        └── fixtures/inventory/     ✏️ BOM de référence source ci (site A, generic runtime node), variantes refusées
```

## Test Scope

```mermaid
journey
  section Happy path
    Site A generic runtime node, sources = ["ci"], clé d'inventaire enregistrée => inventaire signé source ci 204, 1 inventaire source ci: 5: api
    Site B wordpress, sources = ["agent-php", "ci"] => inventaire agent 204 puis inventaire ci 204 : 2 derniers inventaires, un par source: 5: api
    Configuration F5 source = "agent-php" => chargée telle quelle, comportement F5 inchangé: 5: api
    Renvoi ci inchangé 300 s plus tard => seen_at avancé, pas de nouvelle ligne ; l'inventaire agent n'est pas touché: 5: api
    inventory-key rotate => last_seq à 0, ancienne clé refusée, nouvelle acceptée, inventaire gardé: 5: cli
  section Edge case
    Clé d'inventaire sur /r/v1/report, /r/v1/logs, /r/v1/commands => 404 (signature): 1: api
    Site à sources = ["ci"] seul : inventaire signé par la clé de rapport => 404: 1: api
    Clé de rapport, enveloppe source ci => 404 (schéma : source) ; clé d'inventaire, source absente ou agent => 404: 1: api
    Site sans ci déclaré mais clé d'inventaire restée en base => 404 avant lecture du corps: 1: api
    sources = ["ci"] sans clé en base => 404 avant lecture du corps (corps de 10 Mio jamais lu): 1: api
    source et sources ensemble, sources vide, en double ou valeur inconnue => configuration refusée au chargement: 1: api
    sources = ["agent-php"] sur un site static => refusé ; sources = ["ci"] sur un generic sans runtime => accepté: 1: api
    inventory-key add sans ci déclaré, clé égale à la clé d'agent du site, clé d'un autre site => refus, code 2: 1: cli
    Débit 240 s et plafond de 24 nouveaux : comptés par (site, source), l'agent n'est pas freiné par la CI: 1: api
    seq ci rejoué => 404 (replay) ; seq agent indépendant: 1: api
    site remove d'un site static sans clé d'agent => clé d'inventaire et inventaires purgés, plus aucune ligne: 1: cli
    ci retiré de la configuration depuis 31 j (FakeClock) => dernier inventaire ci purgé, inventaire agent gardé: 1: api
    Inventaire ci accepté => reports.last_valid_at et incidents inchangés: 1: api
```

## Tasks to do

1. **Configuration** (`config.rs`) : `InventorySource { AgentPhp, Ci }` (`rename_all = "kebab-case"`, `as_str`). `[sites.inventory]` (`deny_unknown_fields`) : `source: Option<InventorySource>` (forme F5) et `sources: Option<Vec<InventorySource>>` ; exactement un des deux ; `sources` de 1 ou 2 valeurs distinctes ; méthode `Site::inventory_sources() -> Vec<InventorySource>`. `AgentPhp` refusé au chargement hors runtime effectif `php` (règle F5, message inchangé) ; `Ci` admis pour tout runtime, `None` compris. `config.example.toml` : exemple commenté de site `static` avec `sources = ["ci"]` (`https://site-a.example.org`).
2. **Registre** (`capability.rs`) : `inventory_sources(site)` remplace (ou complète, selon la forme réelle de F5) `inventory_source(site)` ; tous les appelants de F5 passent par lui ; `Needs::InventorySource` vrai dès qu'une source est déclarée. Test exhaustif sur `SiteKind` × `Runtime` × sources. Aucun `Control` ajouté (F7).
3. **Source d'inventaire** (`inventory/mod.rs`, `inventory/bom.rs`) : `Source { Agent, Ci }` (`"agent"`, `"ci"`) ; l'enveloppe F5 gagne `source: Option<Source>` (absent = `Agent`), toujours `deny_unknown_fields`. Aucun autre champ ajouté au BOM.
4. **Migration 00NN** (prochain numéro libre à la fusion ; 0017 est pris par F2) :
   - `CREATE TABLE site_inventory_keys (site TEXT PRIMARY KEY, pubkey BLOB NOT NULL UNIQUE CHECK (length(pubkey) = 32), last_seq INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL, rotated_at INTEGER)` ;
   - `ALTER TABLE site_inventory ADD COLUMN source TEXT NOT NULL DEFAULT 'agent' CHECK (source IN ('agent','ci'))` ;
   - `CREATE INDEX site_inventory_site_source ON site_inventory (site, source, id)`.
   `SCHEMA_INVENTORY_KEYS` dans `store.rs` ; instantané `migration_files_build_the_expected_schema` mis à jour ; test de montée d'une base remplie au numéro précédent (inventaires F5 compris) : les lignes existantes prennent `source = 'agent'`, `PRAGMA foreign_key_check` vide.
5. **Store** :
   - `add_inventory_key(site, pubkey, now) -> KeyOutcome` (refus si la clé égale `site_keys.pubkey` du site ou si `UNIQUE` saute : « clé déjà enregistrée pour un autre site ») ; `rotate_inventory_key` (remplace, `last_seq = 0`, `rotated_at`, mêmes refus) ; `remove_inventory_key` (garde l'inventaire) ; `inventory_key(site) -> Option<[u8; 32]>`.
   - `accept_inventory` reçoit la `Source` fixée par la signature : `seq` comparé à `site_keys.last_inventory_seq` (agent) ou `site_inventory_keys.last_seq` (ci), clé revérifiée inchangée dans la transaction IMMEDIATE ; débit, digest inchangé et plafond quotidien calculés sur les lignes `(site, source)`.
   - `last_inventory(site, source)`, `inventory_history(site, source)` ; `purge_inventory(now, declared: &[(site, source)])` : historique non dernier de plus de 30 jours, par (site, source) ; dernier d'une (site, source) non déclarée dont le `seen_at` a 30 jours.
   - `remove_key` : supprime aussi `site_inventory_keys` et **tous** les inventaires du site, et rend vrai si l'une des deux clés existait (un site `static` sans agent peut être retiré).
6. **Réception** (`inventory/receive.rs`, `serve.rs`) : porte avant le corps (F5) étendue : pour chaque source déclarée, sa clé est lue (`site_keys` pour `agent-php`, `site_inventory_keys` pour `ci`) par la connexion de lecture ; aucune → refus `InventoryClosed`/`UnknownSite` selon F5, **sans lire le corps**. Hors writer (`spawn_blocking`) : `command::key::verify(clé, DOMAIN_INVENTORY, &[corps], signature)` avec la clé d'agent puis la clé d'inventaire ; la première qui vérifie fixe la source ; aucune → `BadSignature`. Puis liste blanche F5 ; `source` d'enveloppe ≠ source fixée → `Schema("source")` (texte fixe). Journal d'acceptation : site, source, seq, composants, écartés, `complete`, nouveau/inchangé ; jamais un purl.
7. **CLI** (`main.rs`) : `vigie site inventory-key <id> add --pubkey <b64>`, `rotate --pubkey <b64>`, `remove [--yes]` ; refus (code 2, `ConfigError` ou erreur d'usage existante) si le site est absent de la configuration ou, pour `add` et `rotate`, si `ci` n'y est pas déclaré ; clé publique lue comme pour `site add` (32 octets base64, point valide). Messages : « clé d'inventaire de site-a enregistrée : elle ne signe que des inventaires ». `site remove` : confirmation inchangée, message adapté (« clés et inventaires de … retirés »). `site list` : colonne « inventaire » (`agent`, `ci`, `agent+ci`, `—`) selon les clés en base.
8. **tick** : `purge_inventory` reçoit les paires (site, source) déclarées.
9. **Tests** (`tests/inventory_ci_receive.rs`) : chaque cas du Test Scope, clés Ed25519 générées par le test, `FakeClock`, BOM de `tests/fixtures/inventory/` (site A fictif `generic`/`node`, composants `pkg:npm/…`, `pkg:composer/…`, `pkg:cargo/…` inventés ou publics) ; le cas « corps jamais lu » reprend le corps en flux sans fin de F5. Les tests F5 (`inventory_receive.rs`, `interop.rs`) passent sans modification de leurs assertions.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Matrice `SiteKind` × `Runtime` (dont absent) × {`agent-php`, `ci`, les deux} exhaustive : seul `agent-php` hors `php` est refusé ; l'ancienne forme `source = "agent-php"` donne `[AgentPhp]` |
| 3 | Enveloppe sans `source` → `Agent` ; `source` inconnue ou champ en plus → refus du document entier, raison fixe |
| 4 | Base au schéma F5 remplie (rapports, logs, clés, inventaires) montée sans perte ; `source` = `agent` partout ; instantané à jour |
| 5 | `UNIQUE (pubkey)` et l'égalité avec la clé d'agent sont refusés ; après `rotate`, `last_seq = 0` et l'inventaire reste ; après `site remove`, `site_inventory_keys` et `site_inventory` sont vides pour le site, `site_keys` absent ou non |
| 6 | Matrice clés × routes : clé d'inventaire refusée sur `/r/v1/report`, `/r/v1/logs`, `/r/v1/commands` ; clé de rapport refusée sur `/r/v1/inventory` d'un site `["ci"]` et pour une enveloppe `source: ci` ; journal sans aucun octet reçu (capture des logs, valeur `secret-xyz`) |
| 5-6 | Agent et CI au même site : chacun son `seq`, son débit, son plafond (24 nouveaux `ci` acceptés, 25e refusé, l'agent accepté le même jour) |
| 7 | `vigie site inventory-key` testé dans `tests/cli.rs` : add, rotate, remove, refus et codes de sortie |
| 9 | `cargo test --locked --all-targets`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --check` passent sous Linux et Windows ; commit `feat(inventory): source ci et clé d'inventaire au veilleur (#20)` |
