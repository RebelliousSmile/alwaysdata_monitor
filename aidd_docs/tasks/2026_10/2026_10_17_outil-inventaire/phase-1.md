---
status: pending
---

# Instruction: Veilleur : source `ci`, clé d'inventaire et réception par source

Prérequis : F5 (#19) fusionné. Avant la première tâche, relire les noms réels de F5 (`inventory/bom.rs`, `inventory/receive.rs`, `Store::accept_inventory`, `InventoryOutcome`, `InventorySource`, `capability::inventory_source`, numéro de la migration de F5) et ajuster cette phase ; tout écart va dans `decisions.md` en phase 4.

Dans cette phase, « site A static » désigne un site `kind = "generic"`, `runtime = "static"`.

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/00NN.sql        ✅ prochain numéro libre à la fusion (prévus : F2 0017, F3 0018, F4 0019, F7 0020) : site_inventory_keys ; site_inventory.source ; index (site, source, id)
    ├── config.example.toml        ✏️ [sites.inventory] sources = ["ci"] commenté, à côté de l'exemple agent-php
    ├── src/
    │   ├── config.rs              ✏️ InventorySource { AgentPhp, Ci } ; [sites.inventory] source (forme F5) ou sources (1 ou 2 distinctes), pas les deux ; agent-php seul exige runtime php
    │   ├── capability.rs          ✏️ inventory_sources(site) -> Vec<InventorySource> (match sans joker), remplace inventory_source ; Needs::InventorySource vrai si non vide
    │   ├── inventory/
    │   │   ├── mod.rs             ✏️ Source { Agent, Ci } (valeur stockée et champ d'enveloppe), conversion depuis InventorySource ; débit par source
    │   │   ├── bom.rs             ✏️ enveloppe : champ facultatif source ∈ {agent, ci}, absent = agent
    │   │   └── receive.rs         ✏️ porte : une source déclarée a sa clé ; signature essayée clé d'agent puis clé d'inventaire, la clé qui vérifie fixe la source ; source d'enveloppe égale
    │   ├── ingest.rs              ✏️ raison fixe « schéma : source » (aucun texte reçu)
    │   ├── store.rs               ✏️ pubkey_in_use (vérification unique) ; add_key en IMMEDIATE ; KeyOutcome::InUse ; add/rotate/remove_inventory_key, inventory_key ; accept_inventory par (site, source) ; last_inventory(site, source) ; purge_inventory par source ; remove_key purge inventory_keys et tout inventaire ; sites_with_keys ; MIGRATIONS, SCHEMA_INVENTORY_KEYS
    │   ├── command/pull.rs        ✏️ rotation : remplace sa requête « déjà celle d'un autre site » par pubkey_in_use
    │   ├── serve.rs               ✏️ lecture de la clé d'inventaire par la connexion de lecture, avant le corps
    │   ├── tick.rs                ✏️ purge_inventory avec les sources déclarées par site
    │   └── main.rs                ✏️ SiteAction::InventoryKey { id, action: add|rotate|remove, --pubkey } ; site add / rotate-key : refus InUse ; site remove sans clé d'agent ; site list : sites à clé d'inventaire seule compris
    └── tests/
        ├── inventory_ci_receive.rs ✅ parcours de réception par source, clés Rust, FakeClock
        ├── cli.rs                  ✏️ matrice d'unicité des clés publiques (add, rotate-key, inventory-key add/rotate)
        └── fixtures/inventory/     ✏️ BOM de référence source ci (site A static), variantes refusées
```

## Test Scope

```mermaid
journey
  section Happy path
    Site A static, sources = ["ci"], clé d'inventaire enregistrée => inventaire signé source ci 204, 1 inventaire source ci: 5: api
    Site B wordpress, sources = ["agent-php", "ci"] => inventaire agent 204 puis inventaire ci 204 : 2 derniers inventaires, un par source: 5: api
    Configuration F5 source = "agent-php" => chargée telle quelle, comportement F5 inchangé: 5: api
    Inventaire ci nouveau 3 min après le précédent => 204, 2 inventaires ci: 5: api
    Renvoi ci inchangé 300 s plus tard => seen_at avancé, pas de nouvelle ligne ; l'inventaire agent n'est pas touché: 5: api
    inventory-key rotate => last_seq à 0, ancienne clé refusée, nouvelle acceptée, inventaire gardé: 5: cli
    site list => site A (clé d'inventaire seule) listé avec « inventaire : ci »: 5: cli
  section Edge case
    Renvoi ci inchangé 100 s après le précédent => 404 (débit) ; nouvel inventaire agent 100 s après le précédent => 404 (débit F5): 1: api
    25e inventaire ci nouveau du jour UTC => 404 (InventoryQuota) ; l'agent du même site accepté: 1: api
    Clé d'inventaire sur /r/v1/report, /r/v1/logs, /r/v1/commands => 404 (signature): 1: api
    Site à sources = ["ci"] seul : inventaire signé par la clé de rapport => 404: 1: api
    Clé de rapport, enveloppe source ci => 404 (schéma : source) ; clé d'inventaire, source absente ou agent => 404: 1: api
    Site sans ci déclaré mais clé d'inventaire restée en base => 404 avant lecture du corps: 1: api
    sources = ["ci"] sans clé en base => 404 avant lecture du corps (corps de 10 Mio jamais lu): 1: api
    source et sources ensemble, sources vide, en double ou valeur inconnue => configuration refusée au chargement: 1: api
    sources = ["agent-php"] sur un site static => refusé ; sources = ["ci"] sur un generic sans runtime => accepté: 1: api
    inventory-key add sans ci déclaré => refus, code 2: 1: cli
    inventory-key add ou rotate avec la clé d'agent du site ou d'un autre site, ou la clé d'inventaire d'un autre site => InUse, code 2: 1: cli
    site add ou site rotate-key avec une clé d'inventaire (de ce site ou d'un autre) => InUse, code 2: 1: cli
    Commande rotate-key de l'agent vers une clé d'inventaire => refus « déjà enregistrée »: 1: api
    seq ci rejoué => 404 (replay) ; seq agent indépendant: 1: api
    site remove d'un site static sans clé d'agent => clé d'inventaire et inventaires purgés, plus aucune ligne: 1: cli
    ci retiré de la configuration depuis 31 j (FakeClock) => dernier inventaire ci purgé, inventaire agent gardé: 1: api
    Inventaire ci accepté => reports.last_valid_at et incidents inchangés: 1: api
```

## Tasks to do

1. **Configuration** (`config.rs`) : `InventorySource { AgentPhp, Ci }` (`rename_all = "kebab-case"`, `as_str`). `[sites.inventory]` (`deny_unknown_fields`) : `source: Option<InventorySource>` (forme F5) et `sources: Option<Vec<InventorySource>>` ; exactement un des deux ; `sources` de 1 ou 2 valeurs distinctes ; méthode `Site::inventory_sources() -> Vec<InventorySource>`. `AgentPhp` refusé au chargement hors runtime effectif `php` (règle F5, message inchangé) ; `Ci` admis pour tout runtime, `None` compris. `config.example.toml` : exemple commenté d'un site `generic`, `runtime = "static"`, `sources = ["ci"]` (`https://site-a.example.org`).
2. **Registre** (`capability.rs`) : `inventory_sources(site) -> Vec<InventorySource>` remplace `inventory_source(site)` de F5 ; tous ses appelants passent par lui ; `Needs::InventorySource` vrai dès que la liste n'est pas vide. Test exhaustif sur `SiteKind` × `Runtime` × sources. Aucun `Control` ajouté (F7). Le renommage est listé dans « Règles pour F7 » du plan.
3. **Source d'inventaire** (`inventory/mod.rs`, `inventory/bom.rs`) : `Source { Agent, Ci }` (`"agent"`, `"ci"`) ; l'enveloppe F5 gagne `source: Option<Source>` (absent = `Agent`), toujours `deny_unknown_fields`. Aucun autre champ ajouté au BOM.
4. **Migration 00NN** (prochain numéro libre à la fusion) :
   - `CREATE TABLE site_inventory_keys (site TEXT PRIMARY KEY, pubkey BLOB NOT NULL UNIQUE CHECK (length(pubkey) = 32), last_seq INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL, rotated_at INTEGER)` ;
   - `ALTER TABLE site_inventory ADD COLUMN source TEXT NOT NULL DEFAULT 'agent' CHECK (source IN ('agent','ci'))` ;
   - `CREATE INDEX site_inventory_site_source ON site_inventory (site, source, id)`.
   `SCHEMA_INVENTORY_KEYS` dans `store.rs` ; instantané `migration_files_build_the_expected_schema` mis à jour ; test de montée d'une base remplie au numéro précédent (inventaires F5 compris) : les lignes existantes prennent `source = 'agent'`, `PRAGMA foreign_key_check` vide.5. **Unicité des clés publiques** (`store.rs`, `command/pull.rs`) :
   - `pubkey_in_use(tx: &Transaction, pubkey: &[u8; 32], except: Option<(KeyTable, &str)>) -> Result<Option<(KeyTable, String)>>`, `KeyTable { Agent, Inventory }` : cherche la clé dans `site_keys` et `site_inventory_keys`, pour tout site, la ligne `except` exclue ;
   - appelée dans la transaction IMMEDIATE de `add_key` (qui passe en transaction : aujourd'hui `INSERT … ON CONFLICT (site) DO NOTHING` seul), `rotate_key` (l'actuel `Unchanged` reste rendu quand la clé est celle du site), `add_inventory_key`, `rotate_inventory_key` et `rotation` de `command/pull.rs` (qui garde son message « nouvelle clé déjà enregistrée », sa requête propre est retirée) ;
   - `KeyOutcome::InUse { table, site }` ; la CLI l'affiche sans révéler plus que « clé déjà enregistrée (agent ou inventaire d'un site) » et sort en code 2.
6. **Store, clés d'inventaire** : `add_inventory_key(site, pubkey, now) -> KeyOutcome` ; `rotate_inventory_key` (remplace, `last_seq = 0`, `rotated_at`) ; `remove_inventory_key` (garde l'inventaire) ; `inventory_key(site) -> Option<[u8; 32]>` ; `sites_with_keys() -> Vec<SiteKeys { site, agent: bool, inventory: bool }>` pour `site list`.
7. **Store, inventaires par source** :
   - `accept_inventory` reçoit la `Source` fixée par la signature : `seq` comparé à `site_keys.last_inventory_seq` (agent) ou `site_inventory_keys.last_seq` (ci), clé revérifiée inchangée dans la transaction IMMEDIATE ;
   - **débit** : source `agent`, règle F5 (240 s depuis le `seen_at` du dernier, pour tout envoi) ; source `ci`, 240 s **seulement si le digest est égal à celui du dernier** (renvoi inchangé), aucun délai pour un inventaire nouveau ;
   - plafond de 24 nouveaux par jour UTC, digest inchangé et dernier inventaire calculés sur les lignes `(site, source)` ;
   - `last_inventory(site, source)`, `inventory_history(site, source)` ; `purge_inventory(now, declared: &[(String, Source)])` : historique non dernier de plus de 30 jours, par (site, source) ; dernier d'une (site, source) non déclarée dont le `seen_at` a 30 jours ;
   - `remove_key` : supprime aussi `site_inventory_keys` et **tous** les inventaires du site, et rend vrai si l'une des deux clés existait.
8. **Réception** (`inventory/receive.rs`, `serve.rs`) : porte avant le corps (F5) étendue : pour chaque source déclarée, sa clé est lue (`site_keys` pour `agent-php`, `site_inventory_keys` pour `ci`) par la connexion de lecture ; aucune → refus avant lecture du corps, raison de F5. Hors writer (`spawn_blocking`) : `command::key::verify(clé, DOMAIN_INVENTORY, &[corps], signature)` avec la clé d'agent puis la clé d'inventaire ; la première qui vérifie fixe la source ; aucune → `BadSignature`. Puis liste blanche F5 ; `source` d'enveloppe ≠ source fixée → `Schema("source")` (texte fixe). Journal d'acceptation : site, source, seq, composants, écartés, `complete`, nouveau/inchangé ; jamais un purl.
9. **CLI** (`main.rs`) : `vigie site inventory-key <id> add --pubkey <b64>`, `rotate --pubkey <b64>`, `remove [--yes]` ; refus (code 2) si le site est absent de la configuration ou, pour `add` et `rotate`, si `ci` n'y est pas déclaré ; clé publique lue comme pour `site add` (32 octets base64, point valide) ; `InUse` → code 2. `site add` et `site rotate-key` rendent aussi `InUse`. `site remove` : confirmation inchangée, message adapté (« clés et inventaires de … retirés »), plus de refus « n'a pas de clé » quand seule la clé d'inventaire existe. `site list` : parcourt `sites_with_keys` (et non plus seulement `site_keys`), colonne « inventaire » (`agent`, `ci`, `agent+ci`, `—`).
10. **tick** : `purge_inventory` reçoit les paires (site, source) déclarées.
11. **Tests** :
    - `tests/inventory_ci_receive.rs` : chaque cas « api » du Test Scope, clés Ed25519 générées par le test, `FakeClock`, BOM de `tests/fixtures/inventory/` (site A static, composants inventés ou publics) ; « corps jamais lu » reprend le corps en flux sans fin de F5 ;
    - `tests/cli.rs` : matrice d'unicité, chaque commande d'écriture (`site add`, `site rotate-key`, `site inventory-key add`, `site inventory-key rotate`) essayée avec la clé d'agent et la clé d'inventaire du même site et d'un autre site ; commande `rotate-key` de l'agent vers une clé d'inventaire (test de `command/pull.rs`) ;
    - les tests F5 (`inventory_receive.rs`, `interop.rs`) passent sans modification de leurs assertions.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Matrice `SiteKind` × `Runtime` (dont absent) × {`agent-php`, `ci`, les deux} exhaustive : seul `agent-php` hors `php` est refusé ; l'ancienne forme `source = "agent-php"` donne `[AgentPhp]` ; `grep -rn "inventory_source(" vigie/src` ne trouve plus que `inventory_sources` |
| 3 | Enveloppe sans `source` → `Agent` ; `source` inconnue ou champ en plus → refus du document entier, raison fixe |
| 4 | Base au schéma F5 remplie (rapports, logs, clés, inventaires) montée sans perte ; `source` = `agent` partout ; instantané à jour |
| 5 | Matrice de `tests/cli.rs` : toute clé déjà présente dans l'une des deux tables, pour n'importe quel site, est refusée (code 2) par les quatre commandes et par la commande `rotate-key` ; la rotation d'un site vers sa propre clé rend « inchangée » ; deux `add` concurrents de la même clé (deux connexions) : un seul réussit |
| 6-7 | Après `rotate`, `last_seq = 0` et l'inventaire reste ; après `site remove`, `site_inventory_keys` et `site_inventory` sont vides pour le site ; inventaire `ci` nouveau à +180 s accepté, renvoi inchangé à +100 s refusé, agent à +100 s refusé ; 24 nouveaux `ci` acceptés, 25e refusé, l'agent accepté le même jour |
| 8 | Matrice clés × routes : clé d'inventaire refusée sur `/r/v1/report`, `/r/v1/logs`, `/r/v1/commands` ; clé de rapport refusée sur `/r/v1/inventory` d'un site `["ci"]` et pour une enveloppe `source: ci` ; journal sans aucun octet reçu (capture des logs, valeur `secret-xyz`) |
| 9 | `site list` affiche site A (clé d'inventaire seule) |
| 11 | `cargo test --locked --all-targets`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --check` passent sous Linux et Windows ; commit `feat(inventory): source ci et clé d'inventaire au veilleur (#20)` |
