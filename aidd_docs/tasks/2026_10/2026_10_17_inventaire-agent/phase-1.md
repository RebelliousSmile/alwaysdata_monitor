---
status: done
---

# Instruction: Point d'entrée /r/v1/inventory, liste blanche et stockage

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/0016.sql        ✅ (prochain numéro libre : F1 #15 prend 0015) last_inventory_seq dans site_keys ; site_inventory ; site_inventory_components (FK ON DELETE CASCADE, index sur base)
    ├── config.example.toml        ✏️ [sites.inventory] commenté
    ├── src/
    │   ├── command/key.rs         ✏️ DOMAIN_INVENTORY = b"vigie-inventory-v1\n" ; test des six domaines et d'une signature sans préfixe
    │   ├── config.rs              ✏️ [sites.inventory] source = "agent-php" (enum fermée InventorySource), refusée hors runtime effectif php
    │   ├── capability.rs          ✏️ inventory_ecosystems(kind) et inventory_source(site) (match sans joker), en-tête complété
    │   ├── vulns/purl.rs          ➖ module de F1, importé tel quel (aucune seconde implémentation)
    │   ├── inventory/
    │   │   ├── mod.rs             ✅ Component, Inventory, Scope Vigie, MAX_COMPONENTS, MAX_INVENTORY_BYTES, RETENTION, MIN_INTERVAL, MAX_NEW_PER_DAY
    │   │   ├── bom.rs             ✅ liste blanche CycloneDX 1.6/1.7 (serde deny_unknown_fields), validation bornée, liste canonique et digest
    │   │   └── receive.rs         ✅ porte avant le corps, vérifications hors writer, appel à Store::accept_inventory, raisons fixes
    │   ├── ingest.rs              ✏️ Reason : InventoryClosed, InventoryQuota ; TooSoon réutilisé ; Schema avec texte fixe seulement pour l'inventaire
    │   ├── lib.rs                 ✏️ pub mod inventory
    │   ├── store.rs               ✏️ accept_inventory, last_inventory, inventory_history, inventory_heads, inventory_components, purge_inventory ; InventoryHead, InventoryComponentRow ; remove_key et rotate_key ; MIGRATIONS
    │   ├── serve.rs               ✏️ route POST /r/v1/inventory ; read_agent_body(limit) paramétré (64 Ko ailleurs, 512 Kio ici)
    │   └── tick.rs                ✏️ purge de l'inventaire à côté de purge_logs, avec la configuration
    └── tests/
        ├── inventory_receive.rs   ✅ parcours de réception, signés par une clé Rust
        └── fixtures/inventory/    ✅ BOM de référence fictifs (site-a WordPress, site-b PrestaShop) et variantes refusées
```

## Test Scope

```mermaid
journey
  section Happy path
    Inventaire signé de 12 composants (site-a wordpress, [sites.inventory]) => 204, 1 inventaire, 12 composants relisibles: 5: api
    Même contenu renvoyé 300 s plus tard avec un seq plus grand => 204, toujours 1 ligne, seen_at avancé: 5: api
    Une version change => 204, 2 inventaires, last_inventory rend le nouveau: 5: api
    inventory_history(site-a) => les 2 InventoryHead, plus récent d'abord, id, complete, seen_at, received_at, agent remplis: 5: api
    inventory_heads() sur site-a (2 inventaires), site-b (1) et un site sans inventaire => 2 têtes, le dernier de chaque site, triées par site, sans lire site_inventory_components: 5: api
    inventory_components(id, 0, 500) sur 1 201 composants, puis depuis le dernier rowid => lots de 500, 500, 201 dans l'ordre (purl, path), ni doublon ni manque, puis vide: 5: api
    Composant à version vide => version None ; path = vigie:path reçu ; inventaire inconnu => vide: 1: api
    Lectures sur Store::open_read => mêmes résultats, aucune écriture: 1: api
  section Edge case
    Site sans [sites.inventory], inconnu ou sans clé => 404 sans lire le corps (corps annoncé de 10 Mio jamais lu): 1: api
    [sites.inventory] sur un site sans runtime php => configuration refusée au chargement: 1: api
    Rapport signé envoyé sur /r/v1/inventory => 404 (signature): 1: api
    Inventaire signé envoyé sur /r/v1/report et /r/v1/logs => 404 (signature): 1: api
    Inventaire signé sans préfixe ou sous un autre des six domaines => 404: 1: api
    seq rejoué ou plus petit => 404 (replay): 1: api
    Deux inventaires à moins de 240 s => second 404 (débit): 1: api
    25e inventaire nouveau du jour UTC => 404, raison InventoryQuota au journal ; un renvoi inchangé reste accepté: 1: api
    sent_at à 301 s => 404 (horloge): 1: api
    Champ hors liste blanche (authors, supplier, licenses, hashes, bom-ref) ou propriété hors vigie:* listées => 404 (schéma), document entier refusé: 1: api
    JSON invalide ou champ inconnu => journal à raison fixe, sans texte serde ni octet reçu: 1: api
    specVersion 1.5 ou 1.8 => 404 ; 1.6 => 204: 1: api
    metadata.component.name différent du site => 404: 1: api
    2 001 composants => 404 ; corps de 512 Kio + 1 octet => 404 (taille): 1: api
    purl non canonique (composer à majuscules, version à ~, module PS à point) => écarté, dropped compté, 204: 1: api
    pkg:npm/%40Scope/Nom => gardé tel quel: 1: api
    pkg:prestashop sur un site wordpress => écarté et compté ; pkg:cargo sur tout site => gardé: 1: api
    Doublon (purl, vigie:path) => un seul gardé, l'autre compté: 1: api
    Version vide => composant gardé, purl sans @: 1: api
    Inventaire accepté => reports.last_valid_at et incidents inchangés: 1: api
    site remove => plus aucune ligne d'inventaire ; rotate-key => seq remis à 0, inventaire gardé: 1: api
    FakeClock à J+31 => historique purgé, dernier gardé ; site retiré de [sites.inventory] depuis 31 j => dernier purgé aussi: 1: api
```

## Tasks to do

1. **Domaine** : `DOMAIN_INVENTORY` dans `command/key.rs`, documenté en tête. Test `signatures_are_bound_to_their_domain` étendu à la matrice des six domaines (`pull`, `logs`, `commands`, `audit`, `rotate`, `inventory`) et à une signature sans préfixe (celle d'un rapport) : chacune ne vérifie que son propre domaine.
2. **Configuration et registre** : `[sites.inventory]` dans `config.rs` (`deny_unknown_fields`, `source` ∈ {`agent-php`}), refusée au chargement si le runtime effectif n'est pas `php`. `capability.rs` : `inventory_ecosystems(SiteKind)` sur l'enum d'écosystème de `vulns::purl` (`Wordpress` → wordpress, composer, npm, cargo ; `Prestashop` → prestashop, composer, npm, cargo ; `Generic` → composer, npm, cargo) ; `inventory_source(site) -> Option<InventorySource>`, seule porte de `/r/v1/inventory` et future condition `Needs::InventorySource` du contrôle `vulns` (F7). Aucun `Control` ajouté.
3. **purl** : aucun code nouveau. `vulns::purl` de F1 fournit purl canonique et analyse selon la grammaire commune de `failles.md` ; si une fonction manque à F5 (calcul du purl sans version, par exemple), elle s'ajoute **dans ce module**, avec ses vecteurs dans `purl.json`.
4. **Liste blanche** (`inventory/bom.rs`) : enveloppe `v`=1, `type`=`inventory`, `site` = `X-Vigie-Site`, `seq` ≥ 1, `sent_at`, `agent` (1 à 64 imprimables), `complete`, `skipped` (0 à 100 000), `bom`. BOM : `bomFormat`, `specVersion` ∈ {`1.6`, `1.7`}, `serialNumber` (`urn:uuid:` + UUID minuscule), `metadata` = `{timestamp, component}` (RFC 3339 UTC lu par `jiff`, à ±30 jours de `sent_at` ; `component` = `{"type":"application","name":<site>}`), `components` 0 à 2 000 ; composant = `{type, name, version, purl, scope, properties}` exactement (`type` ∈ {`application`, `library`}, `name` 1 à 214 imprimables, `version` vide ou selon la grammaire, `purl` ≤ 512, `scope` ∈ {`required`, `excluded`}) ; `properties` : `vigie:path` (relatif, ≤ 200, sans `.`/`..`), `vigie:scope` ∈ {`required`, `dev`, `mu`}, `vigie:parent` (slug), `vigie:config-version` (version) ; toute autre clé ou propriété, ou une propriété en double, refuse le document. Cohérences : `excluded` ⇔ `dev` ; `mu` seulement pour `pkg:wordpress/plugin` ; `vigie:parent` seulement pour un thème ; `vigie:config-version` seulement pour un module PrestaShop ; `application` ⇔ noyau. Un défaut d'enveloppe ou de BOM refuse tout ; un défaut de composant (purl non canonique, nom hors grammaire, écosystème non admis, incohérence, doublon `(purl, path)`) l'écarte et le compte (`dropped`).
5. **Raisons sans écho** : chaque refus de schéma est une raison fixe (`json`, `champ hors liste blanche`, `specVersion`, `trop de composants`…) ; l'erreur serde n'est jamais formatée dans le journal, ni aucun nom, version ou purl reçu.
6. **Liste canonique et digest** : composants gardés triés par `(purl, path)`, sérialisés par le veilleur depuis ses propres structures, SHA-256 → `digest`.
7. **Migration 0016** (renuméroter au prochain numéro libre) : `ALTER TABLE site_keys ADD COLUMN last_inventory_seq INTEGER NOT NULL DEFAULT 0` ; `site_inventory` (`id INTEGER PRIMARY KEY AUTOINCREMENT`, `site`, `digest BLOB NOT NULL CHECK (length(digest) = 32)`, `spec_version CHECK IN ('1.6','1.7')`, `serial`, `generated_at`, `agent`, `complete CHECK IN (0,1)`, `skipped`, `dropped`, `components`, `received_at`, `seen_at`), index `(site, id)` et `(site, received_at)` ; `site_inventory_components` (`inventory REFERENCES site_inventory(id) ON DELETE CASCADE`, `ecosystem CHECK IN ('wordpress','prestashop','composer','npm','cargo')`, `base`, `purl`, `name`, `version`, `scope CHECK IN ('required','dev','mu')`, `type CHECK IN ('application','library')`, `path`, `parent`, `config_version`, `PRIMARY KEY (inventory, purl, path)`, table à `rowid`, pas `WITHOUT ROWID`), index sur `base` et sur `inventory` (le `rowid` implicite de cet index sert le curseur de `inventory_components`) ; composants insérés dans l'ordre canonique `(purl, path)`. `migration_files_build_the_expected_schema` et un test de montée d'une base remplie au numéro précédent sans perte.
8. **Store** : `accept_inventory(&InventoryDoc, now) -> InventoryOutcome { Accepted { new, dropped }, UnknownSite, Replay { last_seq }, TooSoon { seen_at }, Quota { new_today } }` en IMMEDIATE : clé inchangée, `seq` > `last_inventory_seq`, débit 240 s sur le `seen_at` du dernier, digest égal → `seen_at` et `seq` seuls ; sinon plafond (24 inventaires de `received_at` dans le jour UTC de `now`) puis insertion. Lectures pour F7 (#21), toutes valables sur `Store::open_read` : `InventoryHead { site: String, id: i64, complete: bool, seen_at: i64, received_at: i64, agent: String }` ; `last_inventory(site) -> Option<InventoryHead>` ; `inventory_history(site) -> Vec<InventoryHead>` (id décroissant) ; `inventory_heads() -> Vec<InventoryHead>` (dernier inventaire de chaque site, `max(id)` groupé par site, une requête légère sur `site_inventory` seule, triée par site) ; `inventory_components(inventory_id: i64, after_rowid: i64, limit: usize) -> Vec<InventoryComponentRow { rowid: i64, ecosystem, base, purl, name, version: Option<String>, scope, path }>` (`WHERE inventory = ? AND rowid > ? ORDER BY rowid LIMIT ?`, 0 pour le premier lot ; `ecosystem` sur l'enum de `vulns::purl`, `scope` Vigie, `path` = `vigie:path`, version vide → `None`). `purge_inventory(now, sites_declared)` (non derniers dont `seen_at` < now − 30 j ; tous ceux d'un site hors de `sites_declared` dont le dernier `seen_at` < now − 30 j). `remove_key` purge `site_inventory` du site ; `rotate_key` remet `last_inventory_seq` à 0. Rien ne touche `reports`.
9. **serve** : route `POST /r/v1/inventory` (`fallback(not_found)`) ; handler : en-têtes et porte (`inventory_source`, clé en base par une connexion de lecture) **avant** `read_agent_body(body, announced, MAX_INVENTORY_BYTES)` (512 Kio, 10 s) ; signature, liste blanche, purl et digest dans `spawn_blocking` **hors** de `writer.write` ; puis `writer.write(accept_inventory)`. Journal d'acceptation : site, seq, nombre de composants, écartés, `complete`, « nouveau » ou « inchangé ». `other_routes_and_methods_are_a_silent_404` étendu (`GET /r/v1/inventory`).
10. **tick** : `purge_inventory(now, sites déclarés)` avec `purge_logs`, erreurs journalisées sans arrêter le passage.
11. `tests/inventory_receive.rs` : chaque cas du Test Scope, clé Rust, `FakeClock`, BOM de `tests/fixtures/inventory/` ; le cas « corps jamais lu » vérifie le refus sur un corps en flux qui ne se termine pas.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Matrice 7 × 7 (six domaines + sans préfixe) : seule la diagonale vérifie |
| 2 | Matrice CMS × écosystème exhaustive sur `SiteKind` ; `[sites.inventory]` sur un `generic` sans runtime ou un `static` fait échouer le chargement |
| 3 | `grep -rn "fn canonical" vigie/src` ne trouve qu'une définition, dans `vulns/purl.rs` |
| 4-6 | Chaque cas du Test Scope est un test ; digest identique pour deux BOM aux composants permutés et aux `serialNumber`/`timestamp` différents |
| 5 | Un refus de schéma provoqué par une valeur `"secret-xyz"` laisse un journal sans `secret-xyz` (capture des logs du test) |
| 7 | Base remplie (rapports, logs, clés) montée sans perte ; `PRAGMA foreign_key_check` vide |
| 8-10 | `inventory_heads` ne lit pas `site_inventory_components` (`EXPLAIN QUERY PLAN`) ; `inventory_components` lu par lots rend exactement la liste canonique `(purl, path)` ; renvoi inchangé : `count(*)` de `site_inventory` reste 1 ; 24 nouveaux acceptés puis le 25e refusé le même jour UTC et accepté le lendemain ; après `site remove`, les deux tables sont vides pour le site ; `reports.last_valid_at` inchangé ; le journal d'une acceptation ne contient aucun purl |
| 11 | `cargo test`, `cargo clippy -- -D warnings` et `cargo fmt --check` passent |
