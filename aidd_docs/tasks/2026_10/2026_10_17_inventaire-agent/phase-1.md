---
status: pending
---

# Instruction: Point d'entrée /r/v1/inventory, schéma strict et stockage

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/0016.sql        ✅ (prochain numéro libre : F1 #15 prend 0015) last_inventory_seq dans site_keys ; site_inventory ; site_inventory_components (FK ON DELETE CASCADE, index sur purl sans version)
    ├── src/
    │   ├── command/key.rs         ✏️ DOMAIN_INVENTORY = b"vigie-inventory-v1\n" ; test des domaines étendu
    │   ├── config.rs              ✏️ [sites.inventory] source = "agent-php" (enum fermée InventorySource), refusée hors runtime effectif php
    │   ├── capability.rs          ✏️ Ecosystem { Wordpress, Prestashop, Composer, Npm } ; inventory_ecosystems(kind) et inventory_source(site) (match sans joker)
    │   ├── inventory/
    │   │   ├── mod.rs             ✅ types partagés : Component, Inventory, Scope Vigie, MAX_COMPONENTS, MAX_INVENTORY_BYTES, RETENTION, MIN_INTERVAL
    │   │   ├── purl.rs            ✅ purl canonique (encodage pourcentage, minuscules pour composer seulement) et analyse bornée ; réutilisé par F6 et F7 (ou celui de F1 s'il existe déjà)
    │   │   ├── bom.rs             ✅ sous-ensemble CycloneDX 1.6/1.7, serde deny_unknown_fields, validation bornée, liste canonique et digest
    │   │   └── receive.rs         ✅ vérifications dans l'ordre, refus 404 avec raison, appel à Store::accept_inventory
    │   ├── ingest.rs              ✏️ Reason : InventoryClosed (site sans [sites.inventory] source), TooSoon réutilisé
    │   ├── lib.rs                 ✏️ pub mod inventory
    │   ├── store.rs               ✏️ accept_inventory, last_inventory, inventory_history, purge_inventory ; remove_key purge, rotate_key remet last_inventory_seq à 0 ; MIGRATIONS
    │   ├── serve.rs               ✏️ route POST /r/v1/inventory ; read_agent_body(limit) paramétré (64 Ko rapport/logs/retrait, 512 Kio inventaire)
    │   └── tick.rs                ✏️ purge de l'historique d'inventaire à côté de purge_logs
    └── tests/
        ├── inventory_receive.rs   ✅ parcours de réception, signés par une clé Rust
        └── fixtures/inventory/    ✅ BOM de référence (site-a WordPress, site-b PrestaShop), un par cas hostile côté veilleur
```

## Test Scope

```mermaid
journey
  section Happy path
    Inventaire signé de 12 composants (site-a wordpress) => 204, 1 inventaire, 12 composants, purl relisibles: 5: api
    Même contenu renvoyé 300 s plus tard avec un seq plus grand => 204, toujours 1 ligne, seen_at avancé: 5: api
    Une version change => 204, 2 inventaires, last_inventory rend le nouveau: 5: api
  section Edge case
    Rapport signé envoyé sur /r/v1/inventory => 404 (signature): 1: api
    Inventaire signé envoyé sur /r/v1/report et /r/v1/logs => 404 (signature): 1: api
    Inventaire signé sans préfixe de domaine => 404 (signature): 1: api
    seq rejoué ou plus petit => 404 (replay): 1: api
    Deux inventaires à moins de 240 s => second 404 (débit): 1: api
    sent_at à 301 s => 404 (horloge): 1: api
    Champ inconnu dans l'enveloppe, dans bom, dans metadata ou dans un composant => 404 (schéma): 1: api
    Composant portant authors, supplier ou licenses, ou propriété hors vigie:* => 404 (schéma): 1: api
    pkg:npm/%40Scope/Nom gardé tel quel ; pkg:composer/Vendor/Nom => écarté (non canonique): 1: api
    specVersion 1.5 ou 1.8 => 404 ; 1.6 => 204: 1: api
    metadata.component.name différent du site => 404 (schéma): 1: api
    2 001 composants => 404 (schéma): 1: api
    Corps de 512 Kio + 1 octet => 404 (taille): 1: api
    purl incohérent avec name ou version => composant écarté, dropped compté, 204: 1: api
    Composant pkg:prestashop sur un site wordpress, pkg:cargo, type inconnu => écartés et comptés: 1: api
    Doublon (purl, vigie:path) => un seul gardé, l'autre compté: 1: api
    Version vide => composant gardé, purl sans @: 1: api
    Site sans [sites.inventory] source, ou sans clé => 404: 1: api
    [sites.inventory] sur un site sans runtime php => configuration refusée au chargement: 1: api
    Inventaire accepté => reports.last_valid_at et incidents inchangés: 1: api
    site remove => plus aucune ligne d'inventaire ; rotate-key => seq remis à 0, inventaire gardé: 1: api
    FakeClock à J+31 => historique purgé, dernier inventaire gardé: 1: api
```

## Tasks to do

1. **Domaine** : `DOMAIN_INVENTORY` dans `command/key.rs`, documenté dans l'en-tête ; le test `signatures_are_bound_to_their_domain` vérifie qu'une signature `vigie-inventory-v1\n` ne vaut ni pour `vigie-logs-v1\n` ni sans préfixe, et inversement.
2. **Configuration et registre** : `[sites.inventory]` dans `config.rs` (`deny_unknown_fields`, `source` ∈ {`agent-php`}), refusée au chargement si le runtime effectif n'est pas `php` ; `config.example.toml` commenté. `capability.rs` : `Ecosystem` fermé ; `inventory_ecosystems(SiteKind) -> &'static [Ecosystem]` (`Wordpress` → wordpress, composer, npm ; `Prestashop` → prestashop, composer, npm ; `Generic` → composer, npm) ; `inventory_source(site) -> Option<InventorySource>` (déclaration explicite, seule porte de `/r/v1/inventory`, et future condition d'existence `Needs::InventorySource` du contrôle `vulns` de F7). Aucun `Control` ajouté ; en-tête du module complété.
3. **purl** (`inventory/purl.rs`) : `canonical(ecosystem, name, version) -> Option<String>` (Composer `vendor/nom` en minuscules, deux segments ; npm `nom` ou `@scope/nom`, `@` encodé `%40`, **casse gardée** ; WordPress `plugin|theme/<slug>` tel quel, `core/core` ; PrestaShop `module/<nom>`, `core/prestashop` ; segments et version encodés hors `[A-Za-z0-9._~-]`) ; `parse(purl) -> Option<Parsed>` borné à 512 octets, sans qualificatifs ni sous-chemin en V1. Tests unitaires sur les exemples de `failles.md` (`pkg:npm/%40scope/nom@1.0.0`, `pkg:wordpress/core/core@6.6.2`, `+` → `%2B`, majuscules Composer normalisées, majuscules npm gardées, version vide sans `@`).
4. **Schéma** (`inventory/bom.rs`, `receive.rs`) : enveloppe `v`=1, `type`=`inventory`, `site` = `X-Vigie-Site`, `seq` ≥ 1, `sent_at`, `agent` (1 à 64 imprimables), `complete` (booléen), `skipped` (0 à 100 000), `bom`. BOM : `bomFormat` = `CycloneDX`, `specVersion` ∈ {`1.6`, `1.7`}, `serialNumber` motif `urn:uuid:` + UUID minuscule, `metadata` = `{timestamp, component}` (timestamp RFC 3339 UTC lu par `jiff`, à ±30 jours de `sent_at` ; component = `{"type":"application","name":<site>}`), `components` 0 à 2 000 ; composant : `type` ∈ {`application`, `library`}, `name` 1 à 214 imprimables, `version` 0 à 64 octets `[0-9A-Za-z.+_~-]`, `purl` ≤ 512, `scope` ∈ {`required`, `excluded`}, aucun autre champ (`authors`, `supplier`, `licenses`, `hashes`, `bom-ref`… refusent tout le document), `properties` : `vigie:path` (relatif, ≤ 200, segments sans `.`/`..`, imprimable), `vigie:scope` ∈ {`required`, `dev`, `mu`}, `vigie:parent` facultatif (slug), aucune autre, aucune en double. Cohérence : `scope` = `excluded` ⇔ `vigie:scope` = `dev` ; `mu` seulement pour `pkg:wordpress/plugin` ; `vigie:parent` seulement pour `pkg:wordpress/theme` ; `type` = `application` ⇔ noyau. Un défaut d'enveloppe ou de BOM refuse tout ; un défaut de composant (purl non canonique, écosystème non admis, incohérence, doublon `(purl, path)`) l'écarte et le compte dans `dropped`.
5. **Liste canonique et digest** : composants gardés triés par `(purl, path)`, sérialisés en JSON compact par le veilleur (ses propres structures, pas les octets reçus), SHA-256 → `digest`.
6. **Migration 0016** (renuméroter si F1 a pris 0015 et un autre plan 0016) : `ALTER TABLE site_keys ADD COLUMN last_inventory_seq INTEGER NOT NULL DEFAULT 0` ; `site_inventory` (`id INTEGER PRIMARY KEY AUTOINCREMENT`, `site`, `digest BLOB NOT NULL CHECK (length(digest) = 32)`, `spec_version CHECK IN ('1.6','1.7')`, `serial`, `generated_at`, `agent`, `complete CHECK IN (0,1)`, `skipped`, `dropped`, `components`, `received_at`, `seen_at`), index `(site, id)` ; `site_inventory_components` (`inventory REFERENCES site_inventory(id) ON DELETE CASCADE`, `ecosystem CHECK IN ('wordpress','prestashop','composer','npm')`, `base` = purl sans version, `purl`, `name`, `version`, `scope CHECK IN ('required','dev','mu')`, `type CHECK IN ('application','library')`, `path`, `parent`, `PRIMARY KEY (inventory, purl, path)`), index sur `base`. `migration_files_build_the_expected_schema` et un test de montée d'une base v14 (et v15 si F1 a fusionné) remplie sans perte.
7. **Store** : `accept_inventory(&InventoryDoc, now) -> InventoryOutcome { Accepted { new: bool, dropped }, UnknownSite, Replay { last_seq }, TooSoon { seen_at } }` en IMMEDIATE (clé inchangée, `seq` > `last_inventory_seq`, débit 240 s sur le `seen_at` du dernier, puis digest égal → `seen_at` et `seq` seuls, sinon insertion de l'inventaire et des composants) ; `last_inventory(site)` (en-tête + composants triés) ; `inventory_history(site)` (en-têtes) ; `purge_inventory(now)` (inventaires non derniers de leur site dont `seen_at` < now − 30 j, composants par cascade). `remove_key` purge `site_inventory` du site ; `rotate_key` remet `last_inventory_seq` à 0. Rien ne touche `reports`.
8. **serve** : route `POST /r/v1/inventory` (`fallback(not_found)`), `read_agent_body(body, announced, limit)` avec `MAX_INVENTORY_BYTES = 512 * 1024` et le même délai de 10 s ; handler calqué sur `logs_handler` (writer, `spawn_blocking`) ; journal à l'acceptation : site, seq, composants, écartés, `complete`, « nouveau » ou « inchangé » — jamais un nom de composant ni une version (l'inventaire ne sort pas de la base, même dans le journal). `other_routes_and_methods_are_a_silent_404` étendu (`GET /r/v1/inventory` → 404).
9. **tick** : `purge_inventory` appelé avec `purge_logs`, erreurs journalisées sans arrêter le passage.
10. `tests/inventory_receive.rs` : chaque cas du Test Scope, avec une clé Rust (`SigningKey::from_bytes`), une `FakeClock` et des BOM de `tests/fixtures/inventory/`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Une signature d'un domaine ne vérifie aucun des quatre autres |
| 2 | La matrice CMS × écosystème est un test exhaustif sur `SiteKind` ; `[sites.inventory]` sur un `generic` sans runtime ou un `static` fait échouer le chargement ; sans la section, tout inventaire est refusé |
| 3 | Tout purl produit par `canonical` se relit par `parse` à l'identique ; les exemples de `failles.md` donnent le purl écrit dans la doc |
| 4-5 | Chaque cas du Test Scope est un test ; le digest est le même pour deux BOM aux composants permutés et aux `serialNumber`/`timestamp` différents |
| 6 | Base v14 remplie (rapports, logs, clés) montée en v16 sans perte ; `PRAGMA foreign_key_check` vide |
| 7-9 | Renvoi inchangé : `SELECT count(*) FROM site_inventory` reste 1 ; après `site remove`, `site_inventory` et `site_inventory_components` sont vides pour le site ; `reports.last_valid_at` inchangé après un inventaire ; le journal d'une acceptation ne contient aucun purl |
| 10 | `cargo test`, `cargo clippy -- -D warnings` et `cargo fmt --check` passent |
