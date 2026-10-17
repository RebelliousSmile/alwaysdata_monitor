---
status: pending
---

# Instruction: Envoi, état 0.5.0, interopérabilité, bout en bout et docs

## Architecture projection

```txt
.
├── CHANGELOG.md                               ✏️ ligne #19 après fusion, comme les issues précédentes
└── vigie/
    ├── agent/php/
    │   ├── vigie-agent.php                    ✏️ VERSION 0.5.0 ; DOMAIN_INVENTORY ; état inventory dans state.json et migration 0.2–0.4 ; send_inventory ; mode --inventory ; ordre du passage
    │   ├── config.example.json                ✏️ section inventory
    │   └── tests/
    │       ├── AgentTest.php                  ✏️ migration d'état, empreinte et 24 h, recul d'1 h après refus, repli de clé, fixtures suivies à jour
    │       └── make-interop-fixture.php       ✏️ régénère php-signed-report.json (0.5.0), écrit php-signed-inventory.json et inventory-vectors.json
    ├── tests/
    │   ├── fixtures/php-signed-report.json    ✏️ régénérée (agent 0.5.0)
    │   ├── fixtures/php-signed-inventory.json ✅ inventaire du site A fictif signé par sodium, graine fixe
    │   ├── fixtures/inventory-vectors.json    ✅ domaine et corps signés : valide, rapport rejoué, lot de logs rejoué, sans préfixe
    │   ├── interop.rs                         ✏️ 0.5.0 ; inventaire PHP accepté tel quel ; signatures croisées refusées
    │   ├── inventory_vectors.rs               ✅ vecteurs rejoués contre le routeur
    │   └── agent_e2e.rs                       ✏️ inventaire de bout en bout, renvoi inchangé, rapport rejoué sur /r/v1/inventory
    ├── config.example.toml                    ✏️ [sites.inventory] commenté
    ├── README.md                              ✏️ route POST /r/v1/inventory et sa limite de 512 Kio
    └── docs/
        ├── protocole-agent.md                 ✏️ /r/v1/inventory, enveloppe, sous-ensemble CycloneDX, domaine vigie-inventory-v1, effets, rotate-key / remove
        ├── agent-php.md                       ✏️ section Inventaire (config, kind prestashop, bornes, --inventory, état, retour à 0.4)
        ├── failles.md                         ✏️ purl révisés (core/core, casse npm), correspondances prestashop-module et wpackagist, limites V1
        └── decisions.md                       ✏️ section « Inventaire de l'agent (issue #19, F5) » datée
```

## Test Scope

```mermaid
journey
  section Happy path
    Passage de l'agent réel avec inventory activé => rapport 204, inventaire 204, last_inventory du site = composants attendus: 5: agent
    Second passage, rien de changé => aucun envoi d'inventaire: 5: agent
    sent_at de l'état reculé de 25 h => renvoi, toujours 1 inventaire en base, seen_at avancé: 5: agent
    Version d'une extension changée => 2 inventaires, le dernier porte la nouvelle version: 5: agent
  section Edge case
    Rapport signé par la clé de l'agent posté sur /r/v1/inventory => 404 ; le même sur /r/v1/report => 204: 1: agent
    Fixture php-signed-inventory.json sur /r/v1/report et /r/v1/logs => 404: 1: agent
    state.json 0.2/0.3 (5 clés) et 0.4 (6 clés) => migrés, séquences et htaccess_pending gardés: 1: agent
    inventory forgé dans state.json => État illisible, code 2, rapport envoyé quand même: 1: agent
    Veilleur qui refuse => code 1, failed_at écrit, pas de nouvel essai avant 1 h: 1: agent
    Rotation de clé non accusée => repli sur secret.key.new, 204: 1: agent
    state.lock tenu par un autre passage => inventaire sauté avec message, rapport envoyé: 1: agent
    Section inventory absente => aucun envoi, comportement 0.4 inchangé: 1: agent
    --inventory => enveloppe affichée, rien de signé ni d'envoyé, aucun état écrit: 1: agent
    Site sans [sites.inventory] côté veilleur => 404, code 1, recul d'1 h: 1: agent
```

## Tasks to do

1. **État** : `empty_state()` gagne `inventory => null` ; `STATE_KEYS_0_4` (6 clés) ; `load_state` migre un état à 5 clés (ajout de `htaccess_pending` et `inventory`) ou à 6 clés (ajout d'`inventory`), puis valide `valid_inventory_state()` (`null` ou exactement `seq`, `sha256`, `sent_at`, `failed_at`, entiers ≥ 0, `sha256` vide ou 64 hex minuscules). Message d'erreur inchangé (« État illisible … »).
2. **Envoi** (`send_inventory(Config, dir, now)`) : relevé (`collect_inventory`, phase 2) **hors verrou** ; puis `with_state` (message de verrou propre : « un autre passage tient le verrou : ce passage saute l'inventaire ») : relire l'état, décider (`sha256` différent ou `now − sent_at ≥ 86 400`, et `now − failed_at ≥ 3 600`), sinon rien ; `seq = max(seq + 1, heure en ms)` écrit avant l'envoi ; corps signé `DOMAIN_INVENTORY . $body` par `secret.key` puis, sur échec, `pending_new_secret()` (comme `send_log_batch`), `sodium_memzero` ; sur 204 : `sha256`, `sent_at = now`, `failed_at = 0` ; sinon `failed_at = now` et `SendError` (« inventaire refusé (raison dans journalctl -u vigie-serve) : nouvel essai dans 1 h »).
3. **Passage** : `main` appelle `send_inventory` après les commandes et avant les logs, si `inventory.enabled` ; `SendError` → code 1, `UsageError` → code 2, sans empêcher les logs. Mode `--inventory` (exclusif avec `--dry-run` et `--init`) : affiche l'enveloppe en JSON indenté, sans signer, envoyer ni écrire d'état. `VERSION = '0.5.0'`, en-tête du fichier et usage mis à jour.
4. **Fixtures signées et vecteurs** : `make-interop-fixture.php` régénère `php-signed-report.json` (seul `agent` change, à vérifier par le diff), écrit `php-signed-inventory.json` (fixture `wp-inventory`, graine `INTEROP_SEED_HEX`, `serialNumber` et heures fixes) et `inventory-vectors.json` (`domain`, `seed`, `now`, cas `valid` → 204, `report-replayed` (corps de rapport signé sans préfixe) → 404, `logs-replayed` (signé `vigie-logs-v1\n`) → 404, `unprefixed` (inventaire signé sans préfixe) → 404, `purls` : couples (écosystème, nom, version) → purl attendu, partagés par `purl()` PHP et `purl::canonical` Rust). `AgentTest.php` vérifie que les fichiers suivis sont égaux à ce que l'agent produit.
5. **Rust** : `interop.rs` attend `vigie-agent-php/0.5.0` ; nouveau test « l'ingestion accepte l'inventaire PHP tel quel » (site `kind = wordpress`, `[sites.inventory] source = "agent-php"`, composants attendus en base, `dropped = 0`) et refus croisés (inventaire sur `/r/v1/report` et `/r/v1/logs`, rapport sur `/r/v1/inventory`). `inventory_vectors.rs` rejoue chaque vecteur contre le routeur et chaque purl contre `purl::canonical`.
6. **Bout en bout** (`agent_e2e.rs`, PHP 8.1 épinglé en CI) : copie de `wp-inventory` en dossier temporaire, `config.toml` du veilleur avec `[sites.inventory]`, `config.json` avec `"inventory": {"enabled": true}` ; passage 1 → inventaire en base ; passage 2 → aucun nouvel envoi (`seen_at` inchangé) ; `sent_at` de `state.json` reculé de 25 h par le test → renvoi, 1 seule ligne ; version d'une extension modifiée → 2 lignes ; rapport signé avec `secret.key` de l'agent (lu par le test) rejeté sur `/r/v1/inventory`, accepté sur `/r/v1/report`. `FakeClock` avancée de 300 s entre passages (débit 240 s, rapport 60 s). Le test du verrou tenu (`a_held_lock_makes_the_agent_skip_without_waiting`) vérifie aussi le message d'inventaire sauté.
7. **Docs** :
   - `protocole-agent.md` : `POST /r/v1/inventory` dans la liste des routes, ligne « Inventaires » dans « Une clé par usage » (`vigie-inventory-v1\n`), enveloppe, sous-ensemble CycloneDX et liste blanche, purl, ordre des vérifications, débit, renvoi inchangé, conservation, « pas une preuve de vie », effets de `rotate-key` et `site remove`, limites V1 (licences, hachages, graphe).
   - `agent-php.md` : `kind` `prestashop`, section « Inventaire (agent 0.5.0, issue #19) » (configuration, sources lues par CMS, correspondances `prestashop-module` et `wpackagist`, bornes, `--inventory`, état dans `state.json`, 24 h et recul d'1 h, activation côté veilleur par `[sites.inventory]`) ; **retour à un agent 0.4** : son `load_state` refuse un état 0.5.0, retirer la clé `inventory` de `state.json` avant.
   - `failles.md` : purl révisés (`pkg:wordpress/core/core`, casse npm et cargo gardée, minuscules Composer seules), correspondances `prestashop-module` → `pkg:prestashop/module` et `wpackagist-*` → `pkg:wordpress`, limites (Bedrock complet, `installed.json`, lockfiles npm v1, yarn, pnpm).
   - `decisions.md` : section « Inventaire de l'agent (issue #19, F5) » datée du jour d'implémentation, reprenant les décisions du plan (dont l'écart `scope`/`vigie:scope`, l'absence de gzip, `[sites.inventory]`), et tout écart au plan constaté.
   - `README.md` : routes de `serve` et limite de 512 Kio de `/r/v1/inventory`.
8. **Pose sur le site A** (après fusion, hors CI) : déployer le veilleur d'abord, déclarer `[sites.inventory]`, puis l'agent 0.5.0, `--inventory` pour relire, activer `inventory` ; relevé consigné dans `hebergement.md` sans aucun nom de composant ni version réels (dépôt public : nombres seulement).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Test de migration étendu : un état 0.2/0.3 et un état 0.4 se chargent, se réécrivent avec les 7 clés de `empty_state()` dans l'ordre ; un `inventory` à clé en trop ou à `sha256` invalide est refusé |
| 2-3 | Un serveur de test (`php -S` ou veilleur réel) compte les envois : 1 au premier passage, 0 au second, 1 après recul de 25 h, 0 juste après un refus, 1 une heure plus tard (heure injectée) ; le rapport part même quand l'état est illisible |
| 4 | `git diff` de `php-signed-report.json` ne montre que `agent` et la signature ; `php run.php` échoue si une fixture suivie n'est pas à jour |
| 5 | `cargo test --test interop --test inventory_vectors` passe ; les purl des vecteurs sont identiques des deux côtés |
| 6 | `VIGIE_E2E_PHP=… cargo test --test agent_e2e -- --ignored` passe en CI (PHP 8.1 épinglé) ; chaque étape du Test Scope y est une assertion |
| 7 | Les docs ne contiennent aucun domaine, compte ou composant réel ; `grep -rn "core/wordpress" vigie/docs` ne trouve plus que la mention historique éventuelle de la décision révisée |
| 8 | `vigie` en ligne accepte l'inventaire du site A (journal « inventaire accepté … nouveau ») ; l'incident de silence et `reports.last_valid_at` ne bougent pas du fait de l'inventaire |
