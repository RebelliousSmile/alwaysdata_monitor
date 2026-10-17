---
status: done
---

# Instruction: Envoi, état 0.5.0, interopérabilité, bout en bout et docs

## Architecture projection

```txt
.
├── CHANGELOG.md                               ✏️ ligne #19 après fusion, comme les issues précédentes
└── vigie/
    ├── agent/php/
    │   ├── vigie-agent.php                    ✏️ VERSION 0.5.0 ; DOMAIN_INVENTORY ; inventory.json sous inventory.lock ; relevé économe ; send_inventory ; mode --inventory ; ordre du passage
    │   ├── config.example.json                ✏️ section inventory
    │   └── tests/
    │       ├── AgentTest.php                  ✏️ état, relevé économe, empreinte et 24 h, recul d'1 h, repli de clé, verrou, fixtures suivies à jour
    │       └── make-interop-fixture.php       ✏️ régénère php-signed-report.json (0.5.0), écrit php-signed-inventory.json et inventory-vectors.json
    ├── tests/
    │   ├── fixtures/php-signed-report.json    ✏️ régénérée (agent 0.5.0)
    │   ├── fixtures/php-signed-inventory.json ✅ inventaire du site A fictif signé par sodium, graine fixe
    │   ├── fixtures/inventory-vectors.json    ✅ domaine et corps signés : valide, rapport, retrait et lot de logs rejoués, sans préfixe
    │   ├── interop.rs                         ✏️ 0.5.0 ; inventaire PHP accepté tel quel (dropped = 0) ; signatures croisées refusées
    │   ├── inventory_vectors.rs               ✅ vecteurs rejoués contre le routeur
    │   └── agent_e2e.rs                       ✏️ inventaire de bout en bout, renvoi inchangé, rapport rejoué sur /r/v1/inventory, verrou tenu
    ├── README.md                              ✏️ route POST /r/v1/inventory et sa limite de 512 Kio
    └── docs/
        ├── protocole-agent.md                 ✏️ /r/v1/inventory, enveloppe, liste blanche, domaine, vérifications, débit, plafond, effets, rotate-key / remove
        ├── agent-php.md                       ✏️ kind prestashop, section Inventaire, retour à 0.4
        ├── failles.md                         ✏️ côté extension : règles de doublons, complete, limites V1
        └── decisions.md                       ✏️ section « Inventaire de l'agent (issue #19, F5) » datée
```

## Test Scope

```mermaid
journey
  section Happy path
    Passage de l'agent réel avec inventory activé => rapport 204, inventaire 204, last_inventory du site = composants attendus: 5: agent
    Second passage sans avance d'horloge, rien de changé => rapport refusé par le débit (code 1), ni relevé complet ni envoi d'inventaire, seen_at inchangé: 5: agent
    sent_at d'inventory.json reculé de 25 h => renvoi, toujours 1 inventaire en base, seen_at avancé: 5: agent
    En-tête Version d'une extension modifié => relevé (mtime), 2 inventaires, le dernier porte la nouvelle version: 5: agent
  section Edge case
    Rapport signé par la clé de l'agent posté sur /r/v1/inventory => 404 ; le même sur /r/v1/report => 204: 1: agent
    php-signed-inventory.json sur /r/v1/report et /r/v1/logs => 404: 1: agent
    inventory.json forgé ou ouvert à d'autres => code 2, inventaire arrêté, rapport envoyé: 1: agent
    state.json d'un agent 0.4 => lu tel quel, jamais réécrit par l'inventaire: 1: agent
    Veilleur qui refuse => code 1, failed_at écrit, pas de nouvel essai avant 1 h: 1: agent
    Rotation de clé non accusée => repli sur secret.key.new, 204: 1: agent
    inventory.lock tenu par un autre passage => inventaire sauté avec message, rapport et commandes faits: 1: agent
    Section inventory absente => aucun relevé, aucun fichier inventory.*: 1: agent
    --inventory => enveloppe affichée, rien de signé ni d'envoyé, aucun état écrit: 1: agent
    Site sans [sites.inventory] côté veilleur => 404, code 1, recul d'1 h: 1: agent
```

## Tasks to do

1. **État** : `inventory.json` (0600, `save_private_json`) et `inventory.lock` (`with_lock`, `LOCK_NB`, message « un autre passage relève l'inventaire : ce passage le saute ») ; `empty_inventory_state()` = `seq`, `sent_sha256`, `sent_at`, `failed_at`, `scanned_at`, `stat_sha256`, `stat_paths` ; `load_inventory_state()` sur le modèle de `load_logs_state()` (clés exactes, types, `sha256` vide ou 64 hex, `stat_paths` liste de 4 000 chemins relatifs au plus) ; illisible → `UsageError` (« le supprimer refait un relevé et un envoi »). `state.json` n'est pas touché.
2. **Relevé économe** : sous le verrou, `stat` des `stat_paths` (`clearstatcache`) → empreinte `(chemin, mtime, taille)` ; relevé complet si elle diffère de `stat_sha256`, si `now − scanned_at ≥ 3 600`, ou si un renvoi est dû (`now − sent_at ≥ 86 400`) ; sinon fin du passage d'inventaire. Après un relevé : `scanned_at`, `stat_paths` (vide si plus de 4 000 : relevé horaire seul), `stat_sha256`.
3. **Envoi** (`send_inventory(Config, dir, now)`) : envoi si l'empreinte de la liste ≠ `sent_sha256` ou si `now − sent_at ≥ 86 400`, et si `now − failed_at ≥ 3 600` ; `seq = max(seq + 1, heure en ms)` écrit avant l'envoi ; corps signé `DOMAIN_INVENTORY . $body` par `secret.key`, puis `pending_new_secret()` sur échec (comme `send_log_batch`), `sodium_memzero` ; 204 → `sent_sha256`, `sent_at = now`, `failed_at = 0` ; sinon `failed_at = now` et `SendError` (« inventaire refusé (raison dans journalctl -u vigie-serve) : nouvel essai dans 1 h »).
4. **Passage** : `main` appelle `send_inventory` après les commandes et avant les logs si `inventory.enabled` ; `SendError` → code 1, `UsageError` → code 2, sans empêcher les logs. Mode `--inventory` (exclusif avec `--dry-run` et `--init`) : enveloppe indentée, rien de signé, envoyé ni écrit. `VERSION = '0.5.0'`, en-tête et usage mis à jour.
5. **Fixtures signées et vecteurs** : `make-interop-fixture.php` régénère `php-signed-report.json` (seuls `agent` et la signature changent), écrit `php-signed-inventory.json` (fixture `wp-inventory`, graine `INTEROP_SEED_HEX`, `serialNumber` et heures fixes) et `inventory-vectors.json` (`domain`, `seed`, `now` ; `valid` → 204 ; `report-replayed`, `pull-replayed`, `logs-replayed`, `unprefixed` → 404). `AgentTest.php` vérifie que les fichiers suivis sont égaux à ce que l'agent produit. Aucun vecteur purl ici : `purl.json` de F1 est le seul fichier (rejoué en phase 2).
6. **Rust** : `interop.rs` attend `vigie-agent-php/0.5.0` ; test « l'ingestion accepte l'inventaire PHP tel quel » (site `kind = wordpress`, `[sites.inventory] source = "agent-php"`, composants attendus en base, `dropped = 0` grâce au dédoublonnage de l'agent) et refus croisés (inventaire sur `/r/v1/report` et `/r/v1/logs`, rapport sur `/r/v1/inventory`). `inventory_vectors.rs` rejoue chaque vecteur contre le routeur.
7. **Bout en bout** (`agent_e2e.rs`, PHP 8.1 épinglé en CI) : copie de `wp-inventory` en dossier temporaire, `[sites.inventory]` côté veilleur, `"inventory": {"enabled": true}` côté agent. Horloge (variante robuste) : avant chaque passage, la `FakeClock` est **recalée** — sur « `seen_at` du dernier inventaire accepté + 241 s » quand le passage doit envoyer un inventaire, **sans avance** sinon — et le test **affirme `|FakeClock − heure réelle du moment| ≤ 270 s`** avant de lancer l'agent. Calendrier indicatif par rapport à l'heure réelle : P1 (inventaire 1) à −240 ; P2 à ≈ −240, sans avance : le rapport est refusé par le débit de 60 s, l'agent sort en code 1 mais passe quand même à l'inventaire, et le test affirme **aucun inventaire envoyé et `seen_at` inchangé** ; P3 (renvoi après recul de 25 h de `sent_at` dans `inventory.json`) à +1 ; P4 (en-tête modifié, `touch` à +2 s pour changer le `mtime`) à +242. Puis rapport signé par `secret.key` de l'agent (lu par le test) rejeté sur `/r/v1/inventory`, accepté sur `/r/v1/report`. `a_held_lock_makes_the_agent_skip_without_waiting` tient aussi `inventory.lock` et vérifie le message.
8. **Docs** :
   - `protocole-agent.md` : `POST /r/v1/inventory` dans la liste des routes ; ligne « Inventaires » dans « Une clé par usage » (`vigie-inventory-v1\n`) ; enveloppe, `complete`/`skipped`, liste blanche (refus du document entier), purl et grammaire (renvoi à `failles.md`), ordre des vérifications (porte avant le corps), débit 240 s, plafond de 24 nouveaux par jour UTC, renvoi inchangé, conservation, « pas une preuve de vie », `rotate-key` et `site remove`, limites V1.
   - `agent-php.md` : `kind` `prestashop` ; section « Inventaire (agent 0.5.0, issue #19) » : configuration, sources par CMS, version des modules (littéral d'abord, `vigie:config-version`), correspondances `prestashop-module` et `wpackagist`, **`wpackagist` sur un site `generic` jamais rapproché**, `hello.php` ≠ `hello-dolly`, bornes, relevé économe, `--inventory`, `inventory.json`/`inventory.lock`, 24 h et recul d'1 h, `[sites.inventory]` côté veilleur. **Retour à 0.4** : retirer `inventory` et `kind: "prestashop"` de `config.json` avant, sinon 0.4 refuse la configuration (code 2), n'envoie plus de rapport, et le site tombe en silence.
   - `failles.md` : côté extension, doublons (purl sans version pour CMS, purl complet + chemin pour Composer/npm), `complete` (seul un inventaire complet vaut absence, pour F7), limites V1.
   - `decisions.md` : section « Inventaire de l'agent (issue #19, F5) » datée du jour d'implémentation : écarts à l'issue (`scope`/`vigie:scope`, état dans `inventory.json` sans migration de `state.json`), absence de gzip, porte `[sites.inventory]`, plafond quotidien, et tout écart au plan constaté.
   - `README.md` : routes de `serve`, limite de 512 Kio de `/r/v1/inventory`.
9. **Pose sur le site A** (après fusion, hors CI) : veilleur d'abord avec `[sites.inventory]`, puis agent 0.5.0, `--inventory` pour relire, puis `"inventory": {"enabled": true}` ; relevé consigné dans `hebergement.md` en nombres seulement (aucun composant ni version réels : dépôt public).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `inventory.json` à clé en trop, `sha256` invalide, lien symbolique ou 0644 → refusé ; `state.json` identique octet pour octet avant et après un passage d'inventaire |
| 2-4 | Un serveur de test compte les envois et un compteur de lectures les relevés : 1 relevé et 1 envoi au premier passage, 0 et 0 au second, 1 et 1 après recul de 25 h, 0 envoi juste après un refus, 1 une heure plus tard (heure injectée) ; le rapport part même quand `inventory.json` est illisible |
| 5 | `git diff` de `php-signed-report.json` ne montre que `agent` et la signature ; `php run.php` échoue si une fixture suivie n'est pas à jour |
| 6 | `cargo test --test interop --test inventory_vectors` passe |
| 7 | `VIGIE_E2E_PHP=… cargo test --test agent_e2e -- --ignored` passe en CI (PHP 8.1 épinglé) ; chaque étape du Test Scope est une assertion, et l'assertion `|FakeClock − heure réelle| ≤ 270 s` précède chaque passage |
| 8 | Les docs ne contiennent aucun domaine, compte ou composant réel ; `grep -rn "core/wordpress" vigie/docs` ne trouve plus de règle en vigueur |
| 9 | `vigie` en ligne accepte l'inventaire du site A (journal « inventaire accepté … nouveau ») ; ni `reports.last_valid_at` ni l'incident de silence ne bougent du fait de l'inventaire |
