---
objective: "L'agent PHP retire à chaque passage la commande de son site, ne l'exécute que si la réponse est signée par la clé de commandes épinglée et passe toutes les règles de protocole-commandes.md, n'exécute que des commandes de sa propre liste fermée, garde son état hors webroot de façon sûre, et renvoie le résultat jusqu'à l'accusé."
status: done
issue_number: 6
---

# Plan: Agent PHP : consommation et exécution des commandes

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Côté site du canal de #10, sans y ouvrir de porte : rien ne s'exécute sans signature du veilleur, rien d'autre que `ping` et `rotate-key` tant que #13 n'est pas livré |
| **Source** | Issue GitHub #6 ; `vigie/docs/protocole-commandes.md` ; `vigie/tests/fixtures/commands-vectors.json` ; `vigie/docs/decisions.md` (ext-sodium native, base64) |

## Phases

| #   | Phase                                        | File                         |
| --- | -------------------------------------------- | ---------------------------- |
| 1   | État sûr, retrait signé, vérification        | [`phase-1.md`](./phase-1.md) |
| 2   | Exécution, résultat, rotate-key, tests       | [`phase-2.md`](./phase-2.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| ext-sodium native et base64, pas `sodium_compat` ni hex | Décision du 2026-10-16 (`decisions.md`) : l'agent signe ainsi en production |
| Clé publique de commandes épinglée dans `config.json` (`commands.pubkey`, avec `commands.endpoint`), et non compilée dans le fichier PHP : quand `commands` est présent, l'agent exige `config.json` en 0600 et son dossier en 0700 (vérifiés par `realpath`, sans lien), sinon il refuse de retirer | Le fichier de l'agent est le même pour tous les sites (déployé depuis un commit) ; qui peut écrire `config.json` sous ce compte peut aussi remplacer l'agent : l'épinglage en configuration protégée est équivalent à une clé compilée. Écart consigné dans `decisions.md` |
| Sans `commands` dans la configuration, l'agent ne retire rien | Fail-closed, comme `[commands]` côté veilleur |
| État dans `~/.vigie-agent/state.json` (0600, dossier 0700 vérifié, `flock` sur `state.lock`, écriture atomique par fichier temporaire puis `rename`, jamais de lien suivi) : `pull_seq`, `last_command_seq`, commande en cours, résultat en attente d'accusé | L'idempotence vit au veilleur, mais un résultat ne doit pas se perdre entre deux passages (contrat de #10) |
| Liste fermée côté agent : `match` sur des constantes littérales ; `ping` → `ok` ; `rotate-key` → nouvelle paire et preuve ; `htaccess-apply`/`htaccess-rollback` → `refused` (« indisponible », #13) ; tout autre nom → réponse rejetée sans exécution. Aucun `eval`, aucun appel shell | Le canal ne doit pas devenir un webshell même si le veilleur est compromis |
| Vérification de la réponse dans l'ordre du contrat : statut 200 et corps JSON non vide (un `php -S` en erreur fatale rend 200 vide), signature sur `vigie-commands-v1\n` + horodatage + `\n` + corps, `server_time` égal à l'en-tête, ±300 s, `site`, `nonce`, puis commande : schéma strict, `v`, `runtime` = `php`, nom connu, `expires_at` futur, `seq` > dernier exécuté | Contrat de #10 et vecteurs |
| Résultat persisté avant et après exécution, renvoyé à chaque retrait jusqu'à `acked` ; une commande re-servie déjà exécutée n'est pas rejouée ; une exécution interrompue (état « en cours » au démarrage) rend `failed` « exécution interrompue » | Contrat de #10 |
| `rotate-key` : nouvelle paire dans `secret.key.new` (0600, création exclusive), preuve sur `vigie-rotate-v1\n` + site + `\n` + id + `\n` + nouvelle clé ; bascule (`rename` atomique sur `secret.key`) seulement sur `acked` + `accepted: true`, suppression de la nouvelle paire sur `accepted: false` ; tant que la bascule attend, un rapport ou un retrait refusé (404) avec l'ancienne clé est retenté une fois avec la nouvelle, et un succès vaut bascule | Contrat de #10 ; l'agent ne doit jamais se verrouiller dehors |
| L'agent ne lit jamais `$_SERVER` ni un en-tête pour décider quoi exécuter : il ne tourne qu'en CLI (déjà en place) et n'agit que sur le corps signé | Exigence de l'issue |
| Vecteurs consommés par le test PHP depuis `vigie/tests/fixtures/commands-vectors.json`, sans exécuter de PHP dans le CI Rust ; le test de bout en bout réel (`tests/agent_e2e.rs`) est `#[ignore]`, lancé par `VIGIE_E2E_PHP` dans une étape CI dédiée avec le PHP 8.1 épinglé en Docker, et échoue (jamais sauté) quand la variable est posée ; l'horloge du veilleur y est une `FakeClock` avancée entre deux passages pour franchir les débits (rapport 60 s, retrait 30 s) | Relecture du 2026-10-16 : pas de PHP dans `cargo test` ordinaire ; version visée 8.1 ; TLS n'est pas l'objet du test (http en boucle locale) |
| La bascule de clé n'a lieu que sur une réponse signée (accusé accepté, ou réponse valide à un retrait signé par la nouvelle clé) ; l'ancienne clé est gardée en `secret.key.old` ; un 204 de rapport ne fait jamais basculer | Un 204 non signé, forgé ou mal routé, enfermerait l'agent dehors |
| JSON décodé en objets (`{}` et `[]` distincts), signature vérifiée sur les octets bruts avant tout décodage, `data` omis quand il est vide ; verrou `LOCK_NB` sur tout le cycle ; propriétaire du dossier contrôlé par `posix_geteuid` ; `commands` refusé sous Windows ; une rotation interrompue supprime `secret.key.new` | Relecture du 2026-10-16 |
