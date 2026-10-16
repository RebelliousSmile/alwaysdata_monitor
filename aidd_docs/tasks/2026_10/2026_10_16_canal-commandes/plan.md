---
objective: "Le veilleur sert à l'agent d'un site, à sa demande, une commande signée par une clé dédiée, prise dans une liste fermée filtrée par runtime, préparée par `vigie site command` en aperçu puis appliquée par --apply, rejouable nulle part, et tracée dans un journal d'audit chaîné et signé."
status: pending
issue_number: 10
---

# Plan: Canal de commandes /r/v1/commands et CLI

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Ouvrir la seule voie d'écriture du veilleur vers un site, sans en faire un webshell : pull signé, liste fermée, une commande en vol au plus, kill-switch, audit vérifiable |
| **Source** | Issue GitHub #10 ; `vigie/docs/decisions.md` (trois temps : proposer, valider, appliquer ; une clé par usage ; base64) ; `capability.rs` (#2) |

## Phases

| #   | Phase                                     | File                         |
| --- | ----------------------------------------- | ---------------------------- |
| 1   | Clé de commandes, file et audit en base   | [`phase-1.md`](./phase-1.md) |
| 2   | Point d'entrée /r/v1/commands             | [`phase-2.md`](./phase-2.md) |
| 3   | CLI `vigie site command` et contrat écrit | [`phase-3.md`](./phase-3.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Pull seulement : `POST /r/v1/commands` est appelé par l'agent, signé par **sa** clé (celle des rapports) ; le veilleur n'ouvre jamais de connexion vers un site | L'agent n'expose aucune URL (brainstorm). La requête de l'agent s'authentifie comme un rapport ; ses corps ont des schémas disjoints (`"type":"pull"` obligatoire ici, champ inconnu d'un rapport), un rapport ne passe donc jamais pour un retrait, ni l'inverse |
| La réponse est signée par une **clé de commandes** du veilleur, distincte de toute clé d'agent, sur `vigie-commands-v1\n` + `X-Vigie-Timestamp` + `\n` + octets bruts du corps. Signature en base64 (décision du 2026-10-16) | Le préfixe sépare les domaines de signature ; l'horodatage, sinon modifiable, entre dans ce qui est signé ; pas de JSON re-sérialisé |
| La clé privée de commandes vit dans `<dossier de la base>/commands.key`, 0600 vérifié à chaque lecture comme le mot de passe SMTP ; `vigie commands init-key` la crée (refus si elle existe) et affiche la clé publique à épingler par l'agent | Même règle que les autres secrets (`hebergement.md`) ; aucun secret en variable d'environnement |
| Fail-closed : sans clé de commandes lisible, sans site activé (`commands_enabled`, faux par défaut), sans runtime admis, `/r/v1/commands` ne sert aucune commande et le dit par un corps signé `{"command":null}` quand il peut signer, sinon par le 404 commun | Rien ne s'exécute par défaut ; un agent ne distingue pas un site désactivé d'un site sans commande |
| Anti-rejeu côté veilleur : `seq` de retrait strictement croissant par site (distinct du `seq` des rapports), `sent_at` à ±300 s. Côté agent (#6) : `seq` de commande strictement croissant et `X-Vigie-Timestamp` à ±300 s ; chaque réponse porte le `nonce` de la requête, que l'agent compare | Un retrait intercepté ne se rejoue pas ; une réponse interceptée ne se rejoue ni plus tard ni pour une autre requête |
| `command_id` en UUIDv7 tiré par le veilleur (`getrandom` + heure), `seq` de commande par site, strict et sans trou. Une table des commandes servies garde chaque `command_id` : une commande n'est servie qu'à l'agent de son site, et son résultat n'est accepté qu'une fois | Exigence de l'issue ; la table sert aussi l'audit |
| Une seule commande non acquittée par site : `--apply` est refusé tant qu'une commande est `pending` ou `served`. Une commande non retirée ou non acquittée 24 h après sa création passe `expired` au `tick` suivant | « Jamais deux commandes non acquittées », purge > 24 h ; pas d'exception « concurrentes explicites » en V1, faute de besoin |
| La liste fermée et le filtre par runtime sont ceux de `capability.rs` (#2). Les paramètres de chaque commande ont un schéma strict, typé dans un `enum` (`deny_unknown_fields`), borné ; `ping` et `htaccess-rollback` n'en ont pas, `rotate-key` non plus, `htaccess-apply` reçoit le bloc de règles (16 Kio au plus, validé par #13) | Pas de dispatch dynamique, pas de paramètre libre |
| Le résultat d'une commande revient dans le retrait suivant (`result` : `command_id`, `status` `ok`/`error`/`refused`, `detail` imprimable 1000 caractères au plus, `data` propre à la commande) ; l'agent n'écrit rien en local à ce sujet (#6) | L'audit vit côté serveur |
| Journal d'audit en table SQLite `command_audit`, append-only (déclencheurs qui refusent `UPDATE` et `DELETE`), chaque entrée chaînée par SHA-256 à la précédente et signée par la clé de commandes. `vigie site audit <site>` l'exporte en JSONL vérifiable avec la clé publique ; `vigie site audit --verify` vérifie la chaîne | « Journal d'audit append-only signé, exporté dans le rapport » : la console et l'exploitant ont une trace qu'on ne réécrit pas sans la clé |
| Horloge du veilleur : ses décisions de fenêtre passent par `Clock` (#9) | Tests de fenêtre reproductibles |
| L'API de la console reste en lecture pour les commandes (aucun endpoint d'écriture ici) | Écriture par la console : garde-fous de #5, plus tard |
