---
objective: "Le veilleur sert à l'agent d'un site, à sa demande, une commande signée par une clé dédiée, prise dans une liste fermée filtrée par runtime contre la configuration du moment, préparée par `vigie site command` en aperçu puis appliquée par --apply, rejouable nulle part, dont le résultat revient jusqu'à accusé, et tracée dans un journal d'audit chaîné, signé par une clé d'audit distincte et ancré hors de la base."
status: pending
issue_number: 10
---

# Plan: Canal de commandes /r/v1/commands et CLI

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Ouvrir la seule voie d'écriture du veilleur vers un site, sans en faire un webshell : pull signé, liste fermée, une commande en vol au plus, kill-switch, résultat fiable, audit vérifiable |
| **Source** | Issue GitHub #10 ; `vigie/docs/protocole-commandes.md` (enveloppe fixée par #2) ; `vigie/docs/decisions.md` ; relecture de sécurité du 2026-10-16 |

## Phases

| #   | Phase                                     | File                         |
| --- | ----------------------------------------- | ---------------------------- |
| 1   | Clés, file et audit en base               | [`phase-1.md`](./phase-1.md) |
| 2   | Point d'entrée /r/v1/commands             | [`phase-2.md`](./phase-2.md) |
| 3   | CLI `vigie site command` et contrat écrit | [`phase-3.md`](./phase-3.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Pull seulement : `POST /r/v1/commands` est appelé par l'agent ; le veilleur n'ouvre jamais de connexion vers un site | L'agent n'expose aucune URL (brainstorm) |
| Trois clés, trois usages. **Clé des rapports de l'agent** : signe aussi ses retraits, mais sur `vigie-pull-v1\n` + octets du corps (préfixe de domaine ; les rapports restent signés sans préfixe, format en service). **Clé de commandes** du veilleur : signe seulement les réponses de `/r/v1/commands`, sur `vigie-commands-v1\n` + `X-Vigie-Timestamp` + `\n` + octets du corps ; lue par `serve` seul. **Clé d'audit** du veilleur : signe seulement le journal d'audit ; lue par `serve`, `tick` et la CLI. Exception « clé de l'agent pour deux types de requête » consignée dans `decisions.md` | Règle « une clé par usage » (#9) : la clé la plus dangereuse ne quitte pas `serve` ; la séparation de domaine empêche qu'une signature de rapport vaille retrait |
| Les deux clés du veilleur : chemins absolus dans `[commands]` de `config.toml` (`key_file`, `audit_key_file`), fichiers 0600, dossier parent 0700, même propriétaire que le processus, ouverts sans suivre de lien (`O_NOFOLLOW`) ; `vigie commands init-keys` les crée en création exclusive et affiche la clé publique de commandes à épingler par l'agent | Même règle que le mot de passe SMTP (`alert.rs`) ; aucun secret en variable d'environnement |
| Fail-closed : sans `[commands]`, sans clé lisible, site non activé (`enabled`, faux par défaut), commande non admise ou indisponible, rien n'est servi : corps signé `{"command":null}` quand la clé est lisible, 404 commun sinon | Rien ne s'exécute par défaut |
| `permit` est vérifié contre la configuration **relue à chaque retrait** par `serve` (le fichier, pas celle chargée au démarrage) ; une configuration illisible ne sert rien. L'empreinte de typologie au moment de la création est gardée dans la ligne de la commande et dans l'audit | `serve` ne lit sinon la configuration qu'au démarrage (#2) |
| `htaccess-apply` et `htaccess-rollback` restent **indisponibles** dans le code (refus à la création et à la délivrance) jusqu'à ce que #13 livre la liste fermée de directives, vérifiée côté agent. Seuls `ping` et `rotate-key` sont disponibles | Un bloc `.htaccess` libre donne l'exécution de code (`php_value auto_prepend_file`, `AddHandler`) : la validation doit tenir même si le veilleur est compromis |
| Anti-rejeu, côté veilleur : `seq` de retrait strictement croissant par site (distinct de celui des rapports), `sent_at` ±300 s. Côté agent (#6) : `X-Vigie-Timestamp` ±300 s et égal à `server_time` du corps, `nonce` de la réponse égal à celui de sa requête, `seq` de commande jamais exécuté deux fois | Ni un retrait ni une réponse interceptés ne se rejouent |
| Résultat fiable : l'agent persiste `{id, seq, état, résultat}` dans son état avant et après exécution (#6) et renvoie le résultat à chaque retrait tant que la réponse ne porte pas `"acked": "<id>"`. Le veilleur traite un résultat identique déjà enregistré comme sans effet (re-`acked`), un résultat différent pour une commande close comme refusé. Une commande re-servie que l'agent a déjà exécutée n'est pas rejouée : il renvoie son résultat | Le passage de l'agent est un processus court toutes les 5 min : sans état, un résultat perdu bloquerait la file 24 h |
| `command_id` en UUIDv7 (48 bits d'heure en ms, `Clock::unix_ms`), `seq` de commande par site strict et sans trou ; une seule commande non close par site, garantie par un index unique partiel en plus de la transaction IMMEDIATE ; `serve` vérifie `expires_at` avant de servir ; `tick` passe en `expired` une commande `pending` de plus de 24 h, et en `unknown` une commande `served` sans résultat à 24 h (elle a pu s'exécuter) | Issue ; une issue inconnue n'est pas un échec |
| Remettre en file une commande non idempotente (`rotate-key`, `htaccess-*`) dont la précédente est `unknown` exige `--force` | On ne rejoue pas à l'aveugle une écriture qui a peut-être eu lieu |
| `rotate-key` : l'agent crée une nouvelle paire, **garde l'ancienne** ; son résultat porte la nouvelle clé publique et une preuve de possession (signature par la nouvelle clé de `vigie-rotate-v1\n` + id + `\n` + nonce de la commande) ; il voyage dans un retrait signé par l'**ancienne** clé. Le veilleur vérifie la preuve, remplace la clé, remet à zéro les `seq` de rapport et de retrait dans la même transaction, et répond `acked`. L'agent ne bascule qu'à l'accusé ; s'il le perd, il essaie la nouvelle clé au retrait suivant quand l'ancienne est refusée. Une seule rotation en vol (sérialisation par la règle « une commande non close ») | Spécifié pour #6. `rotate-key` n'est **pas** un remède à une compromission du site : un attaquant qui tient la clé de l'agent peut répondre avec sa propre clé ; le remède reste la réinstallation et `vigie site rotate-key` hors canal |
| Paramètres et résultats typés par commande (`deny_unknown_fields`, bornés) ; `detail` imprimable, 1000 caractères ; la CLI neutralise les caractères de contrôle à l'affichage | Le résultat vient d'un site peut-être hostile |
| Audit : table append-only (déclencheurs refusant `UPDATE` et `DELETE`), chaîne **par site** ; chaque entrée stocke ses octets JSON tels qu'écrits, `hash = SHA-256(hash précédent ‖ octets)`, signature par la clé d'audit de `vigie-audit-v1\n` + hash. Le hash de tête est ancré hors de la base : il figure dans l'e-mail envoyé à chaque création et à chaque clôture de commande, et dans `vigie status`. `vigie site audit <site>` exporte en JSONL ; `--verify` vérifie chaîne, signatures, et une tête attendue passée en option | Une troncature de la fin de chaîne n'est détectable qu'avec une ancre externe |
| Kill-switch durable : `site commands enable|disable` ; `site remove`, `site rotate-key` (CLI) remettent `enabled` à faux et annulent la commande en vol | Un site réajouté n'hérite pas d'une activation |
| Ce que le canal ne protège pas, écrit dans le contrat : un attaquant installé sur le site (clé de l'agent volée) peut retirer une commande et déclarer `ok` sans l'exécuter ; l'audit enregistre des déclarations de l'agent, pas des preuves. Un `seq` de retrait forgé à 2⁶³−1 bloque l'agent légitime (déni de service, remède : `site rotate-key` hors canal) | Honnêteté du modèle de menace |
| L'API de la console reste en lecture pour les commandes | Écriture par la console : garde-fous de #5, plus tard |
