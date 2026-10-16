---
objective: "Le socle de Vigie tient les exigences de l'issue #9 : écritures SQLite sans SQLITE_BUSY entre serve, tick et la CLI, erreurs d'API uniformes avec request_id, horloge injectable, build musl et détection de secrets en CI, règles de clés et de secrets écrites."
status: in-progress
issue_number: 9
---

# Plan: Socle transversal

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Combler les manques du socle relevés le 2026-10-16 : connexions et transactions SQLite, writer unique de `serve`, erreurs uniformes, horloge, garde-fous de CI, règles de clés |
| **Source** | Issue GitHub #9 ; inventaire du code de `feat/console-vigie` du 2026-10-16 ; `vigie/docs/decisions.md` |

## Phases

| #   | Phase                                  | File                         |
| --- | -------------------------------------- | ---------------------------- |
| 1   | Store : connexions et writer unique    | [`phase-1.md`](./phase-1.md) |
| 2   | Erreurs uniformes et request_id        | [`phase-2.md`](./phase-2.md) |
| 3   | Horloge injectable                     | [`phase-3.md`](./phase-3.md) |
| 4   | CI, clés et secrets                    | [`phase-4.md`](./phase-4.md) |

## Resources

| Source | Verified |
| ------ | -------- |
| https://www.sqlite.org/wal.html | En WAL, une transaction ouverte en lecture qui tente ensuite d'écrire, alors qu'un autre processus a écrit depuis son instantané, échoue en SQLITE_BUSY sans attendre `busy_timeout` ; une transaction `BEGIN IMMEDIATE` prend le verrou d'écriture d'entrée et attend |
| https://www.sqlite.org/pragma.html#pragma_query_only | `PRAGMA query_only` refuse toute écriture sur la connexion |

## Decisions

| Decision | Why |
| -------- | --- |
| Le writer unique ne vaut que dans `serve`. Entre processus (`serve`, `tick` lancé chaque minute par systemd, la CLI), la sérialisation passe par WAL, `busy_timeout` 5 s et des transactions d'écriture toutes en `IMMEDIATE` | Un canal ne traverse pas les processus. Les transactions DEFERRED restantes (`record_tick`, `reconcile`, `close_unwatched`, `remove_key`) peuvent échouer en SQLITE_BUSY sans attendre. Dans `serve`, le writer garde une connexion au lieu d'un `Store::open` par rapport, qui rejoue `migrate()` sous verrou IMMEDIATE à chaque requête |
| Le writer de `serve` est une connexion sous `Mutex`, appelée depuis `spawn_blocking`, et non la « task dédiée + canal mpsc » du texte de l'issue | Le but de l'issue est une seule connexion qui écrit, avec des écritures sérialisées. Le mutex l'atteint sans thread dédié, sans oneshot et sans la feature `sync` de tokio. Les écritures en attente patientent sur le mutex comme elles patienteraient dans le canal |
| La connexion du writer s'ouvre sans créer la base et sans migrer, à la première écriture | `serve` ne crée pas la base (`serve.rs`, démarrage) : c'est `tick` ou la CLI qui la crée. Pendant un déploiement, l'ancien `serve` doit tolérer un schéma plus récent, comme le fait aujourd'hui `open_read`, par lequel passent les écritures de l'API |
| L'horloge injectable couvre l'heure Unix et un instant monotone logique. L'heure Unix sert aux fenêtres actuelles : `MAX_CLOCK_SKEW`, `TICK_MAX_AGE` et `CLOSED_WINDOW`. L'instant monotone servira aux fenêtres glissantes de #5, que l'issue cite comme raison du trait. Les délais d'E/S réelles (délais réseau de `tick`, `http`, `tls`, `tokio::time::timeout`) restent sur l'horloge système | Simuler le temps d'une E/S réelle ne teste rien ; ce sont les décisions de fenêtre qui doivent être reproductibles en test |
| Les erreurs de `/api/v1` portent un corps JSON `{"error":{"code","message","request_id"}}` et l'en-tête `X-Request-Id`. `/r/v1/report` garde son 404 sans corps ; son request_id ne va qu'au journal | Le 404 silencieux du point d'entrée des agents est une décision de sécurité (`protocole-agent.md`) : il ne doit rien révéler. #5 réutilise ce module au lieu de le créer |
| Signatures : base64 standard et ext-sodium native, sans changement. La case « hex minuscule » de #9 est fermée par cette décision | Décision de l'utilisateur du 2026-10-16, consignée dans `vigie/docs/decisions.md` |
| Clés par usage et épinglage : la règle est écrite maintenant dans `protocole-agent.md` ; la clé de signature des commandes du veilleur et son épinglage par l'agent sont livrés avec les commandes (#10, #6) | Il n'existe aujourd'hui qu'un usage (les rapports) et aucun webhook entrant (registre, issue #3). Créer une clé sans usage serait du code mort |
| Le garde-fou contre aws-lc et openssl est un contrôle de `Cargo.lock` en CI, pas un nouvel outil | Un grep suffit à empêcher la régression ; le build musl par zigbuild en CI prouve le reste |
