---
objective: "Un seul registre de capacités déclare, pour chaque contrôle (externe, battement de cœur, familles de l'agent, logs) et chaque commande, les typologies qu'il exige ; tick, l'ingestion, la clôture des incidents, la CLI et l'API le consultent tous, refusent fail-closed ce qu'il ne connaît pas, et l'audit du chemin critique avant déploiement est fait et écrit."
status: pending
issue_number: 4
---

# Plan: Registre de capacités final (E1)

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Finir E1 : la typologie (#2) filtre effectivement tout ce qui s'exécute ou s'ouvre pour un site, depuis une seule déclaration |
| **Source** | Issue GitHub #4 ; `vigie/src/capability.rs` (commandes, #2), `CheckKind::cms` dans `checks/mod.rs`, `tick.rs` (`close_unwatched`), `report.rs` (familles `agent:*` libres), `facts.rs` ; décisions « typologie à deux axes » et « écriture en trois temps » |

## Phases

| #   | Phase                                     | File                         |
| --- | ----------------------------------------- | ---------------------------- |
| 1   | Registre unique et filtrage partout       | [`phase-1.md`](./phase-1.md) |
| 2   | Tests d'extrémité et audit du chemin critique | [`phase-2.md`](./phase-2.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| `capability.rs` devient le registre unique : `enum Control { Check(CheckKind), Heartbeat, Agent(AgentFamily), Logs }` et `CommandKind`, chacun déclarant ses exigences par un `match` sans joker : CMS admis (axe `kind`) pour les contrôles, runtimes admis pour les commandes, plus la condition d'existence (agent enregistré pour `Heartbeat` et `Agent(_)`, source de logs pour `Logs`). `CheckKind::cms` est supprimé et déplacé dans le registre | Une seule déclaration ; une variante nouvelle oblige à décider |
| Familles d'agent fermées : `AgentFamily { Integrity, UploadsPhp, Root, Php }` (celles qu'émet l'agent PHP 0.3 et celles admises par `report.rs`), avec leurs CMS (`UploadsPhp` : WordPress seulement). Une famille inconnue ou non admise pour le CMS du site : le constat est **écarté et compté** à l'ingestion (le rapport reste accepté, la raison est journalisée), jamais un incident | Fail-closed sans casser un agent plus récent que le veilleur ; un agent compromis ne fabrique pas d'incidents hors typologie |
| `watched(site, check_name, ctx) -> bool` unique, dérivé du registre, utilisé par `close_unwatched` (tick), l'ingestion et l'API (états des contrôles) ; `allowed_controls(site)` et `allowed(site)` (commandes) servent la CLI (`site list`, `status`) et l'API | Le même verdict partout : un contrôle affiché, exécuté et clos selon la même règle |
| Kind inconnu dans `config.toml` : déjà refusé au chargement (#2) ; ici, tests d'extrémité seulement (kind vide, casse, valeur inconnue, runtime contradictoire avec le CMS) | Exigence de l'issue |
| Audit du chemin critique écrit dans `vigie/docs/audit-chemin-critique.md`, chaque point avec sa preuve (test, CI, ou relevé masqué) : anti-rejeu (seq, horloge ±300 s, nonce des retraits, idempotence des lots de logs), `SQLITE_BUSY` sous charge (test de contention existant étendu à `serve` + `tick` + lots de logs), délais de l'agent (connexion, total, verrous `LOCK_NB`), build zigbuild musl (CI) et cible réelle (`x86_64`, glibc 2.43 relevée ; binaire statique musl qui ne dépend pas de la glibc). Un point sans preuve est écrit « non vérifié » avec ce qu'il faut faire, jamais coché | L'issue demande l'audit avant le premier déploiement des nouveautés ; la règle du dépôt public impose de masquer les valeurs réelles |
