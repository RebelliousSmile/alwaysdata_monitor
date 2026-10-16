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
| **Ordre** : #4 s'implémente après #1 et #8 fusionnés (source de logs, contrôle `logs`, lots de logs) ; #8 ajoute provisoirement `logs` au prédicat de `tick`, que le registre reprend ici pour en être la seule source | Le contrôle `logs` et les lots n'existent qu'avec #1 et #8 |
| `capability.rs` devient le registre unique : `enum Control { Check(CheckKind), Heartbeat, Integrity, Agent(AgentFamily), Logs }` et `CommandKind` (dont le filtrage par runtime et le test « `php` refusé pour `static` et `node` » existent depuis #2 et sont déplacés dans `tests/capability.rs`), chacun déclarant ses exigences par un `match` sans joker : CMS admis pour les contrôles, runtimes admis pour les commandes, plus la condition d'existence (agent enregistré **et** runtime effectif `php` pour `Heartbeat`, `Integrity` et `Agent(_)` ; référence d'empreintes en plus pour `Integrity` ; source de logs pour `Logs`). `CheckKind::cms` est déplacé dans le registre | Une seule déclaration ; une variante nouvelle oblige à décider ; une clé d'agent sur un site `static` n'ouvre rien |
| Familles d'agent fermées, celles qu'émet réellement l'agent PHP (`finding('…'`) : `AgentFamily { Root, CriticalFile, MustContain, UploadsPhp }` ; `UploadsPhp` WordPress seulement, les autres tous CMS. Un test confronte la liste aux `finding('…'` de `vigie-agent.php` et à la fixture signée. `agent:integrity` est **réservé au veilleur** (`facts::compare`) : `Control::Integrity`, jamais une famille ; un agent qui l'émet voit tout son rapport refusé (règle actuelle de `report.rs`, gardée). Un nom mal formé (casse, espace) est déjà refusé par `is_check_name` avec tout le rapport. Une famille bien formée mais inconnue ou non admise pour le CMS : constat **écarté et compté** (compteur `dropped` dans `reports`, visible dans `status` et journalisé), le rapport reste accepté | Fail-closed sans casser un agent plus récent ; un agent ne fabrique ni intégrité ni incident hors typologie ; la règle « nom réservé → refus, famille inconnue → écart » est écrite dans `decisions.md` |
| Écart à l'ingestion : `serve` garde la configuration typée des sites dans son état (même source que `typology.serve`) ; `ingest` reçoit `&Site`, filtre avant `accept_report` et rend le compte écarté dans `Accepted` ; `accept_report` ne réconcilie et n'enregistre de passage que pour les contrôles `watched` (prédicat passé par l'appelant) | Sans le CMS, l'ingestion ne peut pas filtrer ; sans le prédicat, une famille écartée serait close « rétablie » et enregistrée « ok » à chaque rapport |
| `watched(site, check_name, ctx) -> bool` unique, dérivé du registre, remplace les trois prédicats actuels (`api.rs` ×2, `tick.rs`) et sert l'ingestion ; un test vérifie que l'API, `close_unwatched` et l'ingestion rendent le même verdict sur toute la matrice. Un incident ouvert dont le contrôle n'est plus surveillé est clos par `close_unwatched` avec un e-mail distinct « plus surveillé » (jamais « rétabli ») ; il ne se rouvre pas, puisque son constat est désormais écarté | Le même verdict partout ; pas de faux « rétabli » ni de cycle clos/rouvert |
| **Migration 0011** (après 0009 de #1 et 0010 de #8) : `reports.dropped INTEGER NOT NULL DEFAULT 0`, `incidents.close_reason TEXT` ; `close_unwatched` écrit `close_reason = 'unwatched'`, `close_email` choisit « plus surveillé » ou « rétabli » selon la raison ; constante `SCHEMA_REGISTRY` | L'e-mail de clôture part plus tard (`pending_closes`) : la raison doit être en base |
| **Site sans runtime `php` portant une clé d'agent** (cas d'un `generic` sans `runtime` déclaré, surveillé aujourd'hui) : `site add`/`site rotate-key` refusent désormais un site sans runtime `php` ; pour une clé déjà en base, `tick` ouvre un incident d'avertissement `typology` (« agent enregistré sur un site sans runtime php : déclarer runtime = \"php\" ») et `status` l'affiche, au lieu de clore en silence ; l'audit avant déploiement vérifie la configuration du VPS (masquée) : aucun site sans `runtime = "php"` n'a de clé d'agent | Pas de perte silencieuse de surveillance à la mise à jour |
| Contrôle d'intégrité : la condition « référence existante » s'évalue dans la transaction d'`accept_report` (la première référence s'y crée), le prédicat reçoit la référence par son contexte | L'appelant ne peut pas la connaître avant |
| Kind inconnu dans `config.toml` : déjà refusé au chargement (#2) ; ici, tests d'extrémité seulement (kind vide, casse, valeur inconnue, runtime contradictoire avec le CMS) | Exigence de l'issue |
| Audit du chemin critique écrit dans `vigie/docs/audit-chemin-critique.md`, chaque point avec sa preuve (test, job CI, relevé masqué) ou « non vérifié » et l'action à faire : anti-rejeu (seq, horloge ±300 s, nonce des retraits, idempotence des lots de logs) ; `SQLITE_BUSY` sous charge (contention `serve` + `tick` + retraits + lots de logs) ; délais de l'agent (test : serveur qui ne répond pas → `SEND_TIMEOUT` respecté ; verrou `LOCK_NB` déjà pris → sortie propre) ; cible réelle : le job musl prouve la compilation statique, la cible se prouve par un relevé masqué sur le VPS (`vigie --version` et un `tick` à blanc avec le binaire de la CI, empreinte SHA-256 comparée), sinon « non vérifié » | L'issue demande l'audit avant le déploiement ; un binaire compilé n'est pas un binaire qui tourne sur la cible |
