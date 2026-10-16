---
objective: "Chaque site porte deux axes déclarés par l'exploitant, CMS et runtime ; chaque contrôle déclare les CMS auxquels il s'applique et chaque commande les runtimes qui l'admettent, et une commande hors runtime est refusée avant d'exister, dès le premier contrat de /r/v1/commands."
status: pending
issue_number: 2
---

# Plan: Typologie des sites (E1 partiel)

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Poser le champ de typologie dans le contrat des contrôles et des commandes avant A1 (#10), pour ne jamais changer ce contrat après le déploiement des agents |
| **Source** | Issue GitHub #2 ; `vigie/docs/decisions.md`, décision transverse « typologie à deux axes » |

## Phases

| #   | Phase                                   | File                         |
| --- | --------------------------------------- | ---------------------------- |
| 1   | Runtime, capacités et liste des commandes | [`phase-1.md`](./phase-1.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Deux axes, comme le registre des décisions : `kind` (`generic`, `wordpress`, `prestashop`, existant) pour les contrôles ; `runtime` (`php`, `node`, `static`), nouveau, pour les commandes. Le `generic` de l'issue reste le défaut du CMS | Décision du 2026-10-16 ; le CMS seul ne dit pas ce qu'un site exécute |
| `runtime` est facultatif dans `config.toml`. `wordpress` et `prestashop` impliquent `php` ; un `runtime` contraire est une erreur de configuration (code 2). Un site `generic` sans `runtime` n'en a aucun et n'admet aucune commande | Fail-closed : sans déclaration, rien ne s'exécute. Aucune valeur n'est devinée |
| Le registre des capacités est `config.toml` sur le VPS (0600, propriétaire `vigie`, `deny_unknown_fields`), jamais un fait rapporté par l'agent ni détecté sur le site. Il n'est pas signé, écart à l'issue consigné dans `decisions.md` : il ne quitte jamais le VPS, et qui peut l'écrire peut aussi remplacer le binaire. Sa version est l'empreinte SHA-256 d'une projection canonique de la typologie (par site : id, CMS, runtime effectif). `serve` l'écrit en base à son démarrage, `tick` à chaque passage où elle change, en journalisant le détail par site ; `vigie status` compare l'empreinte du fichier, celle de `tick` et celle de `serve`, et signale « serve à redémarrer » quand celle de `serve` diffère, ou manque sur une base en v7 (ancien `serve` en mémoire, ou première installation où `tick` a créé la base après le démarrage de `serve`) | Une signature ne protégerait que contre un attaquant qui tient déjà le compte `vigie`. `serve` lit la configuration une seule fois : c'est lui qui délivrera les commandes (#10), son empreinte est celle qui compte |
| Une valeur inconnue (`runtime = "python"`) est refusée à la lecture par serde, comme `kind` aujourd'hui ; dans le contrat JSON des commandes, un runtime inconnu est un refus | Fail-closed exigé par l'issue |
| La liste des commandes est un `enum` fermé, codé en dur, dès cette issue : `ping`, `rotate-key`, `htaccess-apply`, `htaccess-rollback`. Chaque variante déclare ses runtimes par un `match` sans joker. Tant qu'aucun agent Node n'existe, toutes n'admettent que `php` ; `static` n'en admet aucune (pas d'agent) | Le contrat de #10 hérite de la liste et du filtre ; fail-closed jusqu'à l'existence d'un agent Node. Ajouter une commande ou un runtime reste un changement de code relu |
| Dans le contrat de `/r/v1/commands`, le champ s'appelle `runtime` (et non `kind` comme dans le texte de l'issue, `kind` désignant déjà le CMS) ; il est obligatoire dans chaque commande, couvert par la signature, à côté de `v` et `site` (la clé de commandes étant commune, une commande ne vaut que pour son site) ; l'agent refuse une commande dont le runtime n'est pas le sien, une valeur inconnue ou une commande absente de sa propre liste codée en dur ; le veilleur revérifie `permit` à la délivrance, pas seulement à la création. Écrit dans `protocole-commandes.md` dès #2 | Fixer l'enveloppe avant A1 est l'objet même de l'issue |
| Ordre de déploiement : binaire d'abord, `runtime` dans `config.toml` ensuite ; revenir au binaire précédent impose de retirer `runtime` et ne marche plus sur une base migrée en v7. Écrit dans `hebergement.md` | `deny_unknown_fields` : un ancien binaire refuse la clé et `tick` s'arrête (incident `[api]` du 2026-10-16) |
| `vigie site add` avertit quand le site n'a pas de runtime admettant une commande ; un site PHP déclaré `generic` doit poser `runtime = "php"` pour recevoir des commandes (documenté dans `agent-php.md`) | Ne pas laisser croire qu'un agent installé reçoit des commandes |
| Les contrôles déclarent leurs CMS par une table (`CheckKind::cms()`), et `applies` la lit, au lieu d'un `match` ad hoc | Un seul registre de capacités, finalisé par #4 |
