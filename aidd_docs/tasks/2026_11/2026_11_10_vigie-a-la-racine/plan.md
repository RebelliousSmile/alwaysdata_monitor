---
objective: "Le contenu de vigie/ est à la racine du dépôt sc-vigie, la CI, les tests et les deux scripts de déploiement passent sans aucun chemin vigie/ propre au dépôt."
status: in-progress
---

<!-- Fill or omit these sections; never add, rename, or reorder one. -->

# Plan: vigie à la racine du dépôt sc-vigie

## Overview

| Field      | Value                   |
| ---------- | ----------------------- |
| **Goal**   | Remonter `vigie/` à la racine (déplacement à l'identique), corriger tout chemin qui en dépend, puis remettre la copie locale d'aplomb |
| **Source** | Brainstorm du 2026-11-10 (texte) : « le code de vigie est dans le répertoire vigie, éliminer les fichiers racine du module PrestaShop et remonter le code qui est dans vigie » |

## Phases

| #   | Phase                                  | File                         |
| --- | -------------------------------------- | ---------------------------- |
| 1   | Déplacement, CI et déploiement         | [`phase-1.md`](./phase-1.md) |
| 2   | Docs, commentaires et changelog        | [`phase-2.md`](./phase-2.md) |
| 3   | Copie locale et premier déploiement    | [`phase-3.md`](./phase-3.md) |

## Decisions

| Decision   | Why   |
| ---------- | ----- |
| **Préalable : la PR #64 (`chore/split-module`) est fusionnée.** Le déplacement part de `main` après elle, dans une PR à part (phases 1 et 2), la phase 3 après sa fusion | La #64 retire déjà tout le module de la racine : il ne reste qu'à remonter `vigie/`. Une PR de pur déplacement se relit seule, et `git log --follow` suit chaque fichier |
| **Déplacement à l'identique** (hypothèse retenue, pas de réponse au brainstorm) : `Cargo.toml`, `src/`, `tests/`, `migrations/` du veilleur à la racine, `app/`, `agent/`, `scripts/`, `deploy/`, `docs/`, `examples/` à côté. Pas d'espace de travail Cargo | Le crate de la console (`app/src-tauri`) est déjà un paquet imbriqué sous celui du veilleur, sans `[workspace]` : la relation ne change pas. Une refonte en `watcher/`, `app/`, `agent/` serait un autre chantier |
| **Aucun nom en collision** : `vigie/` ne contient aucun fichier de même nom qu'un fichier de la racine après la #64 ; `vigie/README.md` devient le `README.md` du dépôt, `app/CHANGELOG.md` reste celui de la console, `CHANGELOG.md` racine reste celui du dépôt | Vérifié sur `chore/split-module` (`comm` des deux listes : vide) |
| **Chemins serveur intacts** : `~vigie/vigie/…`, `~/.vigie-agent/…`, `vigie-inventory`, `vigie/0.3.0` (User-Agent), `org.example.vigie` ne sont pas des chemins du dépôt | Les changer casserait le VPS et les agents en place |
| **`aidd_docs/tasks/` n'est pas réécrit** | Plans historiques : ils décrivent l'arbre de leur époque |
| **`/vigie/` reste ignoré à la racine** (transition) ; dans la copie locale, pull d'abord, déplacement ensuite | Une copie d'avant le déplacement garde `vigie/deploy/targets.json` (cibles réelles) : sans cette ligne, il deviendrait non suivi et non ignoré dans un dépôt public ; déplacé avant le pull, il le serait aussi, sous l'ancien `.gitignore` |
| **Archive de déploiement = commit entier** ; **fusion par merge commit** | 7 Mo, sous le `maxBuffer` de 64 Mo, et rien d'oublié (`include_str!` vers `tests/fixtures/`) ; le squash effacerait le commit de pur déplacement |
| **Hors de ce plan** : suppression des tags `v1.*` et des releases du module encore dans ce dépôt (copies dans `ps8_alwaysdata`) | Décision distincte, irréversible, à prendre par l'utilisateur |
