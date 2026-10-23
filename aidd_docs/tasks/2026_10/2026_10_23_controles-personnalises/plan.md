---
objective: "Un site peut déclarer dans config.toml des règles de page à contrôler (statut attendu, texte présent, texte absent) ; le veilleur les joue avec ses contrôles intégrés et ouvre un incident par règle en échec."
status: done
issue_number: 33
---

# Plan: Contrôles personnalisés (issue #33, première case)

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Remplacer l'encart « Contrôles personnalisés, pas encore disponible » de la console par une fonctionnalité réelle, côté veilleur |
| **Source** | Issue #33 ; `vigie/app/src/lib/features.ts` (clé `personnalises`) ; `vigie/src/checks/` ; registre des capacités `vigie/src/capability.rs` |

## Relecture critique (rechallenge)

| Piste écartée | Raison |
| --- | --- |
| Un `CheckKind` par règle | Les noms de contrôle sont des constantes de compilation (`CheckKind::name`), figées dans le registre des capacités ; des noms dynamiques casseraient le registre unique (#4) et `Control::from_name` (fail-closed). |
| Définir les règles depuis la console | Écriture que le veilleur s'interdit (#35) ; `ack` est la seule écriture de la console. Les règles vivent dans `config.toml` sur le VPS, comme tout le reste. |
| Syntaxe de test libre (regex, scripts) | Surface d'attaque et de panne ; on garde trois assertions fermées. |

Retenu : **un seul contrôle `custom`**, un constat par règle (`key` = identifiant de la règle, stable ; `detail` = ce qui a échoué).

## Décisions

- Section `[[sites.custom_checks]]` : `id` (`[a-z0-9-]`, 40 max, unique par site), `path` (commence par `/`, joint à l'origine du site), `status` (100 à 599, 200 par défaut), `contains`, `absent` (200 caractères au plus), `severity` (`warning` par défaut, ou `critical`). 20 règles au plus par site.
- Un chemin ne peut pas sortir de l'origine du site : pas de `//`, pas de `\`, pas d'espace ni de caractère de contrôle.
- Une erreur réseau isolée est rejouée une fois (comme `content`) ; une deuxième donne un constat « injoignable ». Un site injoignable (`content`) saute `custom`, comme les autres contrôles.
- Aucun secret dans `path` : il figure dans le détail des constats et les e-mails.

## Phases

| #   | Phase | File |
| --- | ----- | ---- |
| 1   | Configuration, contrôle `custom`, registre, tests, documentation, console | [`phase-1.md`](./phase-1.md) |
