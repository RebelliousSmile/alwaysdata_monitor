---
objective: "Chaque case de l'issue #3 renvoie à une preuve dans le dépôt, et l'issue peut être fermée."
status: in-progress
issue_number: 3
---

# Plan: Sonde UptimeRobot sur le veilleur

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Constater que la sonde UptimeRobot est en service et que ses conditions sont vérifiées, puis consigner dans le registre des décisions le « pas de webhook entrant en V1 » et le cahier des charges d'un webhook futur |
| **Source** | Issue GitHub #3 ; `vigie/docs/reception.md` § 4 ; `vigie/src/serve.rs` |

## Phases

| #   | Phase                                 | File                         |
| --- | ------------------------------------- | ---------------------------- |
| 1   | Preuves et décision sur le webhook    | [`phase-1.md`](./phase-1.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Aucun code : les trois premières cases de #3 sont déjà tenues (conditions consultées et sonde validée le 2026-10-16 dans `reception.md` § 4 ; `/health` dans `serve.rs`, 503 au-delà de 3 min ; aucune route entrante hors `/health` et `/r/v1/report`) | Réécrire ce qui est livré et prouvé n'apporte rien ; le plan relie chaque case à sa preuve |
| Le cahier des charges d'un webhook entrant futur est reporté dans `vigie/docs/decisions.md`, pas dans le code ni dans `protocole-agent.md` | Il ne vit aujourd'hui que dans le texte de l'issue, qui disparaît des vues une fois fermée. Le registre est l'endroit où les plans suivants cherchent les décisions ; `protocole-agent.md` décrit le canal des agents, qui n'a rien à voir avec UptimeRobot |
| À l'endtask, le commentaire de fermeture de #3 relie chacune des quatre cases à sa preuve : `reception.md` § 4, `vigie/src/serve.rs` (test `health_thresholds`), la section du registre | Les cases restées non cochées dans l'issue ne doivent pas passer pour un travail abandonné. C'est une étape de l'endtask, pas une tâche de phase, parce qu'elle suit le commit de la phase |
