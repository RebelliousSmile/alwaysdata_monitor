---
objective: "Chaque point resté ouvert dans le brainstorm du 2026-10-15 porte une décision datée, consignée dans le dépôt, et l'issue #11 peut être fermée."
status: implemented
issue_number: 11
---

# Plan: Décisions ouvertes du brainstorm 2026-10-15

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Consigner les décisions de l'utilisateur du 2026-10-16 sur les sept points ouverts de #11, et retirer les marques « provisoire » devenues fausses |
| **Source** | Issue GitHub #11 ; `aidd_docs/tasks/2026_10/2026_10_15_veilleur-multisites/brainstorm.md`, section « Encore ouvert » ; réponses de l'utilisateur du 2026-10-16 |

## Phases

| #   | Phase                         | File                         |
| --- | ----------------------------- | ---------------------------- |
| 1   | Registre des décisions        | [`phase-1.md`](./phase-1.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Les décisions vivent dans `vigie/docs/decisions.md`, un registre daté que les plans suivants citent ; le brainstorm reçoit seulement un renvoi en fin de fichier | Le brainstorm est la trace d'une séance approuvée : le réécrire effacerait ce qui était ouvert à l'époque. Un registre unique évite de disperser les décisions entre plans, issues et docs |
| Choix par défaut, révisable : les sites sans tâche planifiée ni SSH (accès FTP et SQL seulement, constat de l'utilisateur) sont couverts en V1 par les contrôles externes seuls, comme les sites statiques. Aucun accès FTP n'est stocké. La piste notée pour plus tard est un agent déposé une fois par FTP, puis appelé par le veilleur en HTTPS signé | La règle du brainstorm « l'accès est demandé au moment d'agir, jamais stocké » reste vraie. Stocker un accès FTP donne le rayon d'impact maximal relevé par la revue de sécurité. L'adaptateur de logs (#1) vise Alwaysdata, où la tâche planifiée existe |
