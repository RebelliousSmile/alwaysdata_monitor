---
objective: "La console Vigie (Tauri 2, déjà publiée en 0.1.1) couvre toute l'issue #12 : vue des logs alimentée par l'API (#5), listes paginées, jeton dans le Credential Manager sous Windows et dans le stockage privé sous Android, CSP, capacités et absence de v-html verrouillées par des tests, et aucune écriture hors de l'acquittement."
status: pending
issue_number: 12
---

# Plan: Shell Tauri, poste de pilotage (D2)

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Finir #12 sur la console existante (`vigie/app/`) sans casser les appareils appairés |
| **Source** | Issue GitHub #12 ; plan `2026_10_16_console-vigie` (phases 1 à 5, jeton par appareil) ; plan #5 `2026_10_16_api-v1` (pagination, routes logs, 429) ; maquettes `aidd_docs/design/vigie-design/maquettes/` et `tokens.css` |

## Phases

| #   | Phase                                         | File                         |
| --- | --------------------------------------------- | ---------------------------- |
| 1   | Jeton dans le trousseau, garde-fous verrouillés | [`phase-1.md`](./phase-1.md) |
| 2   | Vue des logs et listes paginées               | [`phase-2.md`](./phase-2.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| **Jeton sous Windows dans le Credential Manager** (crate `keyring`, backend natif Windows, cible `vigie-console/<id d'appareil>`), lu et écrit côté Rust seulement ; le fichier `device.json` ne garde que l'URL, l'id et le nom de l'appareil. Au premier lancement de la nouvelle version, un `device.json` qui porte encore le jeton est migré (jeton écrit au trousseau, relu, puis fichier réécrit sans jeton) ; un échec de migration garde l'ancien fichier et le signale. **Sous Android**, pas de trousseau commun utilisable sans mot de passe : le jeton reste dans le fichier du stockage privé de l'application (bac à sable par application, 0600), écart à l'issue écrit dans `decisions.md` | Exigence « keyring OS, jamais en fichier 0644 » tenue sous Windows ; sous Android le stockage privé est l'équivalent du système |
| Abstraction `SecretStore` (trousseau Windows, fichier privé Android, mémoire pour les tests) ; le jeton ne passe jamais au webview (déjà vrai : commandes Tauri qui rendent les données, jamais le jeton) | Testable sur Linux en CI ; le test Windows réel tourne sur le runner Windows du workflow console |
| **Garde-fous verrouillés par des tests** : CSP sans `unsafe-*` ni origine externe (existant) ; capacités limitées à `core:default` et, sur mobile, au scanner (test qui lit `capabilities/*.json`) ; règle ESLint `vue/no-v-html` en erreur et test qui refuse `v-html` et `innerHTML` dans `src/` ; aucun plugin `fs`, `shell`, `http` dans `Cargo.toml` ni `package.json` (test) | Exigences « CSP stricte », « capacités inutiles désactivées », « échappement des champs issus des logs » |
| **Vue des logs** (écran Trafic des maquettes : robots vus, IP suspectes, charge, règles dépassées) alimentée par `GET /api/v1/sites/{id}/logs` et `…/logs/ips` (#5) ; champs issus des logs affichés par interpolation de texte seulement ; état « pas encore disponible » gardé pour un site sans source de logs (404 de l'API) | Exigence « vue logs » ; principe 5 du HANDOFF (aucune donnée inventée) |
| Listes paginées : incidents clos d'un site et verdicts d'IP par « Afficher plus » (`next_cursor`) ; 429 de l'API affiché comme « trop de requêtes, réessayer dans N s » sans relance automatique | Pagination de #5 ; pas de boucle qui aggrave une limite de débit |
| Aucune écriture nouvelle : la console propose, ne fait jamais d'application ; l'acquittement reste la seule écriture | Exigence « la GUI propose, ne fait jamais d'application automatique » |
| Version 0.2.0 de la console ; release par le workflow existant (tags `console-v*`), publiée par l'exploitant | Releases déjà en place |
