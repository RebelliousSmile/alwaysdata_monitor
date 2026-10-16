---
objective: "L'API /api/v1 de la console, déjà en service (appairage, lecture, acquittement), satisfait toutes les exigences de sécurité de l'issue #5 : débit limité et journal des appels, pagination de toute liste qui croît, en-têtes stricts sans CORS, DTO dont aucun champ secret ne peut sortir, champs issus des logs assainis, lecture de l'analyse des logs ; et la décision de ne pas faire de mTLS est écrite."
status: pending
issue_number: 5
---

# Plan: API /api/v1, exigences de sécurité

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Fermer l'issue #5 sur l'API existante (`vigie/src/api.rs`, `device.rs`, `docs/api-console.md`) sans casser la console 0.1.1 en service |
| **Source** | Issue GitHub #5 ; `vigie/docs/api-console.md` ; `vigie/docs/decisions.md` ; plan `2026_10_16_console-vigie` (jeton par appareil, fichier privé de l'application) ; socle #9 (`error.rs`, `request_id.rs`, `Clock::monotonic`) ; analyse des logs #8 |

## Phases

| #   | Phase                                              | File                         |
| --- | -------------------------------------------------- | ---------------------------- |
| 1   | Garde-fous transverses : débit, journal, en-têtes, DTO | [`phase-1.md`](./phase-1.md) |
| 2   | Pagination et lecture de l'analyse des logs        | [`phase-2.md`](./phase-2.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| **Pas de mTLS ni de bind sur 127.0.0.1** : l'API reste derrière Caddy (TLS Let's Encrypt), authentifiée par un jeton d'appareil de 32 octets aléatoires, conservé en SHA-256, comparé en temps constant (`device::ct_eq`), révocable un par un. Le jeton vit dans le fichier privé de l'application (pas de trousseau commun à Windows et Android ; stronghold exige un mot de passe à chaque ouverture) et ne passe jamais au webview | Un téléphone hors du VPS doit joindre l'API ; un certificat client par appareil sous Android et Windows coûte plus qu'il n'apporte face à un jeton aléatoire révocable. L'issue admet l'une ou l'autre voie ; celle-ci est déjà en service et écrite dans le plan de la console |
| **Limite de débit en mémoire de `serve`** : seau à jetons par appareil authentifié (120 appels par minute, rafale 30) et par IP cliente pour ce qui précède l'authentification (`/api/v1/pair` et tout 401 : 10 par minute) ; au-delà, 429 au format d'erreur uniforme avec `Retry-After`. Table bornée (4 096 clés, la plus ancienne évincée), horloge `Clock::monotonic`. L'IP cliente est l'adresse de la connexion, sauf si elle vient de `127.0.0.1` (Caddy) : alors la dernière valeur de `X-Forwarded-For` | Freine le forçage des codes et des jetons et un appareil emballé, sans état persistant ; un en-tête n'est cru que du proxy local |
| **Journal des appels** : une ligne par appel de `/api/v1` sur la sortie de `serve` (journald) : request_id, appareil (id) ou `-`, méthode, gabarit de route (`/api/v1/sites/{id}`, jamais le chemin brut ni la query), statut, durée en ms. Jamais de jeton, de code d'appairage ni d'en-tête | Traçabilité exigée par l'issue, sans données sensibles ni valeurs venues du client |
| **En-têtes stricts** sur toute réponse de `/api/v1` : `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, aucun en-tête CORS. `OPTIONS` (préflight) → 404 uniforme. Un `POST` dont le `Content-Type` n'est pas `application/json` (paramètres admis) → 415 au format uniforme (`ErrorCode::UnsupportedMediaType`) ; un `POST` sans corps attendu (`ack`) refuse un corps non vide | La console appelle depuis Rust (reqwest) : aucun navigateur n'a à être autorisé ; pas de CSRF par formulaire simple |
| **DTO à liste blanche vérifiée par test** : les structs de réponse restent dédiées (`api.rs`) ; un test parcourt la réponse JSON de chaque route sur une base peuplée (appareils, clés d'agents, commandes, audit) et refuse toute clé nommée `token`, `hash`, `secret`, `pubkey`, `key`, `seed`, `signature`, `code` hors liste admise, et toute valeur égale à un secret de la base | Une régression qui sérialiserait une struct du store se voit en CI |
| **Champs issus des logs assainis** : user-agent, chemin, referer passent dans les DTO par une fonction unique qui remplace les caractères de contrôle (C0, C1, DEL, U+2028/2029, bidi) par U+FFFD et tronque (UA 512, chemin 512 caractères). L'échappement HTML relève du rendu de la console (#12 : jamais `v-html`) | Le JSON échappe déjà les guillemets ; il reste l'injection de terminal et de journal et le texte trompeur bidi |
| **Pagination par clé (keyset)** de toute liste qui croît : incidents clos d'un site, verdicts d'IP, robots vus, dépassements de règles. Paramètres `limit` (1 à 100, défaut 50) et `cursor` opaque (base64url du dernier tri) ; réponse `{…, "items": […], "next_cursor": … \| null}`. Curseur illisible → 400 `bad_request`. Les listes bornées par la configuration (sites, contrôles d'un site) ne se paginent pas ; `config.toml` refuse plus de 200 sites | Exigence de l'issue ; un curseur par clé reste stable quand des incidents se ferment pendant la lecture |
| Compatibilité : la console 0.1.1 lit `incidents` dans `GET /api/v1/sites/{id}/incidents` ; la réponse garde `incidents` (première page) et ajoute `next_cursor`. Aucun champ existant ne change de sens | Pas de mise à jour forcée des appareils appairés |
| **Lecture de l'analyse** : `GET /api/v1/sites/{id}/logs` rend la dernière `Analysis` de #8 (heure de référence, charge par heure sur 24 h, robots vus avec métadonnées, dépassements de règles) et `GET /api/v1/sites/{id}/logs/ips` la liste paginée des verdicts d'IP (score, niveau, raisons, classe). Lecture seule ; 404 uniforme pour un site sans source de logs | Exigence « logs » de l'issue ; l'exploitant voit ce que #13 proposera |
| Écriture : seul l'acquittement existe ; toute route d'écriture future passe par les garde-fous de #10 (commande explicite, aperçu, `--apply`) et n'est pas dans cette issue | Exigence de l'issue (« écriture ensuite ») |
