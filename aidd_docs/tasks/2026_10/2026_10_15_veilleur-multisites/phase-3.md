---
status: pending
---

<!-- Fill or omit these sections; never add, rename, or reorder one. -->

# Instruction: Point d'entrée des rapports signés et silence des agents

## Architecture projection

> Tree of the final files. ✅ create · ✏️ modify · ❌ delete

```txt
monitor/
├── Cargo.toml                         ✏️ ed25519-dalek, base64, serde_json, tower-http (limite de corps, délai)
├── docs/protocole-agent.md            ✅ format du rapport v1, en-têtes, règles d'acceptation, rotation de clé
└── src/
    ├── main.rs                        ✏️ site add <id> --pubkey, site list, site rotate-key, site remove
    ├── store.rs                       ✏️ migrations : site_keys, reports (dernier seq, dernier rapport valide)
    ├── report.rs                      ✅ schéma du rapport v1 (serde, deny_unknown_fields), conversion en Finding
    ├── ingest.rs                      ✅ vérification de la signature, de l'horodatage, du seq et du débit
    ├── serve.rs                       ✏️ POST /r/v1/report, limite de 64 Ko, délai de 10 s, réponse 404 muette en cas d'échec
    └── checks/heartbeat.rs            ✅ dans tick : un agent muet au-delà du seuil ouvre un incident critique
└── tests/
    ├── ingest.rs                      ✅ rapports valides, falsifiés, rejoués, périmés et surdimensionnés
    └── fixtures/rfc8032.json          ✅ vecteurs de test ed25519, qui garantissent la compatibilité avec libsodium
```

## User Journey

```mermaid
flowchart TD
  A[Agent : POST /r/v1/report, corps JSON, en-têtes site + signature] --> B{Site connu et taille ≤ 64 Ko ?}
  B -->|non| Z[404 muet, raison journalisée côté veilleur]
  B -->|oui| C{Signature ed25519 valide sur les octets reçus ?}
  C -->|non| Z
  C -->|oui| D{sent_at dans ±300 s et seq > dernier seq ?}
  D -->|non| Z
  D -->|oui| E[Rapport stocké, constats de l'agent convertis en incidents « à notifier »]
  E --> F[204]
  G[monitor tick] --> N[E-mails des incidents « à notifier »]
  G --> H{Dernier rapport valide plus vieux que le seuil ?}
  H -->|oui| I[Incident critique « agent silencieux » + e-mail]
```

## Test Scope

```mermaid
---
title: Test scope
---
journey
  section Setup
    Paire de clés de test et site enregistré via monitor site add => clé publique en base: 5: cli
  section Happy path
    Rapport signé, seq 1, horodatage courant => POST => 204 et rapport stocké: 5: api
    Rapport signé portant un constat critique => POST puis monitor tick => incident ouvert, un e-mail envoyé par tick et aucun par serve: 5: api
    Rapport suivant sans ce constat => POST puis monitor tick => incident clos, e-mail de retour à la normale: 5: api
  section Edge case - signature falsifiée
    Un octet du corps modifié après signature => POST => 404 et rien de stocké: 1: api
  section Edge case - rejeu
    Même rapport renvoyé à l'identique => POST => 404 car seq non croissant: 1: api
  section Edge case - horloge décalée
    sent_at décalé de 10 min => POST => 404: 1: api
  section Edge case - corps trop gros
    Corps de 100 Ko => POST => refus avant toute vérification de signature: 1: api
  section Edge case - site inconnu
    En-tête de site absent de la base => POST => même réponse 404 qu'une signature fausse: 1: api
  section Edge case - agent silencieux
    Dernier rapport vieux de plus de 15 min => monitor tick => incident « agent silencieux » et e-mail: 1: cli
  section Teardown
    Suppression de la base temporaire => état initial: 5: system
```

## Tasks to do

### `1)` Protocole v1

> Écrire le contrat avant le code, parce que c'est la pièce la plus exposée.

1. Rédiger `monitor/docs/protocole-agent.md` :
   - en-têtes `X-Monitor-Site` et `X-Monitor-Signature` (base64 de la signature détachée sur les octets bruts du corps) ;
   - corps JSON `{ v, site, seq, sent_at, agent, findings[], facts{} }`.
2. Règles d'acceptation : le site du corps est égal à celui de l'en-tête, horodatage dans ±300 s, `seq` strictement croissant, au plus un rapport accepté par site et par 60 s.
3. Rotation : `site rotate-key` remplace la clé publique. L'ancienne est refusée dès la rotation.

### `2)` Gestion des clés de site

> La clé privée reste sur le site. Le veilleur ne garde que des clés publiques.

1. `monitor site add <id> --pubkey <base64>` : vérifier que la clé fait 32 octets et refuser un id déjà pris.
2. `site list`, `site remove` (avec une confirmation sans `--yes`), `site rotate-key`.

### `3)` Ingestion

> Refuser tôt, refuser pareil et journaliser la vraie raison.

1. Ordre des vérifications : taille, site connu, signature, schéma, horodatage, `seq`, débit.
2. Tout refus renvoie la même réponse 404 sans corps. La raison n'est écrite que dans le log du veilleur.
3. Pour un rapport accepté : enregistrer `seq` et la date du dernier rapport valide, puis faire passer les constats dans le cycle des incidents de la phase 2, en préfixant leurs contrôles par `agent:`. Les incidents ouverts ou clos ici restent « à notifier » : `serve` n'appelle jamais le `Notifier`, c'est le passage suivant de `tick` qui notifie.

### `4)` Silence d'agent

> Un agent qui se tait est lui-même un signal.

1. Dans `tick`, ouvrir un incident critique « agent silencieux » pour tout site dont l'agent est déclaré et dont le dernier rapport valide dépasse `agent_silence`, par défaut 15 min (soit trois passages de 5 min manqués).
2. Le premier rapport valide qui suit clôt cet incident.

### `5)` Durcissement du point d'entrée

> Exposer le moins de surface possible.

1. Les seules routes sont `/health` et `/r/v1/report`. Tout le reste reçoit une réponse 404.
2. La limite de corps et le délai de 10 s s'appliquent avant toute lecture du JSON.
3. Le log ne contient jamais de corps de rapport, seulement le site, `seq` et la raison.

## Test acceptance criteria

| Task | Acceptance criteria              |
| ---- | -------------------------------- |
| 1    | `protocole-agent.md` décrit les en-têtes, le schéma v1 et les règles d'acceptation, et les tests d'ingestion en reprennent chaque règle |
| 2    | Une clé publique qui ne fait pas 32 octets est refusée. Après `rotate-key`, un rapport signé avec l'ancienne clé est refusé |
| 3    | Les vecteurs RFC 8032 sont vérifiés. Un rapport falsifié, rejoué, périmé, surdimensionné ou d'un site inconnu reçoit la même réponse 404 et n'est pas stocké. Un constat critique accepté produit exactement un e-mail, envoyé par `tick` |
| 4    | Un site sans rapport depuis plus de 15 min a un incident critique ouvert. Le rapport valide suivant le clôt |
| 5    | Une requête vers une route non déclarée renvoie 404. Le log d'un refus ne contient pas le corps reçu |
