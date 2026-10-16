---
status: done
---

# Instruction: Point d'entrée /r/v1/commands

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── command/pull.rs   ✅ schéma du retrait et de la réponse, vérifications dans l'ordre, résultat, réponse signée
    │   └── serve.rs          ✏️ route POST /r/v1/commands, mêmes limites que /r/v1/report ; chemin de la configuration pour la relire
    └── tests/
        └── commands.rs       ✅ retrait, résultat et accusé, rejeu, horloge, clés absentes, configuration modifiée, attaquant installé sur le site
```

## User Journey

```mermaid
sequenceDiagram
  participant A as Agent (site)
  participant V as Veilleur
  A->>V: POST /r/v1/commands {v,type:pull,site,seq,sent_at,nonce,agent,result?} + X-Vigie-Site + X-Vigie-Signature (clé de l'agent, préfixe vigie-pull-v1)
  V->>V: taille, site connu, signature, schéma, horloge ±300 s, seq de retrait croissant, débit
  V->>V: result ? toujours accusé (acked) ; accepted selon l'état de la commande ; audit (tick enverra la tête de chaîne)
  V->>V: configuration relue ; [commands], clé, site activé, permit, disponible, non expirée ?
  V-->>A: 200 {v,site,nonce,server_time,acked,accepted,command|null} + X-Vigie-Timestamp + X-Vigie-Signature (clé de commandes)
```

## Test Scope

```mermaid
journey
  section Happy path
    ping en file, retrait => 200, enveloppe signée, served: 5: api
    retrait suivant avec result ok => done, acked = id, command null: 5: api
    même résultat renvoyé (accusé perdu) => acked de nouveau, aucune nouvelle entrée d'audit: 5: api
    résultat pour une commande expirée, annulée, inconnue ou d'un autre site => acked, accepted faux, audit: 1: api
    résultat tardif d'une commande unknown (hors rotate-key) => done, accepted vrai: 1: api
  section Edge case - rejeu et contrat
    retrait rejoué => 404 ; retrait signé sans préfixe ou rapport sur cette route => 404: 1: api
    X-Vigie-Site B avec la clé de A => 404 ; résultat pour la commande d'un autre site => refusé, audit: 1: api
    réponse : signature vérifiée sur préfixe, horodatage et octets ; X-Vigie-Timestamp = server_time: 1: api
  section Edge case - fail-closed
    [commands] absent ou clé absente => 404 ; site désactivé => command null signé: 1: api
    runtime retiré de config.toml après enqueue, sans relancer serve => refused, jamais servie: 1: api
    commande expirée non encore purgée par tick => non servie: 1: api
  section Edge case - attaquant sur le site
    champ command ou params ajouté au retrait => 404 (schéma): 1: api
    rotate-key avec une preuve signée par une autre clé que celle annoncée, ou une clé égale à l'ancienne ou à celle d'un autre site => refused, clé inchangée: 1: api
    preuve valide arrivée après `site rotate-key` par la CLI => clé de la CLI conservée, accepted faux: 1: api
    résultat tardif de rotate-key sur une commande unknown => accepted faux, failed, clé inchangée: 1: api
    clé d'audit illisible => 404, résultat non accusé: 1: api
    site retiré de config.toml sans relancer serve => 404: 1: api
    aucun chemin ne crée une commande: 1: api
```

## Tasks to do

1. Retrait (`deny_unknown_fields`) : `v`=1, `type`=`pull`, `site`, `seq`, `sent_at`, `nonce` (22 à 64 caractères base64url), `agent`, `result` facultatif (`command_id`, `status` `ok`/`failed`/`refused`, `detail`, `data` typé par commande).
2. Ordre des vérifications calqué sur `ingest.rs` ; refus → 404 commun, raison au journal avec request_id. Un retrait refusé ne consomme rien côté agent.
3. Réponse `{v, site, nonce, server_time, acked, accepted, command}` (`command` : enveloppe de `protocole-commandes.md`) ; `X-Vigie-Timestamp`, `X-Vigie-Signature`, `Cache-Control: no-store`. Signature calculée dans `spawn_blocking`.
4. Commande `served` non close et non expirée : re-servie identique (même `id`, même `seq`).
5. `rotate-key` : preuve de possession vérifiée, bascule de la clé et remise à zéro des `seq` dans la transaction qui clôt la commande.
6. Débit : un retrait accepté par site et par 30 s.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-6 | Chaque cas du Test Scope est un test d'intégration sur le routeur de `serve` |
