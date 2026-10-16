---
status: done
---

# Instruction: Clés, file et audit en base

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/0008.sql   ✅ command_sites (site, enabled, last_pull_seq, last_command_seq), commands (+ index unique partiel des commandes non closes), command_audit (+ déclencheurs append-only), audit_notified (site, last_hash)
    └── src/
        ├── clock.rs          ✏️ Clock::unix_ms
        ├── capability.rs     ✏️ CommandKind::available() : htaccess-* indisponibles jusqu'à #13 ; non_idempotent()
        ├── config.rs         ✏️ [commands] key_file, audit_key_file (chemins absolus)
        ├── command/
        │   ├── mod.rs        ✅ Command, Params et Outcome typés par commande, états et transitions, UUIDv7
        │   ├── key.rs        ✅ lecture sûre d'une clé (0600, dossier 0700, propriétaire, O_NOFOLLOW), création exclusive, signature par domaine
        │   └── audit.rs      ✅ entrée, chaîne par site, signature, vérification, export JSONL
        ├── store.rs          ✏️ file, activation, seq, expiration, audit, remise à zéro par remove/rotate-key
        └── lib.rs            ✏️ déclare command
```

## Test Scope

```mermaid
journey
  section Happy path
    enqueue ping (site php activé) => pending, seq 1, audit created: 5: store
    serve, puis résultat ok => served puis done, audit chaîné et signé: 5: store
  section Edge case
    enqueue avec une commande non close, même par deux connexions => une seule réussit: 1: store
    enqueue htaccess-apply => refus « indisponible »: 1: store
    site désactivé ou absent de [commands] => refus: 1: store
    pending à 24 h + 1 s => expired ; served sans résultat à 24 h => unknown: 1: store
    rotate-key après unknown sans --force => refus: 1: store
    UPDATE ou DELETE sur command_audit => erreur SQLite: 1: store
    clé en 0644, dossier en 0755, lien symbolique => lecture refusée: 1: key
    entrée d'audit altérée ou chaîne tronquée sous une tête attendue => vérification en échec: 1: audit
    site remove puis site add => enabled faux, commande en vol annulée: 1: store
```

## Tasks to do

1. `Clock::unix_ms` (SystemClock en ms, FakeClock en ms) ; UUIDv7 : 48 bits d'heure, version 7, variante RFC 9562, 74 bits de `getrandom`.
2. États : `pending → served → done | failed | refused` ; `pending → expired | refused` (refusée à la délivrance : la configuration ne l'admet plus) ; `pending | served → cancelled` ; `served → unknown → done | failed` (résultat tardif) ; toute autre transition est une erreur.
3. Migration 0008 tolérée par l'ancien `serve` (aucune exigence nouvelle de version pour l'API de la console).
4. Clés : 32 octets de graine Ed25519 en base64, une par fichier ; vérifications Unix (droits, propriétaire, dossier), refus sous Windows hors tests.
5. Audit : entrées `{site, at, event, command_id, detail, typology}` sérialisées une fois, octets stockés tels quels ; premier `prev_hash` à 32 zéros par site.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-3 | Les transitions interdites échouent ; deux commandes non closes sur un site sont impossibles |
| 4 | Aucune clé n'est lue dans un état dangereux ni écrasée |
| 5 | Toute altération est détectée à son entrée ; une troncature l'est contre la tête attendue |
