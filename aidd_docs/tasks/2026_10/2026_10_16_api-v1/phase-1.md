---
status: pending
---

# Instruction: Garde-fous transverses : débit, journal, en-têtes, DTO

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── api/limit.rs      ✅ seaux à jetons bornés, IP cliente (proxy local seulement)
    │   ├── api.rs            ✏️ couche de journal et d'en-têtes, 415, OPTIONS, sanitize des champs de logs
    │   ├── error.rs          ✏️ ErrorCode::UnsupportedMediaType, BadRequest ; Retry-After sur 429
    │   └── config.rs         ✏️ 200 sites au plus
    └── tests/
        └── api_guards.rs     ✅ débit, journal, en-têtes, CORS, 415, liste blanche des DTO
```

## Test Scope

```mermaid
journey
  section Happy path
    Appareil sous la limite => 200, en-têtes stricts, une ligne de journal: 5: api
  section Edge case
    31e appel en rafale => 429, Retry-After, format uniforme: 1: api
    11 appairages ratés d'une IP en une minute => 429 au 11e: 1: api
    X-Forwarded-For d'un pair autre que 127.0.0.1 => ignoré: 1: api
    OPTIONS avec Origin => 404 sans en-tête CORS: 1: api
    POST pair en text/plain => 415: 1: api
    Réponse de chaque route sur base peuplée => aucun champ secret: 1: api
    UA avec ESC et U+202E => U+FFFD dans le DTO: 1: api
```

## Tasks to do

1. `limit.rs` : seau à jetons par clé (`Device(id)` ou `Ip(addr)`), `FakeClock` dans les tests ; table bornée à 4 096 clés.
2. Couche Tower sur `/api/v1` : journal (gabarit de route via `MatchedPath`), en-têtes, `OPTIONS` → 404.
3. 415 sur `POST` mal typé ; corps refusé sur `ack`.
4. `sanitize_log_text` partagé, utilisé par tout DTO qui porte un champ issu d'un log.
5. Test de liste blanche des DTO.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-5 | Chaque cas du Test Scope est un test ; la console 0.1.1 (requêtes de `vigie/app/src-tauri`) reste acceptée |
