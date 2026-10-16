---
status: pending
---

# Instruction: Garde-fous transverses : débit, journal, en-têtes, DTO

## Architecture projection

```txt
.
└── vigie/
    ├── src/
        │   ├── api/limit.rs      ✅ deux tables de seaux (appareils, IP /64), IP cliente (boucle locale seulement)
    │   ├── api/log_text.rs   ✅ LogText : seul constructeur assainissant
    │   ├── serve.rs          ✏️ into_make_service_with_connect_info
    │   ├── api.rs            ✏️ couche de journal et d'en-têtes, 415, OPTIONS, sanitize des champs de logs
    │   ├── error.rs          ✏️ ErrorCode::UnsupportedMediaType, BadRequest, CursorExpired (409) ; Retry-After sur 429
    ├── app/eslint.config.js  ✏️ vue/no-v-html en erreur
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
    31e appel en rafale d'un appareil => 429, Retry-After, format uniforme: 1: api
    11 appairages d'une IP en une minute => 429 au 11e: 1: api
    Seau d'IP vide, requête à jeton valide => 200: 1: api
    5 000 IP arrosées puis l'attaquant => toujours limité: 1: api
    Deux IPv6 du même /64 => même seau: 1: api
    X-Forwarded-For d'un pair hors boucle locale => ignoré ; à plusieurs valeurs depuis la boucle => dernière: 1: api
    Requêtes exactes de la console 0.1.1 (pair, ack sans corps, GET, DELETE) => réponses inchangées: 1: api
    OPTIONS avec Origin => 404 sans en-tête CORS: 1: api
    POST pair en text/plain => 415 ; ack avec corps annoncé => 415: 1: api
    Clé JSON nouvelle dans une route => test d'instantané en échec: 1: api
    Valeurs semées (jeton, code, pubkey, signatures, mot de passe SMTP) => absentes de toute réponse: 1: api
    ESC et U+202E dans le détail d'un incident logs lu via /overview => U+FFFD: 1: api
```

## Tasks to do

1. `limit.rs` (règles du plan), `ConnectInfo` câblé dans `serve`, `FakeClock` dans les tests ; l'extracteur scinde recherche du jeton et `touch_seen` pour appliquer la limite entre les deux.
2. Couche Tower sur `/api/v1`, extérieure à `request_id` : journal (gabarit via `MatchedPath`, regroupement des 429), en-têtes ; test `OPTIONS` → 404.
3. 415 seulement pour un `POST` à corps mal typé.
4. `LogText` utilisé par tout DTO d'origine log, `detail` des incidents `logs` compris.
5. Instantané des clés JSON et recherche de valeurs semées.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-5 | Chaque cas du Test Scope est un test ; la console 0.1.1 (requêtes de `vigie/app/src-tauri`) reste acceptée |
