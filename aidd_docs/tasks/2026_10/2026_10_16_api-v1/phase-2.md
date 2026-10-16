---
status: pending
---

# Instruction: Pagination et lecture de l'analyse des logs

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── api/page.rs       ✅ limit, cursor opaque (base64url), Page<T>
    │   ├── api.rs            ✏️ incidents paginés ; /sites/{id}/logs et /sites/{id}/logs/ips
    │   └── store.rs          ✏️ lectures keyset (incidents clos, verdicts d'IP)
    ├── tests/api_read.rs     ✏️ pagination, compatibilité 0.1.1, analyse
    └── docs/
        ├── api-console.md    ✏️ pagination, 429, 415, routes logs, journal
        └── decisions.md      ✏️ section #5 (pas de mTLS, débit, CORS, assainissement)
```

## Tasks to do

1. `Page<T>` et curseur : `(closed_at, id)` pour les incidents, `(score, ip)` pour les verdicts ; `limit` 1..100.
2. `GET /api/v1/sites/{id}/incidents` : `incidents` (première page) + `next_cursor`.
3. Routes logs : lecture des agrégats et de l'`Analysis` de #8 en lecteur ; 404 pour un site sans source.
4. Docs.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | 120 incidents clos : 3 pages de 50/50/20, sans doublon ni trou, même si un incident se ferme entre deux pages ; curseur forgé → 400 ; réponse sans paramètre identique pour les champs lus par la console 0.1.1 |
| 3 | Site avec analyse : robots, règles et charge ; verdicts paginés triés par score ; site sans source → 404 uniforme |
