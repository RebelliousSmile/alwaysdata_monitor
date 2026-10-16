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

0. Prérequis : #8 phase 3 fusionnée (instantané `log_analysis` / `log_verdicts`).
1. `Page<T>` et curseur : `(closed_at, id)` pour les incidents (SQL, index), `(generated_at, score, ip)` pour les verdicts ; `limit` 1..100 sinon 400 ; curseur ≤ 256 caractères ; 409 `cursor_expired`.
2. `GET /api/v1/sites/{id}/incidents` : `incidents` (première page) + `next_cursor`.
3. Routes logs : lecture de l'instantané de #8 en lecteur ; `{"analysis": null}` pour un site avec source sans analyse ; 404 pour un site sans source ; verdicts en liste blanche (moyen et élevé seulement).
4. Docs.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | 120 incidents clos : 3 pages de 50/50/20 sans doublon ; un incident clos pendant le parcours n'est pas revu et aucun autre ne manque ; curseur forgé ou trop long → 400 ; `limit=0` ou `101` → 400 ; champs lus par la console 0.1.1 présents |
| 3 | Site avec analyse : robots, règles et charge ; verdicts paginés triés par score, sans UA ni chemin ; page 2 lue après un nouveau `tick` → valide ; instantané purgé → 409 `cursor_expired` ; `FakeClock` à 48 h + 1 → `/logs/ips` vide ; site avec source sans analyse → `null` ; site sans source → 404 uniforme |
