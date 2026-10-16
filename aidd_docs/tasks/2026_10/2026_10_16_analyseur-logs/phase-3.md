---
status: pending
---

# Instruction: Signatures partagées et branchement à tick

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/000N.sql   ✅ log_signatures (kind ip|ua, value, site, score, seen_at, expires_at)
    ├── src/
    │   ├── store.rs          ✏️ note, lecture et purge des signatures (30 j)
    │   ├── analysis/shared.rs ✅ bonus de 15 points et mention pour une signature vue ailleurs
    │   └── tick.rs           ✏️ par site ayant une source : lots bornés depuis le curseur, analyse, reconcile sous `logs`, curseur et entrées dans la même transaction
    └── docs/
        ├── logs.md           ✏️ section analyse : règles, ordre, constats, partage
        └── decisions.md      ✏️ section #8
```

## Tasks to do

1. Une IP au score ≥ 70 sur un site, ou un UA de classe `Tool`/`AiTraining` au-delà du seuil `repeated-ip`, est noté ; la note expire au bout de 30 jours, purgée par `tick`.
2. L'analyse d'un autre site lit les signatures actives (hors son propre site) et applique le bonus, sans incident propre.
3. `tick` : `LogSource` par site déclaré dans la configuration (aucune tant que #1 n'est pas livrée) ; `fetch` par lots de 5 000 tant que `more`, dans le budget du passage.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Une IP nuisible sur le site A, vue avec un comportement moyen (score 55) sur le site B, y passe à 70 avec la mention ; au bout de 30 jours (`FakeClock`), plus de bonus |
| 3 | Deux `tick` successifs sur une `MemorySource` ne comptent jamais deux fois une entrée |
