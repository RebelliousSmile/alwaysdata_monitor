---
status: pending
---

# Instruction: LogSource Alwaysdata, rétention et contrat écrit

## Architecture projection

```txt
.
└── vigie/
    ├── src/logs/alwaysdata.rs ✅ AlwaysdataSource : LogSource sur log_entries d'un site, curseur = dernier id servi
    ├── src/tick.rs            ✏️ purge des entrées et lots de plus de 30 jours
    ├── tests/logs_contract.rs ✏️ fixtures de #7 passées par le chemin complet (lot signé → base → AlwaysdataSource)
    └── docs/
        ├── logs.md            ✏️ transport /r/v1/logs, identité des lots, rétention
        ├── protocole-agent.md ✏️ renvoi vers /r/v1/logs
        ├── agent-php.md       ✏️ configuration logs
        └── decisions.md       ✏️ section #1 (RGPD : rien de brut stocké ; plafonds)
```

## Tasks to do

1. `AlwaysdataSource::fetch(from, max)` : entrées d'id supérieur au curseur, dans l'ordre des id, `max` au plus, `more` ; curseur illisible → `CursorInvalid { restart: start }`.
2. Purge à chaque `tick` (heure de l'entrée < now − 30 j ; lots sans entrée restante).
3. Test de bout en bout sur les fixtures de #7 : mêmes comptes que `expected.json`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Deux lectures successives depuis le curseur rendu ne rendent jamais deux fois une entrée |
| 2 | Avec une `FakeClock` à J+31, plus aucune entrée du jour J |
| 3 | Les comptes de `expected.json` tiennent par le chemin complet |
