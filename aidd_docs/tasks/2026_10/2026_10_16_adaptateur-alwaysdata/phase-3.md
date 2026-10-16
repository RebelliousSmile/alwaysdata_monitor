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
        ├── protocole-agent.md ✏️ /r/v1/logs et vigie-logs-v1 dans la liste des points d'entrée et des domaines
        ├── agent-php.md       ✏️ configuration logs
        └── decisions.md       ✏️ section #1 (RGPD : rien de brut stocké ; plafonds)
```

## Tasks to do

1. `AlwaysdataSource::fetch(from, max)` : `WHERE site = ? AND id > ? ORDER BY id LIMIT max + 1` (`more` si une de plus) ; curseur illisible → `CursorInvalid { restart: start }` ; `rejected` vide (les rejets restent comptés dans `log_batches`).
2. Purge à chaque `tick` : entrées dont l'heure < now − 30 j ; lots et limites dont `received_at` < now − 30 j.
3. Test de bout en bout sur les fixtures de #7 : mêmes comptes que `expected.json`.
4. `agent_e2e.rs` : un lot de logs de l'agent PHP réel jusqu'à `log_entries`, renvoi après réponse perdue compté une fois.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Deux lectures successives depuis le curseur rendu ne rendent jamais deux fois une entrée ; purge totale puis nouveau lot : `fetch` depuis l'ancien curseur rend les nouvelles entrées |
| 2 | Avec une `FakeClock` à J+31, plus aucune entrée du jour J |
| 3 | Les comptes de `expected.json` tiennent par le chemin complet |
