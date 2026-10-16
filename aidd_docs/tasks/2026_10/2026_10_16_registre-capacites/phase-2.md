---
status: pending
---

# Instruction: Tests d'extrémité et audit du chemin critique

## Architecture projection

```txt
.
└── vigie/
    ├── tests/
    │   ├── config_edges.rs   ✅ kind et runtime aux limites
    │   └── store_concurrency.rs ✏️ serve + tick + lots de logs en contention
    └── docs/
        ├── audit-chemin-critique.md ✅ chaque point, sa preuve ou « non vérifié »
        └── decisions.md      ✏️ section #4
```

## Tasks to do

1. Tests de configuration aux limites (kind vide, casse, inconnu ; runtime contradictoire).
2. Délais de l'agent : `agent_e2e` avec un serveur qui ne répond pas (`SEND_TIMEOUT`) et un verrou déjà pris.
3. Contention : quatre écrivains (rapport, retrait, lot de logs, tick) sur une même base, aucun `SQLITE_BUSY` remonté, aucune écriture perdue.
4. Audit écrit, avec renvoi aux tests et aux jobs CI ; relevé masqué sur le VPS (`--version`, `tick` à blanc, empreinte du binaire de la CI) ou « non vérifié ».

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Tests verts sur Linux et Windows en CI |
| 3 | Chaque ligne de l'audit cite un test, un job CI ou porte « non vérifié » et l'action à faire |
