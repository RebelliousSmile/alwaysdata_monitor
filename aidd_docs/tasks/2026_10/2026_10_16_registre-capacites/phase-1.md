---
status: pending
---

# Instruction: Registre unique et filtrage partout

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── capability.rs     ✏️ Control, AgentFamily, exigences, watched, allowed_controls
    │   ├── checks/mod.rs     ✏️ CheckKind sans cms ; applies délègue au registre
    │   ├── report.rs         ✏️ familles fermées ; constat hors registre écarté et compté
    │   ├── ingest.rs         ✏️ compte des constats écartés au journal
    │   ├── tick.rs           ✏️ close_unwatched par watched
    │   ├── api.rs            ✏️ contrôles affichés par allowed_controls
    │   └── main.rs           ✏️ status et site list par le registre
    └── tests/
        └── capability.rs     ✅ matrice kind × runtime × contrôle × commande
```

## Tasks to do

1. Registre et `match` sans joker ; suppression de `CheckKind::cms`.
2. Familles d'agent fermées ; écart compté à l'ingestion.
3. `watched` utilisé par tick, ingestion, API, CLI.
4. Tests : matrice complète ; une commande valide pour `php` refusée pour `static` et `node` ; `installer` seulement WordPress et PrestaShop ; `agent:uploads-php` d'un site `generic` écarté ; un incident `agent:*` clos quand la clé d'agent est retirée ; `logs` gardé seulement avec une source.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-4 | Chaque cas de la tâche 4 est un test ; le rejeu du 2026-09-07 (`tests/replay_2026_09_07.rs`) passe inchangé |
