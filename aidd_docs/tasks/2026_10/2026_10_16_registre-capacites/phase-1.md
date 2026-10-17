---
status: done
---

# Instruction: Registre unique et filtrage partout

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── capability.rs     ✏️ Control (dont Integrity, Logs), AgentFamily, exigences, watched, allowed_controls
    │   ├── checks/mod.rs     ✏️ CheckKind sans cms ; applies délègue au registre
    │   ├── report.rs         ✏️ familles fermées ; constat hors registre écarté et compté
    │   ├── ingest.rs         ✏️ reçoit &Site, filtre, compte des écartés
    │   ├── serve.rs          ✏️ configuration typée des sites dans l'état
    │   ├── store.rs          ✏️ prochaine migration libre ; accept_report filtré par watched ; reports.dropped ; e-mail « plus surveillé »
    │   ├── alert.rs          ✏️ e-mail « plus surveillé »
    │   ├── tick.rs           ✏️ close_unwatched par watched
    │   ├── api.rs            ✏️ contrôles affichés par allowed_controls
    │   └── main.rs           ✏️ status et site list par le registre
    └── tests/
        └── capability.rs     ✅ matrice kind × runtime × contrôle × commande
```

## Tasks to do

1. Registre et `match` sans joker ; suppression de `CheckKind::cms`.
2. Familles fermées `Root`, `CriticalFile`, `MustContain`, `UploadsPhp` ; `integrity` réservé (rapport refusé) ; écart compté à l'ingestion ; test contre les `finding('…'` de l'agent et la fixture signée.
3. `watched` utilisé par tick, ingestion, API, CLI.
3bis. Migration (prochaine libre) (`dropped`, `close_reason`) ; e-mail selon la raison ; incident `typology` pour une clé d'agent sur un site sans runtime `php` ; `site add`/`rotate-key` refusés pour un tel site.
4. Tests : migration d'une base de la version précédente ; e-mail de `close_unwatched` sans « rétabli » ; site `generic` sans runtime avec clé : incident `typology` ouvert, toujours ouvert après deux `tick`, clos « rétabli » après `runtime = "php"` ; matrice complète ; même verdict API / tick / ingestion ; base avec un incident ouvert `agent:<famille-retirée>` : clos « plus surveillé », jamais rouvert ; famille écartée : ni « rétabli » ni passage « ok » ; clé d'agent sur un site `static` : aucun contrôle d'agent, seulement l'incident `typology` ; une commande valide pour `php` refusée pour `static` et `node` ; `installer` seulement WordPress et PrestaShop ; `agent:uploads-php` d'un site `generic` écarté ; un incident `agent:*` clos quand la clé d'agent est retirée ; `logs` gardé seulement avec une source.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-4 | Chaque cas de la tâche 4 est un test ; le rejeu du 2026-09-07 (`tests/replay_2026_09_07.rs`) passe inchangé |
