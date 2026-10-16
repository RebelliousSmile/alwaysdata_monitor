---
status: done
---

# Instruction: Exécution, résultat, rotate-key, tests

## Architecture projection

```txt
.
├── vigie/agent/php/
│   ├── vigie-agent.php       ✏️ exécution par liste fermée, résultat jusqu'à l'accusé, rotate-key et bascule, repli de clé
│   └── tests/AgentTest.php   ✏️ exécution, accusé, rejeu, rotation, intrusion
├── vigie/tests/agent_e2e.rs  ✅ serve sur 127.0.0.1 + agent PHP réel : ping de bout en bout, puis rotate-key
└── vigie/docs/
    ├── agent-php.md          ✏️ configuration commands, état, ce que l'agent exécute
    └── decisions.md          ✏️ section #6
```

## Tasks to do

1. Exécution : état « en cours » écrit avant, résultat écrit après, `last_command_seq` avancé ; `ping` → `{status: ok, detail: "pong"}` ; `rotate-key` → nouvelle paire et preuve ; `htaccess-*` → `refused` ; nom inconnu : réponse rejetée.
2. Résultat renvoyé à chaque retrait jusqu'à `acked` = id ; commande re-servie déjà exécutée : rien n'est rejoué ; état « en cours » au démarrage → `failed` « exécution interrompue ».
3. `rotate-key` : bascule sur `accepted: true`, nouvelle paire supprimée sur `accepted: false` ; repli sur la nouvelle clé pour un rapport ou un retrait refusé tant que la bascule attend.
4. Intrusion : un attaquant qui écrit une « commande » dans `state.json` ou dans un fichier voisin, ou qui sert une réponse non signée par la clé épinglée, n'obtient aucune exécution.
5. Bout en bout : `tests/agent_e2e.rs` lance le routeur de `serve` sur un port local, crée les clés, pose `[commands]`, enregistre l'agent, met `ping` en file, lance `php vigie-agent.php` deux fois et vérifie `done` ; puis `rotate-key` et la nouvelle clé en base ; sauté si `php -m` n'a pas sodium.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Une commande n'est exécutée qu'une fois, même re-servie ; le résultat survit à un passage sans accusé |
| 3 | Les deux issues de la rotation sont testées ; l'agent n'est jamais verrouillé dehors |
| 4 | Aucune exécution sans signature valide de la clé épinglée |
| 5 | Le test de bout en bout passe en CI Linux (PHP présent) |
