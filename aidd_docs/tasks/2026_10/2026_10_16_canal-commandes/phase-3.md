---
status: pending
---

# Instruction: CLI `vigie site command` et contrat écrit

## Architecture projection

```txt
.
└── vigie/
    ├── src/main.rs                 ✏️ commands init-key|pubkey ; site commands enable|disable ; site command <site> <name> [--param …] [--apply] ; site command-cancel ; site audit [--verify]
    ├── tests/cli.rs                ✏️ aperçu sans écriture, --apply, refus
    └── docs/
        ├── protocole-commandes.md  ✏️ contrat complet (requête, réponse, signatures, états, audit)
        ├── protocole-agent.md      ✏️ renvoi vers protocole-commandes.md
        └── decisions.md            ✏️ section canal de commandes
```

## Tasks to do

1. `vigie site command site-a ping` : aperçu (site, runtime, commande, paramètres, effets), rien n'est écrit ; `--apply` crée la commande et affiche son id.
2. Refus lisibles : site inconnu, désactivé, runtime non admis, commande déjà en vol, clé absente.
3. `site commands enable|disable` : kill-switch ; `disable` annule la commande `pending` (audit).
4. `site audit site-a` : JSONL ; `--verify` : code 0 si la chaîne et les signatures tiennent, 1 sinon, avec l'entrée fautive.
5. `protocole-commandes.md` : de quoi écrire un agent sans lire le code Rust, avec un vecteur de test (clé, horodatage, corps, signature) en JSON dans `tests/fixtures/commands-vector.json`, que #6 consommera.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1    | L'aperçu ne modifie pas la base (octets identiques) |
| 3    | Après `disable`, un retrait ne reçoit plus rien |
| 5    | Le vecteur se vérifie dans `tests/commands.rs` |
