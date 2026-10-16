---
status: pending
---

# Instruction: CLI `vigie site command` et contrat écrit

## Architecture projection

```txt
.
└── vigie/
    ├── src/main.rs                 ✏️ commands init-keys|pubkey ; site commands enable|disable ; site command <site> <name> [--force] [--apply] ; site command-cancel ; site audit <site> [--verify [--head <hash>]]
    ├── src/serve.rs                ✏️ commentaire d'en-tête : routes
    ├── tests/cli.rs                ✏️ aperçu sans écriture, --apply, refus, audit
    ├── tests/fixtures/commands-vectors.json ✅ vecteurs : valide, préfixe faux, horodatage altéré, autre site, commande expirée, nonce différent
    └── docs/
        ├── protocole-commandes.md  ✏️ contrat complet : retrait, réponse, signatures, états, résultat et accusé, rotate-key, audit, ce que le canal ne protège pas, rotation de la clé de commandes
        ├── protocole-agent.md      ✏️ routes existantes, renvoi
        ├── hebergement.md          ✏️ secrets : clés de commandes et d'audit
        └── decisions.md            ✏️ section #10
```

## Tasks to do

1. `vigie site command site-a ping` : aperçu (site, runtime, commande, paramètres, effets, empreinte de typologie), rien n'est écrit ; `--apply` crée la commande, affiche son id.
2. Refus lisibles : site inconnu, désactivé, runtime non admis, commande indisponible, commande déjà en vol, `unknown` sans `--force`, `[commands]` absent.
3. `site audit` : JSONL ; `--verify` : 0 si chaîne et signatures tiennent (et la tête attendue si donnée), 1 sinon, avec l'entrée fautive.
4. Procédure de rotation de la clé de commandes : nouvelle clé, réinstallation de chaque agent avec la nouvelle clé publique, ancienne clé détruite.
5. Les vecteurs de test se vérifient dans `tests/commands.rs` ; #6 les consommera côté PHP.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | L'aperçu ne modifie pas la base (octets identiques) |
| 3 | Une entrée altérée ou une tête attendue absente donne le code 1 |
| 5 | Chaque vecteur a son verdict attendu |
