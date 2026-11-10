---
status: pending
---

<!-- Fill or omit these sections; never add, rename, or reorder one. -->

# Instruction: Copie locale et premier déploiement

## Architecture projection

> Tree of the final files. ✅ create · ✏️ modify · ❌ delete

```txt
sc-vigie/ (copie locale, fichiers ignorés par git, jamais commités)
├── deploy/targets.json               ✏️ déplacé depuis vigie/deploy/targets.json
├── config.toml, remote.toml          ✏️ déplacés depuis vigie/ s'ils existent
├── target/                           ✅ recréé par le premier cargo build
└── vigie/                            ❌ résidu ignoré (target/, app/node_modules/, fichiers ci-dessus) supprimé après déplacement
.git/config                           ✏️ remote origin → https://github.com/RebelliousSmile/sc-vigie.git
```

## User Journey

```mermaid
flowchart TD
  A[PR fusionnée] --> B[remote origin vers sc-vigie.git, pull de main : vigie/ reste ignoré]
  B --> C[inventaire des fichiers ignorés sous vigie/]
  C --> D[déplacement de targets.json et des configs locales, git check-ignore]
  D --> E[suppression du résidu vigie/ après vérification]
  E --> F[pnpm install dans app/]
  F --> G[deploy.mjs et deploy-agent.mjs en prévisualisation]
  G --> H{--apply ?}
  H -->|décision de l'utilisateur| I[déploiement réel]
```

## Test Scope

```mermaid
---
title: Test scope
---
journey
  section Setup
    PR de la phase 1 et 2 fusionnée => main contient app/, src/, agent/ à la racine: 5: cli
  section Happy path
    git remote get-url origin => https://github.com/RebelliousSmile/sc-vigie.git: 5: cli
    git status --ignored vigie => plus rien sous vigie/: 5: cli
    node scripts/deploy.mjs veilleur => prévisualisation lit deploy/targets.json, aucune écriture distante: 5: cli
    node scripts/deploy-agent.mjs site-a-agent => prévisualisation, aucune écriture distante: 5: cli
  section Edge case - fichier local oublié
    vigie/ contient encore un fichier ignoré non listé => inventaire avant suppression => fichier déplacé ou signalé, jamais supprimé à l'aveugle: 3: cli
  section Edge case - worktrees
    worktree de .claude/worktrees sur une branche d'avant le déplacement => git worktree list => retiré ou rebasé, signalé: 3: cli
```

## Tasks to do

### `1)` Remote et main

> La copie locale suit le dépôt renommé ; le pull vient d'abord, parce que le `/vigie/` de transition garde le résidu ignoré, alors qu'un fichier déplacé avant le pull serait non suivi sous l'ancien `.gitignore`.

1. `git remote set-url origin https://github.com/RebelliousSmile/sc-vigie.git`, puis `git pull` sur `main` ; `git status` ne montre aucun fichier non suivi.
2. `git worktree list` : retirer le worktree `chore/split-module` (fusionnée) et signaler tout autre worktree d'avant le déplacement.

### `2)` Fichiers locaux ignorés

> Rien de local n'est perdu ni exposé : `git mv` ne déplace pas les fichiers ignorés.

1. `git status --ignored --short vigie` : inventaire complet, montré avant toute suppression.
2. Déplacer `vigie/deploy/targets.json` vers `deploy/targets.json`, et `vigie/config.toml`, `vigie/remote.toml` vers la racine s'ils existent ; `git check-ignore -v deploy/targets.json` (et les configs déplacées) confirme qu'ils sont ignorés, `git status` reste vide.
3. Supprimer le résidu (`vigie/target/`, `vigie/app/node_modules/`) seulement après confirmation de l'utilisateur ; `pnpm install` dans `app/`.

### `3)` Prévisualisation des déploiements

> Les deux scripts fonctionnent depuis la racine sur une vraie cible, sans rien écrire.

1. `node scripts/deploy.mjs veilleur` puis `node scripts/deploy-agent.mjs site-a-agent` : prévisualisation seule.
2. Le `--apply` reste une décision de l'utilisateur.

## Test acceptance criteria

| Task | Acceptance criteria              |
| ---- | -------------------------------- |
| 1 | `origin` pointe sur `sc-vigie.git` ; `main` local égale `origin/main` ; `git status` sans fichier non suivi ; aucun worktree d'avant le déplacement ne reste sans être signalé |
| 2 | `targets.json` et les configurations locales sont à leur nouvelle place, ignorées (`git check-ignore`) ; `vigie/` n'existe plus ; rien n'a été supprimé sans inventaire montré |
| 3 | Les deux prévisualisations aboutissent depuis la racine, sans écriture distante |
