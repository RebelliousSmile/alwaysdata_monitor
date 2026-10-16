---
status: pending
---

# Instruction: Constats, partage et branchement à tick

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/000N.sql   ✅ log_signatures (ua normalisé, site, score, seen_at, expires_at)
    ├── src/
    │   ├── analysis/findings.rs ✅ agrégats → Analysis structurée → constats agrégés et bornés sous le contrôle `logs`
    │   ├── analysis/shared.rs   ✅ signatures d'UA de robots : normalisation, note, lecture, expiration à 30 j, 100 par site
    │   ├── store.rs          ✏️ agrégats, curseur, signatures, purge et masquage à 30 j
    │   └── tick.rs           ✏️ repli à tour de rôle (10 s en tout), constats, reconcile `logs`, close_unwatched reconnaît `logs`
    └── docs/
        ├── logs.md           ✏️ analyse : règles, ordre, heure de référence, agrégats, constats, partage, limites, latence (dont : pic par minute approché ; une IP fraîchement admise après éviction reste sans score tant que l'erreur héritée dépasse le dixième de ses requêtes, ce qui n'est pas un verdict de trafic sain)
        └── decisions.md      ✏️ section #8 (partage sans IP, timeout par entrée, protection au niveau d'action, AiUser protégé)
```

## Tasks to do

1. `Analysis` : robots vus (éditeur, finalité, `robots_only`, `honours_robots`, volume, `protected`), verdicts d'IP (score, niveau, raisons, classe), dépassements de règles, charge ; gardée par site pour #13 et la console (#5).
2. Constats : un par règle dépassée (clé = identifiant de règle ; détail : chiffres, au plus 5 IP ou chemins tronqués à 100 caractères) ; `sensitive-path` (information, une IP suffit) et `sensitive-path-many` (avertissement, 5 IP distinctes) ; `suspicious-ips` (avertissement, 5 pires IP) ; `bots-ai-training` (information) ; `load` (avertissement). Résolution des constats de fenêtre quand `now − référence` > fenêtre + `agent_silence`.
3. Partage : signature d'UA notée quand le score propre d'une IP qui la porte est ≥ 70 et que l'UA est un robot non générique ; jamais d'IP.
4. `tick` : sites ayant une source (#1) ; `close_unwatched` garde `logs` pour eux ; purge des profils à 48 h, des signatures et résumés à 30 j, masquage des détails `logs` clos à 30 j.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 2 | 1 000 IP suspectes → un seul incident ; aucune IP ni chemin dans une clé d'incident ; `spike-404` résolu quand les données s'arrêtent depuis fenêtre + agent_silence (`FakeClock`) |
| 3 | Un UA de robot noté sur le site A ajoute 15 points sur le site B, sans que B le renote par ce seul bonus ; aucune IP dans `log_signatures` ; expiration à 30 j |
| 4 | Deux `tick` de suite sur une `MemorySource`, budget épuisé au milieu d'une série de lots : aucune entrée comptée deux fois, pas de clôture puis réouverture |
