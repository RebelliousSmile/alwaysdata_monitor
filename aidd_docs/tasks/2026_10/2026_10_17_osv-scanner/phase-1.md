---
status: pending
---

# Instruction: Job osv-scanner, remédiations et exceptions datées

## Architecture projection

```txt
.
├── .github/workflows/
│   └── garde-fous.yml        ✏️ schedule hebdomadaire ; job deps : osv-scanner épinglé + SHA-256, composer validate
├── osv-scanner.toml          ✅ [[IgnoredVulns]] id / ignoreUntil / reason, quatre exceptions au 2027-01-17
├── composer.lock             ✏️ régénéré d'après composer.json (0 paquet)
└── vigie/
    ├── Cargo.toml            ✏️ rqrr 0.11 en dev-dependency
    ├── Cargo.lock            ✏️ rqrr 0.11, lru 0.18.x
    ├── tests/cli.rs          ✏️ seulement si l'API de rqrr 0.11 change
    └── docs/
        └── decisions.md      ✏️ section « Dépendances (issue #22) » et marche à suivre
```

## Tasks to do

1. **Job seul, preuve rouge.** Dans `garde-fous.yml`, job `deps` (nom « osv-scanner ») : `env` `OSV_SCANNER_VERSION: "2.7.0"` et `OSV_SCANNER_SHA256: 160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` (commentaire : somme de `osv-scanner_SHA256SUMS` de la release v2.7.0) ; `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0` ; étape « installer osv-scanner (somme vérifiée) » : `curl -sSfL -o osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"`, `echo "${OSV_SCANNER_SHA256}  osv-scanner" | sha256sum -c -`, `chmod +x osv-scanner` ; étape de scan sur les quatre lockfiles nommés (sans `--config` à ce commit). Revérifier avant d'écrire que 2.7.0 est la dernière release et que la somme est inchangée. Pousser : le run doit être rouge sur les 5 failles du relevé ; consigner son lien.
2. **Cron.** Ajouter `schedule: - cron: "17 5 * * 1"` aux déclencheurs ; mettre à jour le commentaire d'en-tête (une faille se publie sans commit).
3. **Remédiation Rust.** `rqrr = { version = "0.11", default-features = false }` dans `vigie/Cargo.toml` ; `cargo update -p rqrr` ; vérifier que `lru` ≥ 0.18.2 dans `vigie/Cargo.lock` et que `check-tls-deps.sh` reste vert ; adapter `tests/cli.rs` si nécessaire ; `cargo test --locked --all-targets`.
4. **composer.lock.** `composer update --no-install` (lock aligné sur `composer.json`, 0 paquet) ; dans le job, étape `composer validate --no-check-publish` avant le scan.
5. **Exceptions.** `osv-scanner.toml` à la racine, quatre `[[IgnoredVulns]]` (`GHSA-wrw7-89jp-8q8g`, `RUSTSEC-2024-0370`, `GHSA-vfj7-8cjw-p6xm`, `GHSA-rj75-hqrm-r3gf`), `ignoreUntil = 2027-01-17`, `reason` en une phrase : origine, pourquoi non exploitable chez nous, condition de levée (voir plan). En-tête en commentaire : règles (échéance ≤ 3 mois, raison obligatoire, remédier d'abord). L’étape de scan passe `--config=osv-scanner.toml`. Aucun nom de site, domaine ou hôte réel dans les raisons.
6. **Documentation.** Section « Dépendances (issue #22) » dans `vigie/docs/decisions.md` (lien vers ce plan, tableau Décision / Raison : outil et version, lockfiles, fail-closed, cron, exceptions, composer, cargo-deny écarté) suivie de la marche à suivre : lire la faille sur osv.dev ; mettre à jour la dépendance ; sinon exception datée motivée en PR ; retirer les exceptions signalées « unused ignores » ; code 127 = relancer le job, jamais excepter ; cron désactivé après 60 jours sans activité = le réactiver ; reproduire en local avec la commande exacte du job.
7. **Preuve sur branche jetable.** Après fusion, branche `test/osv-detecte` remettant `rqrr = "0.10"` (lock régénéré) : run rouge sur `RUSTSEC-2026-0253` ; lien consigné dans la PR ou l'issue ; branche supprimée.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Run du premier commit rouge, sa sortie liste les 5 failles du relevé ; l’étape d’installation affiche `osv-scanner: OK` ; une somme altérée (essai local) fait échouer `sha256sum -c` |
| 2 | Après le premier lundi suivant la fusion, un run `schedule` du workflow garde-fous est visible dans l'onglet Actions |
| 3 | `vigie/Cargo.lock` sans `lru` < 0.18.2 ; workflows vigie (Linux, Windows) et `tls-deps` verts |
| 4 | `composer validate --no-check-publish` sans erreur de lock ; osv-scanner lit `composer.lock` (0 paquet) sans sortir en 128 |
| 5 | Job `deps` vert sur la branche puis sur `main` ; chaque exception a `id`, `ignoreUntil` ≤ 2027-01-17 et `reason` ; essai local d'une échéance passée : la faille réapparaît et la sortie vaut 1 |
| 6 | La section de `decisions.md` contient la marche à suivre complète et la commande locale identique à celle du job |
| 7 | Run rouge de `test/osv-detecte` sur RUSTSEC-2026-0253, lien consigné, branche supprimée |
| 1-7 | Toutes les actions du workflow épinglées par SHA ; `permissions: contents: read` inchangé ; aucune donnée réelle (domaine, hôte, clé) dans les fichiers ajoutés |
