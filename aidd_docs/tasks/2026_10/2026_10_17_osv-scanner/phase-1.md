---
status: in-progress
---

# Instruction: Job osv-scanner, remédiations et exceptions datées

## Architecture projection

```txt
.
├── .github/workflows/
│   └── garde-fous.yml        ✏️ schedule hebdomadaire ; job deps : script d'exceptions, composer validate, osv-scanner épinglé + SHA-256
├── composer.lock             ✏️ régénéré d'après composer.json (0 paquet)
└── vigie/
    ├── Cargo.toml            ✏️ rqrr 0.11 en dev-dependency
    ├── Cargo.lock            ✏️ rqrr 0.11, lru ≥ 0.18.2
    ├── tests/cli.rs          ✏️ seulement si l'API de rqrr 0.11 change
    ├── scripts/
    │   └── check-osv-exceptions.py ✅ id, reason, ignoreUntil ≤ 92 jours ; aucune autre clé
    ├── app/
    │   ├── osv-scanner.toml  ✅ braces, postcss-selector-parser
    │   └── src-tauri/
    │       └── osv-scanner.toml ✅ glib, proc-macro-error
    └── docs/
        └── decisions.md      ✏️ section « Dépendances (issue #22) » et marche à suivre
```

## Tasks to do

1. **Épinglage.** Télécharger `osv-scanner_linux_amd64`, `osv-scanner_SHA256SUMS` et `multiple.intoto.jsonl` de la release v2.6.0 ; vérifier la somme (`ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108`) et la provenance avec `slsa-verifier verify-artifact … --source-uri github.com/google/osv-scanner --source-tag v2.6.0` (slsa-verifier vérifié par sa propre somme) ; consigner la sortie, masquée, dans la PR.
2. **Job seul, preuve rouge.** Dans `garde-fous.yml`, job `deps` (nom « osv-scanner ») : `runs-on: ubuntu-24.04`, `timeout-minutes: 10`, `permissions: contents: read` ; `env` `OSV_SCANNER_VERSION: "2.6.0"` et `OSV_SCANNER_SHA256: ca69b3d3…b108` (commentaire : somme de `osv-scanner_SHA256SUMS` de la release v2.6.0, provenance SLSA vérifiée à l'épinglage) ; `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0` ; étape « installer osv-scanner (somme vérifiée) » : `curl -sSfL -o osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"`, `echo "${OSV_SCANNER_SHA256}  osv-scanner" | sha256sum -c -`, `chmod +x osv-scanner` ; aucun cache ; étape de scan sur les quatre lockfiles nommés, sans `--config`. Pousser : le run doit être rouge sur les 5 failles du relevé ; consigner son lien.
3. **Cron.** Ajouter `schedule: - cron: "17 5 * * 1"` aux déclencheurs ; mettre à jour le commentaire d'en-tête (une faille se publie sans commit).
4. **Remédiation Rust.** `rqrr = { version = "0.11", default-features = false }` dans `vigie/Cargo.toml` ; `cargo update -p rqrr` ; vérifier que `lru` ≥ 0.18.2 dans `vigie/Cargo.lock` et que `check-tls-deps.sh` reste vert ; adapter `tests/cli.rs` si nécessaire ; `cargo test --locked --all-targets`.
5. **composer.lock.** `composer update --no-install` (lock aligné sur `composer.json`, 0 paquet) ; dans le job, étape `composer validate --no-check-publish` avant le scan (sortie non nulle sur un lock périmé, vérifié : 2).
6. **Script d'exceptions.** `vigie/scripts/check-osv-exceptions.py`, bibliothèque standard seule (`tomllib`, `datetime`, `sys`), lancé `python3 -I vigie/scripts/check-osv-exceptions.py $(git ls-files ':(glob)**/osv-scanner.toml')` comme étape du job **avant** le scan. Pour chaque fichier : TOML lisible ; seule clé de premier niveau admise `IgnoredVulns` (liste de tables) ; pour chaque entrée : `id` chaîne non vide, `reason` chaîne non vide après `strip()`, `ignoreUntil` présent et de type date TOML (`datetime.date` ou `datetime.datetime`, ramené à sa date), `ignoreUntil` ≤ date UTC du jour + 92 jours. Toutes les erreurs listées (fichier, id ou index, motif) avant la sortie 1 ; sortie 0 sans fichier. Une échéance déjà passée n'est pas une erreur du script : osv-scanner rend alors la faille, ce qui fait échouer le scan.
7. **Exceptions.** `vigie/app/osv-scanner.toml` (`GHSA-vfj7-8cjw-p6xm`, `GHSA-rj75-hqrm-r3gf`) et `vigie/app/src-tauri/osv-scanner.toml` (`GHSA-wrw7-89jp-8q8g`, `RUSTSEC-2024-0370`), `ignoreUntil` ≤ 92 jours de la date d'implémentation (2027-01-17 au plus tard), `reason` reprise du plan ; pour glib, mot pour mot : « pile gtk3 de tauri, compilée seulement pour Linux desktop ; aucun livrable Linux (release Windows et Android uniquement, console-release.yml) ; lever si une cible Linux est publiée ou si tauri quitte gtk-rs 0.18 » ; pour braces et postcss-selector-parser, la levée inclut « ou si l'un d'eux entre dans dependencies ». En-tête en commentaire : règles (une exception par lockfile du dossier, échéance ≤ 92 jours vérifiée par `check-osv-exceptions.py`, raison obligatoire, remédier d'abord). Aucun nom de site, domaine ou hôte réel dans les raisons.
8. **Documentation.** Section « Dépendances (issue #22) » dans `vigie/docs/decisions.md` (lien vers ce plan, tableau Décision / Raison : outil et version 2.6.0 plutôt que 2.7.0 faute d'ancienneté, provenance SLSA vérifiée, lockfiles, fail-closed, cron, exceptions au plus près et script de contrôle, raison glib mot pour mot, composer, cargo-deny écarté) suivie de la marche à suivre : lire la faille sur osv.dev ; mettre à jour la dépendance ; sinon exception motivée en PR dans le `osv-scanner.toml` du dossier du lockfile, échéance ≤ 92 jours (refusée par le script sinon) ; retirer les exceptions signalées « unused ignores » ; code 127 = relancer le job, jamais excepter ; cron désactivé après 60 jours sans activité = le réactiver ; reproduire en local avec les commandes exactes du job (script puis scan).
9. **Preuves sur branche jetable.** Après fusion, branche `test/osv-detecte`, un commit par essai, chaque run consigné : (a) `rqrr = "0.10"` (lock régénéré) → scan rouge sur `RUSTSEC-2026-0253` ; (b) rqrr rétabli, `ignoreUntil` de glib à une date passée → script vert, scan rouge sur `GHSA-wrw7-89jp-8q8g` (expiration prouvée en CI) ; (c) entrée sans `ignoreUntil` → script rouge ; (d) échéance à +93 jours → script rouge. Branche supprimée, jamais fusionnée.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Somme recalculée identique à `osv-scanner_SHA256SUMS` ; sortie de `slsa-verifier` « PASSED » consignée dans la PR |
| 2 | Run du premier commit rouge, sa sortie liste les 5 failles du relevé ; l'étape d'installation affiche `osv-scanner: OK` ; une somme altérée (essai local) fait échouer `sha256sum -c` ; aucun `actions/cache` dans le job |
| 3 | Après le premier lundi suivant la fusion, un run `schedule` du workflow garde-fous est visible dans l'onglet Actions |
| 4 | `vigie/Cargo.lock` sans `lru` < 0.18.2 ; workflows vigie (Linux, Windows) et `tls-deps` verts |
| 5 | `composer validate --no-check-publish` sans erreur sur le lock régénéré ; essai local sur l'ancien lock : sortie non nulle ; osv-scanner lit `composer.lock` (0 paquet) sans sortir en 128 |
| 6 | Essais locaux : fichiers valides → 0 ; entrée sans `id`, `reason` vide ou blanche, sans `ignoreUntil`, `ignoreUntil` en chaîne, échéance à +93 jours, table `[[PackageOverrides]]`, TOML illisible → 1 avec un message nommant le fichier et l'entrée ; échéance passée → 0 |
| 7 | Job `deps` vert sur la branche puis sur `main` ; aucun `osv-scanner.toml` hors de `vigie/app/` et `vigie/app/src-tauri/` ; raison glib identique au texte imposé |
| 8 | La section de `decisions.md` contient la marche à suivre complète, la raison glib mot pour mot et les commandes locales identiques à celles du job |
| 9 | Runs (a) et (b) rouges au scan, (c) et (d) rouges au script, liens consignés, branche supprimée |
| 1-9 | Toutes les actions du workflow épinglées par SHA ; `permissions: contents: read` ; `timeout-minutes: 10` sur `deps` ; aucune donnée réelle (domaine, hôte, clé) dans les fichiers ajoutés |
