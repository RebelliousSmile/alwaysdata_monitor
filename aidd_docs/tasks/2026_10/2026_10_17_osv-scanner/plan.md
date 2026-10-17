---
objective: "Un job osv-scanner de garde-fous.yml, binaire épinglé et vérifié par SHA-256, confronte à chaque push, pull request et chaque semaine les quatre lockfiles du dépôt (deux Cargo.lock, pnpm-lock.yaml, composer.lock) à la base OSV ; toute faille non couverte par une exception datée et motivée de osv-scanner.toml le fait échouer ; la marche à suivre est écrite dans decisions.md."
status: pending
issue_number: 22
---

# Plan: Failles de Vigie lui-même, osv-scanner en CI (F8)

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Savoir, sans y penser, qu'une dépendance de Vigie (veilleur, console Tauri, module PrestaShop) a une faille publiée, et empêcher qu'elle passe inaperçue sur `main` |
| **Source** | Issue GitHub #22 ; `.github/workflows/garde-fous.yml` (modèle gitleaks : version + SHA-256 vérifiée) ; lockfiles `vigie/Cargo.lock`, `vigie/app/src-tauri/Cargo.lock`, `vigie/app/pnpm-lock.yaml`, `composer.lock` ; relevé local du 2026-10-17 (osv-scanner 2.7.0, bases OSV hors ligne) |

### Relevé du 2026-10-17 (avant tout changement)

`osv-scanner scan source` sur les quatre lockfiles (238 + 520 + 391 + 26 paquets) : **5 paquets, 5 failles**, sortie 1. Le job serait rouge dès son premier passage.

| Faille | Paquet | Lockfile | Origine | Correctif disponible |
| --- | --- | --- | --- | --- |
| RUSTSEC-2026-0253 (use-after-free, `LruCache::pop`) | `lru` 0.16.4 | `vigie/Cargo.lock` | `rqrr` 0.10.1, **dev-dependency** (relit le QR de `vigie device pair` dans `tests/cli.rs`) | oui : `rqrr` 0.11.0 dépend de `lru ^0.18` (corrigé en 0.18.2) |
| RUSTSEC-2024-0429 = GHSA-wrw7-89jp-8q8g (CVSS 6.9, `VariantStrIter`) | `glib` 0.18.5 | `vigie/app/src-tauri/Cargo.lock` | pile gtk3 de `tauri`/`wry`/`webkit2gtk` (Linux seulement) | corrigé en 0.20, que gtk-rs 0.18 (gtk3, figé) n'adopte pas : pas atteignable tant que tauri 2 reste sur webkit2gtk 4.1 |
| RUSTSEC-2024-0370 (non maintenu) | `proc-macro-error` 1.0.4 | `vigie/app/src-tauri/Cargo.lock` | `glib-macros` / `gtk3-macros` 0.18 (macro de compilation) | aucun |
| GHSA-vfj7-8cjw-p6xm (CVSS 8.7, épuisement de pile) | `braces` 3.0.3 | `vigie/app/pnpm-lock.yaml` | `micromatch`/`chokidar` de `tailwindcss` 3.4.19 et des outils de build | aucun (`last_affected` 3.0.3, dernière version publiée) |
| GHSA-rj75-hqrm-r3gf (CVSS 5.9, complexité quadratique) | `postcss-selector-parser` 6.1.4 | `vigie/app/pnpm-lock.yaml` | `tailwindcss` 3.4.19 et `postcss-nested` (`^6.1.2`) | 7.1.6 seulement ; la branche `legacy-v6` s'arrête à 6.1.4 non corrigée |

`composer.lock` : 0 faille, mais **périmé** (`composer validate` : « lock file is not up to date ») : `require-dev` (phpunit) a été retiré de `composer.json` en 1.10.0, le lock garde 26 paquets de développement et aucun paquet d'exécution.

## Phases

| #   | Phase                                                   | File                         |
| --- | ------------------------------------------------------- | ---------------------------- |
| 1   | Job osv-scanner, remédiations et exceptions datées      | [`phase-1.md`](./phase-1.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| **osv-scanner 2.7.0** (`google/osv-scanner`, Apache-2.0), asset `osv-scanner_linux_amd64` (binaire nu, pas d'archive), SHA-256 `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` lue dans `osv-scanner_SHA256SUMS` de la release et recalculée sur le binaire téléchargé le 2026-10-17. Installation calquée sur gitleaks : `env` `OSV_SCANNER_VERSION` / `OSV_SCANNER_SHA256`, `curl -sSfL -o osv-scanner`, `sha256sum -c -`, `chmod +x`. À l'implémentation, revérifier que 2.7.0 est toujours la dernière release (redirection de `releases/latest/download/…`) et que la somme est inchangée | Même modèle de confiance que gitleaks dans ce workflow ; un binaire substitué fait échouer le job avant de tourner |
| Nouveau job `deps` (« osv-scanner ») dans `garde-fous.yml`, à côté de `secrets` et `tls-deps`, `ubuntu-24.04`, `actions/checkout` épinglé par SHA (`11d5960…` v4.4.0, déjà utilisé), permissions `contents: read` du workflow inchangées | L'issue le demande ; garde-fous tourne sans filtre de chemin, donc sur tout changement de lockfile, console comprise |
| Commande : `./osv-scanner scan source --config=osv-scanner.toml --lockfile=vigie/Cargo.lock --lockfile=vigie/app/src-tauri/Cargo.lock --lockfile=vigie/app/pnpm-lock.yaml --lockfile=composer.lock`. Lockfiles nommés, pas `--recursive` ; base OSV en ligne (`api.osv.dev`, joignable depuis les runners) ; pas de `--call-analysis` | Liste explicite : un lockfile absent ou renommé fait échouer le job au lieu d'être sauté en silence. L'analyse d'appels Rust exécute les scripts de build : hors de question dans un garde-fou |
| **Fail-closed sur tout code non nul** : 1 = faille, 127 = erreur (vérifié : `api.osv.dev` injoignable → 127, « max retries exceeded »), 128 = aucun paquet. Aucune tolérance de sévérité ; un « non maintenu » RustSec compte comme une faille | Exigence de l'issue (« toute faille fait échouer le job ») ; une panne réseau ne doit pas passer pour « aucune faille » |
| Déclencheurs du workflow : `push`, `pull_request`, `workflow_dispatch` existants, plus `schedule: - cron: "17 5 * * 1"` (lundi 05:17 UTC). Le cron s'applique à tout le workflow (gitleaks et `tls-deps` repassent aussi, coût négligeable) | Une faille se publie sans qu'aucun commit ne change ; minute décalée de l'heure pleine pour éviter la file d'attente des crons ; pas de `if:` par job à maintenir |
| Exceptions dans **`osv-scanner.toml` à la racine**, passé par `--config` (sinon osv-scanner cherche le fichier le plus proche de chaque lockfile). Chaque entrée `[[IgnoredVulns]]` porte `id`, `ignoreUntil` (date TOML, au plus 3 mois) et `reason` (origine, pourquoi non exploitable chez nous, condition de levée). Vérifié avec 2.7.0 : une exception sur un alias (`GHSA-wrw7-89jp-8q8g`) couvre aussi `RUSTSEC-2024-0429` ; une exception échue est ignorée et la faille refait échouer le job ; une exception devenue inutile est signalée (« unused ignores ») sans échec | Exceptions versionnées, relues en PR, qui expirent d'elles-mêmes : le cron hebdomadaire force la relecture à l'échéance |
| **Remédier avant d'excepter** : `rqrr` passe de `0.10` à `0.11` dans `[dev-dependencies]` de `vigie/Cargo.toml` (`lru` 0.18.x), `tests/cli.rs` adapté si l'API change | Un correctif existe ; aucune exception pour ce qui se corrige |
| **Exceptions initiales, échéance 2027-01-17** : `GHSA-wrw7-89jp-8q8g` (glib, pile gtk3 Linux de tauri, `VariantStrIter` non appelé par la console), `RUSTSEC-2024-0370` (proc-macro-error, macro de compilation, aucun code à l'exécution), `GHSA-vfj7-8cjw-p6xm` (braces, outil de build : motifs de glob écrits par nous, absent du `dist` embarqué), `GHSA-rj75-hqrm-r3gf` (postcss-selector-parser 6, tailwind 3 au build : sélecteurs écrits par nous, absent du `dist`). Levée : tauri sur une pile sans gtk-rs 0.18, braces corrigé, passage à tailwind 4 (hors périmètre, à ouvrir en issue si l'échéance arrive sans correctif amont) | Pas de correctif amont atteignable sans migration ; outils de build ou dépendances Linux de la console, jamais dans le veilleur sur le VPS ; trois mois laissent passer une release amont sans laisser dormir l'exception |
| **composer.lock régénéré** (`composer update --no-install`, d'après `composer.json` : 0 paquet) et toujours scanné ; une étape `composer validate --no-check-publish` (composer est présent sur `ubuntu-24.04`) fait échouer le job si le lock redevient périmé. Le module PrestaShop n'a aucune dépendance Composer à l'exécution (`require` : `php` seul) | Scanner un lock qui ne reflète pas `composer.json` ne prouve rien ; le lock vide reste le point d'entrée d'une future dépendance, vérifié avec 2.7.0 (0 paquet dans un lockfile parmi d'autres : pas d'erreur 128) |
| **cargo-deny écarté pour l'instant** : osv-scanner lit déjà la base RustSec (identifiants `RUSTSEC-*`, « non maintenu » compris) ; les crates TLS interdites restent gardées par `check-tls-deps.sh` ; licences et sources de crates ne sont pas demandées. Réévaluer si une politique de licences devient nécessaire | Un second binaire épinglé pour la même base d'avis ; pas de besoin exprimé au-delà |
| Preuve de détection : le premier commit de la branche ajoute le job **sans** `osv-scanner.toml` ni remédiation → run rouge sur les 5 failles du relevé (lien du run consigné dans la PR). En plus, une branche jetable `test/osv-detecte` remet `rqrr = "0.10"` après la remédiation → rouge sur RUSTSEC-2026-0253 ; branche supprimée, jamais fusionnée | L'issue demande la preuve qu'une version vulnérable épinglée fait échouer le job ; les failles réelles la donnent sans rien inventer |
| Documentation : section « Dépendances (issue #22) » de `vigie/docs/decisions.md` (décisions datées du jour d'implémentation) avec la marche à suivre quand le job est rouge : lire la faille, mettre à jour la dépendance, sinon exception datée ≤ 3 mois motivée en PR ; retirer une exception signalée « unused » ; rouge en 127 = relancer, jamais excepter ; reproduire en local avec la même commande. Ligne de CHANGELOG après fusion, comme les issues précédentes | L'issue demande la marche à suivre ; elle sert à celui qui reçoit l'e-mail d'échec du cron |
| Échec du cron visible : GitHub notifie l'auteur du dernier changement du cron ; un dépôt public sans activité 60 jours voit ses crons désactivés, ce qui est noté dans la marche à suivre (réactiver depuis l'onglet Actions) | Une exécution hebdomadaire qui s'arrête sans bruit ne vaut pas mieux qu’aucune exécution |
