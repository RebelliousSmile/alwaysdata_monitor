---
status: done
---

# Instruction: Comparateurs de versions par écosystème

## Architecture projection

```txt
.
├── .github/workflows/vigie.yml        ✏️ pas Linux « différentiel version_compare (PHP 8.1) » : VIGIE_PHP sous la forme de VIGIE_E2E_PHP, même image épinglée par digest
└── vigie/
    ├── src/
    │   ├── lib.rs                     ✏️ pub mod vulns
    │   └── vulns/
    │       ├── mod.rs                 ✅ rôle du module, renvoi à docs/failles.md
    │       └── version/
    │           ├── mod.rs             ✅ Scheme { Semver, Composer, Php } ; SourceEcosystem → Scheme ; Bound { Floor, At(Version) } ; parse(scheme, &str) -> Result<Version, Unparsable> ; MAX_VERSION_CHARS = 128, MAX_NUMERIC_DIGITS = 18
    │           ├── semver.rs          ✅ semver 2.0 strict, précédence §11, préversions numériques par (longueur, lexical), build ignoré
    │           ├── php.rs             ✅ canonize() exacte de versioning.c, puis Token { Num, Special(rank) } et compare_tokens()
    │           └── composer.rs        ✅ normalize() de VersionParser (composer/semver), jetons injectés (patch au rang pl), puis compare_tokens()
    └── tests/
        ├── vulns_versions.rs          ✅ vecteurs JSON, fuzz à graine fixe (aucune panique, réflexivité, antisymétrie, transitivité, Eq ⇔ Equal)
        ├── vulns_php_diff.rs          ✅ #[ignore] ; échoue si VIGIE_PHP est posé et diffère de PHP
        └── fixtures/versions/
            ├── NOTICE                 ✅ texte MIT complet de composer/semver, lien, liste des vecteurs repris de VersionParserTest
            ├── composer.json          ✅ normalize (repris de composer/semver) et ordre
            ├── npm.json               ✅
            ├── cargo.json             ✅
            ├── wordpress.json         ✅
            └── prestashop.json        ✅
```

## Test Scope

```mermaid
journey
  section Happy path
    WordPress 5.9 contre 5.9.0 => 5.9 < 5.9.0 comme PHP: 5: lib
    WordPress 6.4-beta1 < 6.4-RC1 < 6.4 < 6.4.1: 5: lib
    PrestaShop 1.6.1.24 < 1.7.0.0 < 8.0.0 ; quatre composants: 5: lib
    Composer normalize v1.2 => 1.2.0.0 ; 1.0.0-b2 => 1.0.0.0-beta2 ; 1.0-beta.2 => 1.0.0.0-beta2: 5: lib
    Composer normalize 1.0.0-p1, -pl1, -patch1 => 1.0.0.0-patch1 ; 1.0-ALPHA et 1.0-Rc1 => alpha, RC1: 5: lib
    Composer normalize 1.0.0+build.5 => 1.0.0.0 ; 1.0-stable => 1.0.0.0 ; 20260101 => 20260101 ; 2026.01.01 => 2026.01.01: 5: lib
    Composer ordre 1.0.0-beta2 < 1.0.0-RC1 < 1.0.0 < 1.0.0-patch1 ; 1.0.0-dev < 1.0.0-alpha: 5: lib
    npm 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0: 5: lib
    npm 1.0.0+a = 1.0.0+b ; Cargo 0.9.9 < 0.10.0: 5: lib
  section Edge case - non analysable
    Composer dev-main, 1.x-dev, majeur à 6 chiffres hors format date, chaîne vide => Unparsable: 1: lib
    npm et Cargo 01.2.3, 1.2, v1.2.3, =1.2.3, numérique de 19 chiffres => Unparsable: 1: lib
    PHP 1.0-bogus, 1.0-ALPHA, 1.0-patch, octets de contrôle, U+202E, 129 caractères => Unparsable: 1: lib
    Préversion npm 1.0.0-99999999999999999999999 => analysée sans débordement: 1: lib
  section Plancher
    Bound::Floor sous toute version de chaque schéma ; parse("0") en semver => Unparsable: 1: lib
  section Fuzz
    200 000 chaînes aléatoires (jetons de version et octets hostiles) => aucune panique: 1: lib
    100 000 triplets analysables par schéma => réflexivité, antisymétrie, transitivité: 1: lib
  section Différentiel
    VIGIE_PHP posé, vecteurs + 5 000 paires du fuzz => version_compare de PHP identique: 5: ci
```

## Tasks to do

1. **`version/mod.rs`** : `Scheme`, `SourceEcosystem` (`Packagist`, `Npm`, `CratesIo`, `Wordfence`, `FriendsOfPresta`) et `SourceEcosystem::scheme()` par un `match` sans joker ; `Version` opaque (`Ord` et `Eq` cohérents, `Display` de la chaîne d'origine) ; `Bound { Floor, At(Version) }` (plancher OSV `introduced: "0"`, jamais analysé comme version) ; `parse(scheme, raw)` rend `Err(Unparsable { reason })` pour une chaîne hors de la grammaire de version de `failles.md` (`[0-9A-Za-z.+_-]{1,128}`) ou propre au schéma ; tout composant numérique de plus de 18 chiffres est `Unparsable` (sauf identifiant de préversion semver, comparé par longueur puis lexicalement).
2. **`semver.rs`** : `MAJOR.MINOR.PATCH[-pre][+build]` strict ; préversions selon la §11 (numérique < alphanumérique, numériques par (longueur, lexical), plus long plus grand à préfixe égal) ; build validé puis ignoré dans l'ordre et l'égalité.
3. **`php.rs`** : `canonize(&str) -> String`, copie exacte de `php_canonicalize_version` (commentaire citant `ext/standard/versioning.c` et la version de PHP lue) ; `tokens(&str) -> Result<Vec<Token>, Unparsable>` : composants vides sautés, numérique ou mot spécial exact sensible à la casse (`dev`, `alpha`, `a`, `beta`, `b`, `RC`, `rc`, `pl`, `p`), tout autre mot `Unparsable` ; `compare_tokens` : rangs `dev < alpha = a < beta = b < RC = rc < # < pl = p`, numérique contre mot comparé comme `#`, composant restant comparé à `#`.
4. **`composer.rs`** : `normalize(&str) -> Result<String, Unparsable>` selon `VersionParser::normalize` de `composer/semver` (lu à l'implémentation, version citée) : `+build` retiré, `v` retiré, forme classique (majeur ≤ 5 chiffres) complétée à quatre composants ou forme date, suffixes insensibles à la casse canonisés comme `expandStability` (`alpha`, `beta`, `RC`, `patch`, `-stable` retiré, numéro accolé, `-dev`) ; `dev-*`, `*.x-dev`, alias → `Unparsable`. Comparaison : jetons de `php.rs` sur la forme normalisée, avec `patch` injecté au rang `pl`.
5. **Vecteurs** `tests/fixtures/versions/<écosystème>.json` : `{"cmp": [{"a", "b", "order": -1|0|1, "why"}], "unparsable": [{"v", "why"}]}`, chaque `cmp` vérifié dans les deux sens ; au moins égalité, préversions, suffixes, longueurs différentes, zéros initiaux, valeurs hostiles ; `composer.json` ajoute `normalize: [{"in", "out" | null}]` repris de `VersionParserTest` (`+build`, majeur à 5 chiffres, versions-dates, `-stable`, `beta.2` → `beta2`, `p`/`pl`/`patch` → `patch`, casse). `NOTICE` : texte MIT complet de `composer/semver`, lien du dépôt et du fichier de test, liste des cas repris.
6. **Fuzz** à graine fixe (xorshift sans dépendance, comme `logs/tests.rs`) : 200 000 chaînes faites de jetons (`0`, `1`, `10`, `.`, `-`, `+`, `_`, `alpha`, `ALPHA`, `RC`, `dev`, `pl`, `patch`, `v`, `x`) et d'octets hostiles, aucune panique ; puis 100 000 triplets analysables par schéma : réflexivité, antisymétrie, transitivité, `a == b ⇔ cmp = Equal`.
7. **Différentiel PHP** (`tests/vulns_php_diff.rs`, `#[ignore]`) : écrit dans un fichier sous `/tmp` les paires (vecteurs `wordpress` et `prestashop`, formes normalisées des vecteurs `composer`, 5 000 paires du fuzz dans le domaine accepté), lance `$VIGIE_PHP -r '…version_compare…' <fichier>` (préfixe de commande comme `VIGIE_E2E_PHP`), compare chaque signe ; sans `VIGIE_PHP`, rend tôt avec un message ; avec, échoue au moindre écart en citant la paire.
8. **CI** : pas Linux après « bout en bout », `VIGIE_PHP="docker run --rm --user $(id -u):$(id -g) -v /tmp:/tmp php:8.1-cli@sha256:1215…f836 php" cargo test --locked --test vulns_php_diff -- --ignored`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-4 | Chaque cas « Happy path », « non analysable » et « Plancher » du Test Scope est un vecteur ou un test et passe |
| 5 | Cinq fichiers de vecteurs ; vecteurs de normalisation Composer verts ; `NOTICE` porte le texte MIT complet et la liste des cas repris |
| 6 | Fuzz vert, reproductible, en moins de 10 s en debug |
| 7-8 | Pas CI vert sur Linux ; un vecteur PHP faussé volontairement le fait échouer (vérifié une fois, noté dans la PR) |
| 1-8 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
