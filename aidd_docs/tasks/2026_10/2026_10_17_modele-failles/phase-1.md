---
status: pending
---

# Instruction: Comparateurs de versions par écosystème

## Architecture projection

```txt
.
├── .github/workflows/vigie.yml        ✏️ pas Linux « différentiel version_compare (PHP 8.1) » : VIGIE_PHP, même image épinglée par digest
└── vigie/
    ├── src/
    │   ├── lib.rs                     ✏️ pub mod vulns
    │   └── vulns/
    │       ├── mod.rs                 ✅ rôle du module, renvoi à docs/failles.md (complété en phase 3)
    │       └── version/
    │           ├── mod.rs             ✅ enum Scheme { Semver, Composer, Php } ; écosystème de la source → Scheme ; parse(scheme, &str) -> Result<Version, Unparsable> ; Version: Ord ; borne MAX_VERSION_CHARS
    │           ├── semver.rs          ✅ semver 2.0 strict, précédence §11, build ignoré
    │           ├── php.rs             ✅ version_compare de PHP sur le domaine accepté
    │           └── composer.rs        ✅ normalisation Composer, puis ordre de php.rs ; dev-* et alias de branche non analysables
    └── tests/
        ├── vulns_versions.rs          ✅ vecteurs JSON, fuzz à graine fixe (aucune panique, réflexivité, antisymétrie, transitivité, Eq ⇔ Equal)
        ├── vulns_php_diff.rs          ✅ #[ignore] ; échoue si VIGIE_PHP est posé et diffère de PHP
        └── fixtures/versions/
            ├── composer.json          ✅ normalisation (vecteurs de composer/semver VersionParserTest, cités) et ordre
            ├── npm.json               ✅
            ├── cargo.json             ✅
            ├── wordpress.json         ✅
            └── prestashop.json        ✅
```

## Test Scope

```mermaid
journey
  section Happy path
    Vecteurs de chaque écosystème => ordre attendu, dans les deux sens: 5: lib
    WordPress 5.9 contre 5.9.0 => 5.9 < 5.9.0 comme PHP: 5: lib
    PrestaShop 1.6.1.24 < 1.7.0.0 < 8.0.0 ; quatre composants: 5: lib
    Composer v1.2 = 1.2.0.0 ; 1.0.0-beta2 < 1.0.0-RC1 < 1.0.0 < 1.0.0-patch1: 5: lib
    npm 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta.2 < 1.0.0-rc.1 < 1.0.0 ; 1.0.0+a = 1.0.0+b: 5: lib
    Cargo 0.9.9 < 0.10.0 ; préversion sous la stable: 5: lib
  section Edge case - non analysable
    dev-main, 1.x-dev, chaîne vide, espaces, 129 caractères => Unparsable pour Composer: 1: lib
    01.2.3, 1.2, v1.2.3, =1.2.3 => Unparsable pour npm et Cargo: 1: lib
    1.0-bogus, 1.0-patch, octets de contrôle, U+202E => Unparsable pour PHP: 1: lib
  section Fuzz
    200 000 chaînes aléatoires (alphabet de versions et octets hostiles) => aucune panique, longueur bornée: 1: lib
    Triplets aléatoires analysables => réflexivité, antisymétrie, transitivité: 1: lib
  section Différentiel
    VIGIE_PHP posé, vecteurs + 5 000 paires du fuzz => version_compare de PHP identique: 5: ci
```

## Tasks to do

1. **`version/mod.rs`** : `Scheme` (`Semver`, `Composer`, `Php`), `SourceEcosystem` (`Packagist`, `Npm`, `CratesIo`, `Wordfence`, `FriendsOfPresta`) avec `SourceEcosystem::scheme()` par un `match` sans joker : le comparateur suit l'écosystème **de la source**, jamais le type de purl (une plage Packagist sur `pkg:prestashop/module/<x>` reste Composer) ; `Version` opaque (`Ord`, `Eq` cohérents, `Display` de la chaîne d'origine) ; `parse(scheme, raw)` rend `Err(Unparsable { reason })` pour toute chaîne vide, de plus de `MAX_VERSION_CHARS` (128) caractères ou contenant un caractère hors `[0-9A-Za-z.+_-]`. `"0"` est la plus petite version de chaque schéma (événement `introduced: "0"` d'OSV).
2. **`semver.rs`** : `MAJOR.MINOR.PATCH[-pre][+build]` strict ; numériques sans zéro initial et tenant dans `u64` ; identifiants de préversion comparés selon la §11 (numérique < alphanumérique, plus long plus grand à préfixe égal) ; build validé puis ignoré dans l'ordre et l'égalité.
3. **`php.rs`** : canonisation et comparaison de `php_version_compare` (`ext/standard/versioning.c`), y compris le composant restant comparé à `#`. Domaine accepté : composants numériques et mots spéciaux exacts `dev`, `alpha`, `a`, `beta`, `b`, `RC`, `rc`, `pl`, `p` ; tout autre mot rend `Unparsable` (PHP l'aurait apparié par préfixe). Commentaire citant le fichier source PHP et la version lue.
4. **`composer.rs`** : normalisation de `VersionParser::normalize` (`v` retiré, quatre composants, versions-dates, suffixes `alpha|a`, `beta|b`, `RC`, `patch|pl|p` avec numéro, `-dev` final) ; `dev-*`, `*.x-dev` et alias `as` → `Unparsable` ; ordre = `php.rs` sur la forme normalisée.
5. **Vecteurs** `tests/fixtures/versions/<écosystème>.json` : `{"cmp": [{"a", "b", "order": -1|0|1, "why"}], "unparsable": [{"v", "why"}]}`, au moins : égalité, préversions, suffixes, longueurs différentes, zéros initiaux, valeurs hostiles. `composer.json` porte aussi `normalize: [{"in", "out"}]` repris de `composer/semver` (licence MIT citée dans le fichier et dans `failles.md`). Chaque vecteur `cmp` est vérifié dans les deux sens.
6. **Fuzz** à graine fixe (xorshift sans dépendance, comme `logs/tests.rs`) : 200 000 chaînes générées à partir d'un alphabet de jetons de version (`0`, `1`, `10`, `.`, `-`, `+`, `_`, `alpha`, `RC`, `dev`, `pl`, `v`, `x`) et d'octets hostiles ; pour chaque schéma : aucune panique ; puis 100 000 triplets de versions analysables : `cmp(a, a) = Equal`, `cmp(a, b) = cmp(b, a).reverse()`, `a ≤ b ∧ b ≤ c ⇒ a ≤ c`.
7. **Différentiel PHP** (`tests/vulns_php_diff.rs`, `#[ignore]`) : écrit les paires (vecteurs `wordpress`, `prestashop`, forme normalisée des vecteurs `composer`, et 5 000 paires du fuzz dans le domaine accepté) dans un fichier temporaire, lance `$VIGIE_PHP -r '…version_compare…'` dessus, compare chaque signe ; sans `VIGIE_PHP`, rend tôt avec un message ; avec, échoue au moindre écart en citant la paire.
8. **CI** : pas « différentiel version_compare (PHP 8.1) » dans le job Linux de `vigie.yml`, après « bout en bout », même image `php:8.1-cli@sha256:1215…f836`, `cargo test --locked --test vulns_php_diff -- --ignored`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-4 | Chaque cas « Happy path » et « non analysable » du Test Scope est un vecteur et passe |
| 5 | Cinq fichiers de vecteurs, chacun avec égalité, préversions, suffixes, longueurs différentes et valeurs hostiles ; les vecteurs de normalisation Composer passent |
| 6 | Fuzz vert, reproductible (même graine, même résultat), en moins de 10 s en debug |
| 7-8 | Le pas CI est vert sur Linux ; modifier volontairement un vecteur PHP le fait échouer (vérifié une fois à la main, noté dans la PR) |
| 1-8 | `cargo fmt --check`, `clippy --all-targets -D warnings`, `cargo test --locked` verts sur Linux et Windows ; job musl vert ; `Cargo.toml` inchangé |
