---
status: pending
---

# Instruction: Lecture des lockfiles et construction du BOM (bibliothèque, sans réseau)

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── vulns/purl.rs                ➖ module de F1, importé tel quel (Purl::new, canonical, PurlType)
    │   ├── vulns/version/mod.rs         ➖ in_grammar de F1, importé tel quel
    │   └── inventory/
    │       ├── mod.rs                   ✏️ TOOL_VERSION ; pub mod lockfile, build
    │       ├── bom.rs                   ✏️ Serialize sur les structures de F5 (mêmes noms de champs), aucune règle changée
    │       ├── build.rs                 ✅ Options { cms, omit_dev }, Component brut → composant F5, dédoublonnage, ordre, troncature (2 000, 524 288 o), enveloppe, revalidation par bom.rs
    │       └── lockfile/
    │           ├── mod.rs               ✅ Kind (par nom de fichier), Entry { ecosystem, name, version, dev }, Parsed { entries, ignored }, LockError (raisons fixes), bornes, lecture bornée
    │           ├── composer.rs          ✅ composer.lock : packages / packages-dev
    │           ├── npm.rs               ✅ package-lock.json v2/v3 (règles de F5)
    │           ├── pnpm.rs              ✅ pnpm-lock.yaml '6.0' et '9.0', lecteur ligne à ligne
    │           ├── yarn.rs              ✅ yarn.lock v1 et berry (6, 8), lecteur ligne à ligne
    │           └── cargo.rs             ✅ Cargo.lock 3 et 4 par toml, crates.io seulement
    └── tests/
        ├── inventory_lockfiles.rs       ✅ fixtures réelles → composants attendus ; refus ; fuzz à graine fixe ; parité avec l'agent PHP
        └── fixtures/inventory-tool/
            ├── NOTICE                   ✅ par fichier : outil et version, commande, paquets publics, champs retirés
            ├── composer/composer.lock   ✅ exemple-app : packages + packages-dev, wpackagist-plugin, wpackagist-theme, prestashop-module, version v1.2.3, dev-main
            ├── npm-v3/package-lock.json ✅ scope, majuscules, workspace, link, extraneous, dev, devOptional
            ├── npm-v2/package-lock.json ✅ même projet en lockfileVersion 2
            ├── pnpm-v6/pnpm-lock.yaml   ✅ pnpm 8 : dev true/false, pairs (…), tarball, link:
            ├── pnpm-v9/pnpm-lock.yaml   ✅ pnpm 9 : packages + snapshots, importers, workspace:, git
            ├── yarn-v1/yarn.lock        ✅ yarn 1 : plusieurs plages par entrée, scope, alias npm:, file:, git
            ├── yarn-berry/yarn.lock     ✅ yarn 4 : __metadata 8, npm:, patch:, workspace:, link:
            ├── cargo/Cargo.lock         ✅ version 4 : crates.io, membre du workspace, chemin, git, registre tiers
            └── expected.json            ✅ purl, version, scope, vigie:scope, vigie:path attendus par fixture, et nombre d'ignorés
```

## Test Scope

```mermaid
journey
  section Happy path
    Chaque fixture réelle => liste de composants égale à expected.json (purl canonique F1, version, scope, vigie:scope, vigie:path): 5: lib
    composer.lock => vendor/nom en minuscules, packages-dev en excluded/dev: 5: lib
    composer.lock avec --cms wordpress => wpackagist-* en pkg:wordpress, un par purl sans version ; sans l'option => pkg:composer: 5: lib
    prestashop-module => toujours pkg:composer/prestashop/<x>: 5: lib
    package-lock v2 et v3 du même projet => mêmes composants: 5: lib
    yarn v1, yarn berry, pnpm 9 => tout en required ; pnpm 6 => dev lu: 5: lib
    Alias npm (yarn, pnpm), patch: berry => nom réel et version npm: 5: lib
    Cargo.lock => crates.io seulement, casse gardée, +build gardé dans la version: 5: lib
    Parité : composer.lock et package-lock.json de wp-inventory (F5) => mêmes composer/npm que inventory-expected.json: 5: lib
    BOM construit => accepté par la validation de bom.rs, uniquement les champs de la liste blanche, specVersion 1.7: 5: lib
  section Edge case
    Version de 129 caractères => version vide, purl sans @ (jamais tronquée) ; 128 => gardée: 1: lib
    Version à ~ ou espace => version vide: 1: lib
    Nom Composer de 215 octets, nom npm hors grammaire, crate commençant par un chiffre => écarté, skipped compté, complete false: 1: lib
    lockfileVersion 1, pnpm '5.4', berry 4, Cargo.lock sans version => refus (code 2 côté binaire), raison fixe: 1: lib
    JSON invalide, YAML avec tabulation, ancre ou alias, yarn sans en-tête => refus sans panique: 1: lib
    Lockfile de 32 Mio + 1, ligne de 64 Kio + 1, 200 001 entrées (créés par le test) => refus: 1: lib
    Fuzz à graine fixe (10 000 mutations par format) => jamais de panique, Ok ou LockError: 1: lib
    2 001 composants (créés par le test) => 2 000 gardés, dev retirés d'abord, complete false: 1: lib
    Enveloppe de plus de 524 288 octets => composants retirés depuis la fin, complete false: 1: lib
    Même paquet dans deux lockfiles => deux composants (vigie:path différents) ; doublon dans un même lockfile => un seul: 1: lib
    --omit-dev => aucun composant dev ; sans effet sur yarn, pnpm 9, Cargo: 1: lib
    Deux constructions du même projet => même digest F5 (serialNumber et timestamp différents): 1: lib
```

## Tasks to do

1. **Socle** (`inventory/lockfile/mod.rs`) : `Kind::from_file_name` (`composer.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock` ; rien d'autre) ; `read_bounded(path)` : 32 Mio au plus (taille lue par `metadata` puis lecture limitée), UTF-8 valide ; `Entry { ecosystem: PurlType, namespace: Option<String>, name: String, version: String, dev: bool }` (brut, avant validation) ; `Parsed { entries, ignored: usize }` ; `LockError` à raisons fixes (`format inconnu`, `version de format non gérée`, `JSON illisible`, `structure inattendue ligne N`, `trop gros`, `trop d'entrées`), sans jamais recopier d'octet du fichier. Bornes : 200 000 entrées, ligne de 64 Kio, profondeur JSON bornée par la limite de récursion par défaut de `serde_json` (128, jamais désactivée) ; lecture en structures typées (champs utiles seulement, `IgnoredAny` pour le reste), jamais en `serde_json::Value` entière.
2. **composer.rs** : objet racine ; `packages` et `packages-dev` (tableaux, absents = vides) ; chaque paquet : `name` (chaîne), `version` (chaîne), `type` (facultatif) ; autres champs ignorés. `name` de plus de 214 octets écarté avant tout découpage ; `vendor/nom` → `Entry` composer ; `type` gardé pour `build.rs` (aucune correspondance PrestaShop, cf. plan).
3. **npm.rs** : `lockfileVersion` 2 ou 3 ; `packages` : clé `""` ignorée, clés hors `node_modules/` (workspaces) ignorées, `link: true` et `extraneous: true` ignorés ; nom = ce qui suit le dernier `node_modules/` ; `dev: true` → dev, `devOptional: true` → required ; version brute. Règles **identiques** au point 7 de la phase 2 du plan F5.
4. **pnpm.rs** (ligne à ligne) : première ligne utile `lockfileVersion: '6.0'` ou `'9.0'` (citée ou non) ; un seul document (un second `---` → refus, à revoir sur pnpm 10) ; sections de niveau 0 connues (`settings`, `importers`, `packages`, `snapshots`, `dependencies`, `devDependencies`, `optionalDependencies`, `overrides`, `patchedDependencies`, `catalogs`, …) parcourues ; seule `packages` est lue en v6, `packages` (versions) en v9. Clés d'entrée à deux espaces : v6 `/nom@version` ou `/@scope/nom@version`, v9 `nom@version` ou `'@scope/nom@version'` ; suffixes de pairs `(…)` retirés ; champ `dev: true|false` lu en v6 (4 espaces) ; `resolution` sans `integrity` (`tarball:`, `directory:`, `type: git`) → ignoré ; version qui commence par `link:`, `file:`, `workspace:` ou contient `://` → ignoré. Refus : tabulation, `&`, `*`, `!`, `|`, `>` en valeur, indentation inattendue.
5. **yarn.rs** : v1 si la première ligne non vide est `# yarn lockfile v1` (commentaires suivants admis) ; entrée = ligne à la colonne 0 finissant par `:` (spécificateurs séparés par `, `, cités ou non) puis `  version "x"` ; nom tiré du premier spécificateur (dernier `@` après la position 1) ; plage `npm:vrai@^1` → nom réel ; plages `file:`, `link:`, `git`, `http(s)://`, `github:` → ignoré. Berry si `__metadata:` avec `version: 6` ou `8` ; entrée = clé citée de niveau 0 ; `resolution: "nom@npm:1.2.3"` → nom et version ; `patch:nom@npm%3A1.2.3#…` → `nom`, `1.2.3` (décodage `%3A` seulement) ; autres protocoles ignorés ; `languageName: unknown` (workspace) ignoré. Aucun `dev` : tout `required`.
6. **cargo.rs** : `toml::from_str` sur une structure minimale qui ignore les champs inconnus (Cargo en ajoute, `checksum`, `dependencies`), avec `version` racine exigée ∈ {3, 4} ; `[[package]]` : `name`, `version`, `source` ; gardé seulement si `source` vaut `registry+https://github.com/rust-lang/crates.io-index` ou commence par `sparse+https://index.crates.io/` ; sinon ignoré.
7. **build.rs** :
   - `Options { cms: Option<Cms>, omit_dev: bool }`, `Cms::Wordpress` seul ;
   - chaque `Entry` → `Purl::new(ty, ns, name, version_ok)` où `version_ok = in_grammar(version.trim()).then_some(...)` (jamais tronquée) ; nom refusé → `skipped += 1` ; `--cms wordpress` : `wpackagist-plugin|theme/<slug>` → `Purl::new(Wordpress, Some("plugin"|"theme"), slug, v)` ;
   - `vigie:path` = chemin du lockfile relatif au projet (calculé par l'appelant, validé ici selon la règle F5) ; `vigie:scope` `dev` → `scope: excluded`, sinon `required` ;
   - dédoublonnage : `pkg:wordpress` un par purl sans version ; sinon un par `(purl complet, vigie:path)` ;
   - ordre : lockfiles dans l'ordre reçu, `required` puis `dev` dans chacun, ordre du fichier ensuite ;
   - troncature : 2 000 composants, puis taille de chaque composant encodé mesurée une fois et retrait depuis la fin tant que l'enveloppe dépasse 524 288 octets (règle F5) ; `complete = skipped == 0 && !tronqué` ;
   - `build_bom(site_name, components, now, serial)` et `build_envelope(site, seq, sent_at, bom, complete, skipped)` avec `source: Ci`, `agent: vigie-inventory/<TOOL_VERSION>`, `specVersion: "1.7"`, `metadata.timestamp` RFC 3339 UTC (`iso_utc`), `serialNumber` `urn:uuid:` + UUID v4 minuscule (aléa injecté) ;
   - `validate_own(&Envelope)` : sérialise puis repasse par la validation de `bom.rs` de F5 avec le même site ; tout écart (composant écarté, document refusé, `dropped > 0`) est une erreur interne.
8. **Fixtures** : petits projets fictifs `exemple-app` (aucun nom de client), dépendances publiques choisies pour couvrir chaque cas (scope npm, majuscules, alias, pairs pnpm, crate à majuscules si disponible) ; lockfiles produits par composer 2.x, npm 10, pnpm 8 et 9, yarn 1 et 4, cargo stable (versions exactes dans `NOTICE`) ; `authors`, `support`, `funding`, `notification-url` retirés de `composer.lock` (modification écrite dans `NOTICE`) ; cas impossibles à produire par l'outil (workspace, link, registre tiers, git) ajoutés à la main et signalés dans `NOTICE`. `expected.json` écrit à la main, jamais régénéré par le code testé.
9. **Parité avec l'agent** : `tests/inventory_lockfiles.rs` lit `vigie/agent/php/tests/fixtures/wp-inventory/composer.lock` et `package-lock.json` (F5), construit avec `--cms wordpress`, et compare purl, version, `scope`, `vigie:scope` aux entrées `composer`, `npm` et `wordpress` venues du lockfile dans `inventory-expected.json` (le relevé sur disque de l'agent, qui l'emporte, est exclu de la comparaison). Tout écart échoue.
10. **Fuzz** : générateur xorshift à graine fixe (forme de `logs/tests.rs`), 10 000 mutations par format (octets retournés, lignes dupliquées, tronquées, indentation changée) ; chaque lecteur rend `Ok` ou `LockError`, jamais de panique (`std::panic::catch_unwind` en filet).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Aucun `LockError` ne contient d'octet du fichier (test avec un fichier qui contient `secret-xyz`) ; `grep -rn "fn canonical" vigie/src` ne trouve qu'une définition, dans `vulns/purl.rs` |
| 2-6 | Chaque fixture donne exactement `expected.json` (composants et nombre d'ignorés) ; chaque refus listé dans le Test Scope est un test |
| 4-5 | Aucune dépendance ajoutée à `vigie/Cargo.toml` (`git diff` de `Cargo.toml` et `Cargo.lock` vide) |
| 7 | Version de 129 caractères → version vide ; nom de 215 octets → écarté et compté ; 2 001 → 2 000 et `complete = false` ; enveloppe ≤ 524 288 octets ; digest stable sur deux constructions |
| 7 | Le BOM sérialisé ne contient que les clés de la liste blanche (comparaison récursive) et passe la validation de `bom.rs` avec `dropped = 0` |
| 9 | Parité verte ; un écart volontaire (version modifiée dans une copie) la fait échouer |
| 10 | Fuzz vert sous Linux et Windows en moins de 30 s ; commit `feat(inventory): lecture des lockfiles et BOM CycloneDX (#20)` |
