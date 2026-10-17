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
    │       ├── build.rs                 ✅ Options { cms, omit_dev }, Entry → composant F5, hors registre, dédoublonnage, ordre global, troncature (2 000, 524 288 o), enveloppe, validate_own
    │       └── lockfile/
    │           ├── mod.rs               ✅ Kind (par nom de fichier), un_npm_par_dossier (refus, sans priorité), Entry, Parsed { entries, offregistry, ignored }, LockError (raisons fixes), bornes, lecture bornée
    │           ├── lines.rs             ✅ lecteur ligne à ligne commun (indentation, saut de bloc, collections en ligne, scalaires cités, indicateurs)
    │           ├── composer.rs          ✅ composer.lock : packages / packages-dev ; path et vcs hors registre
    │           ├── npm.rs               ✅ package-lock.json v2/v3 (règles de F5, nom réel par le champ name)
    │           ├── pnpm.rs              ✅ pnpm-lock.yaml '6.0' et '9.0'
    │           ├── yarn.rs              ✅ yarn.lock v1 (en-tête dans le bloc de commentaires) et berry (6, 8)
    │           └── cargo.rs             ✅ Cargo.lock 3 et 4 par toml, crates.io seulement
    └── tests/
        ├── inventory_lockfiles.rs       ✅ fixtures réelles → composants attendus ; refus ; fuzz à graine fixe ; parité avec l'agent PHP ; npm-alias.json ; hôtes des fixtures
        └── fixtures/
            ├── inventory/npm-alias.json ✅ vecteur commun F5 (PHP) / F6 (Rust) : [{key, entry, out | null, why}]
            └── inventory-tool/          ✅ fichiers suffixés .fixture, copiés sous leur vrai nom par les tests
                ├── NOTICE               ✅ par fichier : outil et version, commande, paquets publics, champs retirés des paquets Packagist (authors, support, funding, source, dist ; notification-url gardé), paquets WPackagist intacts et leur provenance (Composer réel, ou lockfile réel recopié), cas ajoutés à la main
                ├── composer/composer.lock.fixture        ✅ packages + packages-dev, wpackagist-plugin/theme au format de Composer (source svn, dist zip, sans notification-url), prestashop-module, v1.2.3, dev-main, notification-url de packagist.org ; cas path et vcs sans notification-url, URL sur example.org
                ├── npm-v3/package-lock.json.fixture      ✅ scope, majuscules, alias (name ≠ clé), workspace, link, extraneous, dev, devOptional, dépendance git sur example.org
                ├── npm-v2/package-lock.json.fixture      ✅ même projet en lockfileVersion 2
                ├── pnpm-v6/pnpm-lock.yaml.fixture        ✅ pnpm 8 : dev true/false, pairs (…), engines/cpu/os en ligne, tarball sur example.org, link:
                ├── pnpm-v9/pnpm-lock.yaml.fixture        ✅ pnpm 9 : packages + snapshots, importers, engines/cpu/os, workspace:, git sur example.org
                ├── yarn-v1/yarn.lock.fixture             ✅ yarn 1 : deux lignes de commentaire avant l'en-tête, plages multiples, ">=12 <14 || >=16", scope, alias npm:, file:, git sur example.org
                ├── yarn-berry/yarn.lock.fixture          ✅ yarn 4 : __metadata 8, npm:, patch:…#optional!builtin<compat/…>, conditions: os=darwin & cpu=arm64, workspace:, link:
                ├── two-lockfiles/                        ✅ composer.lock.fixture + package-lock.json.fixture (required et dev dans chacun), pour l'ordre de troncature
                ├── npm-and-yarn/                         ✅ package-lock.json.fixture + yarn.lock.fixture dans le même dossier
                ├── cargo/Cargo.lock.fixture              ✅ version 4 : crates.io, membre du workspace, chemin, git et registre tiers sur example.org
                └── expected.json                         ✅ purl, version, scope, vigie:scope, vigie:path attendus par fixture, ignorés et hors registre comptés
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
    package-lock : entrée node_modules/alias avec name = vrai => pkg:npm/vrai ; npm-alias.json rejoué => tous les vecteurs égaux: 5: lib
    yarn v1, yarn berry, pnpm 9 => tout en required ; pnpm 6 => dev lu: 5: lib
    yarn v1 à deux lignes de commentaire avant # yarn lockfile v1 => lu: 5: lib
    Alias npm (yarn, pnpm), patch:…#optional!builtin<compat/…> berry => nom réel et version npm: 5: lib
    pnpm engines/cpu/os en ligne, berry conditions: os=darwin & cpu=arm64, yarn v1 ">=12 <14 || >=16" => sautés ou lus comme texte, sans refus: 5: lib
    Cargo.lock => crates.io seulement, casse gardée, +build gardé dans la version: 5: lib
    Parité : composer.lock et package-lock.json de wp-inventory (F5) => mêmes composer/npm/wordpress que inventory-expected.json: 5: lib
    BOM construit => accepté par validate_own (Wordpress avec --cms wordpress, Generic sinon), uniquement les champs de la liste blanche, specVersion 1.7: 5: lib
  section Edge case
    Version de 129 caractères => version vide, purl sans @ (jamais tronquée) ; 128 => gardée: 1: lib
    Version à ~ ou espace => version vide: 1: lib
    Nom Composer de 215 octets, nom npm hors grammaire, crate commençant par un chiffre => écarté, skipped compté, complete false: 1: lib
    Dépendance git, file:, tarball, Composer path ou vcs, crate git ou d'un registre tiers => non émise, skipped compté, complete false: 1: lib
    Membre du workspace (npm, pnpm, yarn, Cargo) => ni émis ni compté: 1: lib
    package-lock.json et yarn.lock à la racine, sans --lockfile => refus (code 2 côté binaire), message qui nomme les deux: 1: lib
    --lockfile package-lock.json --lockfile yarn.lock du même dossier => refus ; --lockfile package-lock.json seul => lu: 1: lib
    Paquet Composer sans notification-url (path, vcs, package) => non émis, skipped compté, complete false ; avec notification-url => émis: 1: lib
    wpackagist-plugin/<slug> sans notification-url => paquet de registre, émis (pkg:wordpress avec --cms wordpress, pkg:composer sinon), skipped inchangé: 1: lib
    lockfileVersion 1, pnpm '5.4', berry 4, Cargo.lock sans version, yarn sans en-tête dans les commentaires de tête => refus, raison fixe: 1: lib
    JSON invalide, tabulation d'indentation, ancre ou alias sur une valeur lue, collection en ligne non fermée, échappement inconnu, second document => refus sans panique: 1: lib
    Clé non lue dont le bloc contient &, *, ! ou des collections en ligne => sautée, lecture réussie: 1: lib
    Scalaires cités : 'it''s', "a\"b", "é" => décodés: 1: lib
    Lockfile de 32 Mio + 1, ligne de 64 Kio + 1, 200 001 entrées (créés par le test) => refus: 1: lib
    Fuzz à graine fixe (10 000 mutations par format) => jamais de panique, Ok ou LockError: 1: lib
    Deux lockfiles, 2 001 composants (créés par le test) => tous les dev des deux retirés avant le moindre required, complete false: 1: lib
    Enveloppe de plus de 524 288 octets => composants retirés depuis la fin de l'ordre global, complete false: 1: lib
    --omit-dev qui retire au moins un composant => complete false ; sans effet sur yarn, pnpm 9, Cargo (complete inchangé): 1: lib
    Même paquet dans deux lockfiles => deux composants (vigie:path différents) ; doublon dans un même lockfile => un seul: 1: lib
    Deux constructions du même projet => même digest F5 (serialNumber et timestamp différents): 1: lib
    Fixtures => aucun hôte hors de la liste admise (question tranchée 5), de packagist.org, des hôtes wordpress.org de WPackagist et d'example.org: 1: lib
```

## Tasks to do

1. **Socle** (`inventory/lockfile/mod.rs`) : `Kind::from_file_name` (`composer.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock` ; rien d'autre) ; **un lockfile npm par dossier, sans priorité** : `un_npm_par_dossier(lockfiles, explicites: bool) -> Result<(), LockError>` ; sans `--lockfile`, plusieurs lockfiles npm (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) à la racine → erreur qui les nomme et demande d'en désigner un par `--lockfile` ; avec `--lockfile`, deux lockfiles npm d'un même dossier → erreur ; le binaire en fait un code 2 ; `read_bounded(path)` : 32 Mio au plus (taille lue par `metadata` puis lecture limitée), UTF-8 valide ; `Entry { ecosystem: PurlType, namespace: Option<String>, name: String, version: String, dev: bool }` (brut, avant validation) ; `Parsed { entries, offregistry: usize, ignored: usize }` (`offregistry` va dans `skipped`, `ignored` = membres du projet, affiché seulement) ; `LockError` à raisons fixes (`format inconnu`, `version de format non gérée`, `JSON illisible`, `structure inattendue ligne N`, `trop gros`, `trop d'entrées`), sans jamais recopier d'octet du fichier. Bornes : 200 000 entrées, ligne de 64 Kio, profondeur JSON bornée par la limite de récursion par défaut de `serde_json` (128, jamais désactivée) ; lecture en structures typées (champs utiles seulement, `IgnoredAny` pour le reste).
2. **Lecteur ligne à ligne** (`lockfile/lines.rs`), commun à pnpm et berry, ses fonctions de citation reprises par yarn v1 :
   - indentation comptée en espaces ; tabulation dans l'indentation → refus ;
   - `skip_block(indent)` : toute ligne plus indentée que la clé courante est sautée sans être analysée (blocs `engines`, `cpu`, `os`, `peerDependencies`, `conditions`, `dependenciesMeta`, `bin`…) ;
   - valeur en ligne `{…}`/`[…]` d'une clé non lue : parcours équilibré qui saute les chaînes citées, refus si non fermée sur la ligne ;
   - scalaires cités : `'…'` avec `''` → `'` ; `"…"` avec `\\`, `\"`, `\/`, `\n`, `\t`, `\uXXXX` (paire de substitution comprise) ; autre échappement → refus ;
   - indicateurs `&`, `*`, `!`, `|`, `>` : refus **seulement** comme premier caractère d'une clé ou d'un scalaire non cité qui est lu (clés de structure, clés d'entrée, `version`, `resolution`, `dev`, `lockfileVersion`, `__metadata.version`) ; ailleurs, texte ;
   - `---` en tête admis une fois, un second document → refus ; commentaires `#` en début de ligne ignorés.
3. **composer.rs** : objet racine ; `packages` et `packages-dev` (tableaux, absents = vides) ; chaque paquet : `name`, `version`, `type`, présence de `notification-url` ; autres champs ignorés. **Un paquet vient d'un registre si et seulement si `notification-url` est présent ou son nom commence par `wpackagist-plugin/` ou `wpackagist-theme/`** (WPackagist n'écrit pas de `notification-url`) ; sinon (`path`, vcs, `package` en ligne) il est hors registre, non émis et compté dans `skipped`. Même règle côté F5 (note pour F5 du plan). `name` de plus de 214 octets écarté avant tout découpage ; `vendor/nom` → `Entry` composer ; `type` gardé pour `build.rs`.
4. **npm.rs** : `lockfileVersion` 2 ou 3 ; `packages` : clé `""` ignorée (projet), clés hors `node_modules/` (workspaces) ignorées, `link: true` ignorée, `extraneous: true` ignorée ; **nom = champ `name` de l'entrée s'il existe, sinon ce qui suit le dernier `node_modules/` de la clé** (question tranchée 2) ; `dev: true` → dev, `devOptional: true` → required ; `resolved` qui commence par `git+`, `git:`, `github:` ou `file:`, ou URL qui n'a pas la forme d'une archive de registre (`…/-/<fichier>.tgz`) → hors registre ; version brute.
5. **Vecteur commun** `vigie/tests/fixtures/inventory/npm-alias.json` : `[{"key": "node_modules/…", "entry": {…}, "out": "pkg:npm/…@…" | null, "why": "…"}]` : alias simple, alias scopé (`name` = `@scope/vrai`), alias imbriqué (`node_modules/a/node_modules/b`), `name` absent, `name` hors grammaire (`out` null). Rejoué par `inventory_lockfiles.rs` ; **F5 l'ajoute à `AgentTest.php`** (note pour F5 du plan). Le fichier ne contient que `key`, `entry`, `out`, `why`.
6. **pnpm.rs** (sur `lines.rs`) : `lockfileVersion: '6.0'` ou `'9.0'` (cité ou non) ; sections de niveau 0 : seule `packages` est lue, toutes les autres (`settings`, `importers`, `snapshots`, `catalogs`, `overrides`, `patchedDependencies`…) sautées par indentation. Clés d'entrée à deux espaces : v6 `/nom@version` ou `/@scope/nom@version`, v9 `nom@version` ou `'@scope/nom@version'` ; suffixes de pairs `(…)` retirés ; `nom@npm:vrai@v` → nom réel ; dans l'entrée, seuls `dev` (v6) et `resolution` sont lus, le reste sauté ; `resolution` avec `tarball:` hors registre, `directory:`, `type: git`, ou version `file:`, `git+`, contenant `://` → hors registre ; `link:` et `workspace:` → membre du projet.
7. **yarn.rs** : **v1** si une ligne `# yarn lockfile v1` figure dans le **bloc de commentaires de tête** (lignes `#` et vides avant la première entrée), sinon refus ; entrée = ligne à la colonne 0 finissant par `:` (spécificateurs séparés par `, `, cités ou non, décodés) puis `  version "x"` ; nom tiré du premier spécificateur (dernier `@` après la position 1) ; plage `npm:vrai@^1` → nom réel ; plages `file:`, `git`, `http(s)://`, `github:` → hors registre ; `link:` → membre du projet ; autres lignes de l'entrée (`dependencies`, `optionalDependencies`, plages avec `||`, `<`, `>`) sautées. **Berry** si `__metadata:` avec `version: 6` ou `8` ; entrée = clé citée de niveau 0 ; seul `resolution` est lu (le reste, dont `conditions`, `dependencies`, `checksum`, `bin`, sauté) : `nom@npm:1.2.3` → nom et version ; `nom@patch:nom@npm%3A1.2.3#…` (y compris `#optional!builtin<compat/…>`) → `nom`, `1.2.3` (décodage `%3A` seulement) ; `workspace:`, `portal:`, `link:` → membre ; `file:`, `exec:`, git, URL → hors registre. Aucun `dev` : tout `required`.
8. **cargo.rs** : `toml::from_str` sur une structure minimale qui ignore les champs inconnus (`checksum`, `dependencies`), `version` racine exigée ∈ {3, 4} ; `[[package]]` : `name`, `version`, `source` ; `source` absent → membre du projet ; `registry+https://github.com/rust-lang/crates.io-index` ou `sparse+https://index.crates.io/…` → `Entry` cargo ; tout autre `source` (git, autre registre) → hors registre.
9. **build.rs** :
   - `Options { cms: Option<Cms>, omit_dev: bool }`, `Cms::Wordpress` seul ;
   - chaque `Entry` → `Purl::new(ty, ns, name, version_ok)` où `version_ok = in_grammar(version.trim()).then_some(...)` (jamais tronquée) ; nom refusé → `skipped += 1` ; hors registre → `skipped += offregistry` ; `--cms wordpress` : `wpackagist-plugin|theme/<slug>` → `Purl::new(Wordpress, Some("plugin"|"theme"), slug, v)` ;
   - `vigie:path` = chemin du lockfile relatif au projet (calculé par l'appelant, validé ici selon la règle F5) ; `vigie:scope` `dev` → `scope: excluded`, sinon `required` ;
   - `--omit-dev` : composants `dev` retirés ; s'il en retire un, `complete = false` ;
   - dédoublonnage : `pkg:wordpress` un par purl sans version ; sinon un par `(purl complet, vigie:path)` ;
   - **ordre global** : tous les `required` de tous les lockfiles (lockfiles dans l'ordre de réception, ordre du fichier dans chacun), puis tous les `dev` dans le même ordre ;
   - troncature depuis la fin de cet ordre : 2 000 composants, puis taille de chaque composant encodé mesurée une fois et retrait tant que l'enveloppe dépasse 524 288 octets (règle F5) ; `complete = skipped == 0 && !omis && !tronqué` ;
   - `build_bom(site_name, components, now, serial)` et `build_envelope(site, seq, sent_at, bom, complete, skipped)` avec `source: Ci`, `agent: vigie-inventory/<TOOL_VERSION>`, `specVersion: "1.7"`, `metadata.timestamp` RFC 3339 UTC (`iso_utc`), `serialNumber` `urn:uuid:` + UUID v4 minuscule (aléa injecté) ;
   - `validate_own(&Envelope, cms)` : sérialise puis repasse par la validation de `bom.rs` de F5 avec le même site et `SiteKind::Wordpress` si `cms = Some(Wordpress)`, sinon `SiteKind::Generic` ; tout composant écarté, `dropped > 0` ou document refusé est une erreur interne.
10. **Fixtures** (`tests/fixtures/inventory-tool/`) : petits projets fictifs `exemple-app` (aucun nom de client), dépendances publiques choisies pour couvrir chaque cas ; lockfiles produits par composer 2.x, npm 10, pnpm 8 et 9, yarn 1 et 4, cargo stable (versions exactes dans `NOTICE`) ; `composer.lock` : paquets Packagist nettoyés de `authors`, `support`, `funding`, `homepage`, `description`, `source` et `dist` (retraits notés dans `NOTICE`), **`notification-url` gardé** (`https://packagist.org/downloads/`) ; **paquets WPackagist intacts**, au format exact de Composer (`source` svn, `dist` zip, sans `notification-url`), sans aucun champ ajouté à la main : produits par un vrai `composer update` à l'implémentation, ou à défaut recopiés d'un lockfile réel **d'un projet public** (jamais d'un client) dont la provenance est écrite dans `NOTICE` ; **vérifier aussi, sur un lockfile réel, le format des autres dépôts Composer publics** (par exemple asset-packagist, `packages.drupal.org`, dépôts Satis publics) et consigner les écarts à la règle de registre dans `decisions.md` ; cas impossibles à produire sans réseau privé (workspace, link, git, `path`, vcs, registre tiers) ajoutés à la main avec des URL sur `example.org` (`https://git.example.org/exemple/lib.git`, `https://registry.example.org/…`), signalés dans `NOTICE`. **Suffixe `.fixture`** sur chaque lockfile ; un utilitaire de test les copie sous leur vrai nom dans un dossier temporaire. `expected.json` écrit à la main, jamais régénéré par le code testé.
11. **Hôtes des fixtures** : test de la question tranchée 5 sur `tests/fixtures/inventory-tool/` : toute URL trouvée a pour hôte `registry.npmjs.org`, `registry.yarnpkg.com`, `index.crates.io`, `github.com` (chemin `/rust-lang/crates.io-index` seulement), `packagist.org` (`notification-url`), `plugins.svn.wordpress.org`, `themes.svn.wordpress.org`, `downloads.wordpress.org` (paquets WPackagist), `wordpress.org` (chemins `/plugins/` et `/themes/` seulement : `homepage` des paquets WPackagist, laissés intacts), ou `example.org` et ses sous-domaines ; tout autre hôte fait échouer.
12. **Parité avec l'agent** : `inventory_lockfiles.rs` lit `vigie/agent/php/tests/fixtures/wp-inventory/composer.lock` et `package-lock.json` (F5), construit avec `--cms wordpress`, et compare purl, version, `scope`, `vigie:scope` aux entrées venues du lockfile dans `inventory-expected.json` (le relevé sur disque de l'agent, qui l'emporte, est exclu). Tout écart échoue.
13. **Fuzz** : générateur xorshift à graine fixe (forme de `logs/tests.rs`), 10 000 mutations par format (octets retournés, lignes dupliquées, tronquées, indentation changée, guillemets ouverts) ; chaque lecteur rend `Ok` ou `LockError`, jamais de panique (`std::panic::catch_unwind` en filet).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Aucun `LockError` ne contient d'octet du fichier (test avec un fichier qui contient `secret-xyz`) ; `grep -rn "fn canonical" vigie/src` ne trouve qu'une définition, dans `vulns/purl.rs` ; dossier `npm-and-yarn` : refus sans `--lockfile`, lecture avec un seul `--lockfile`, refus avec les deux |
| 2 | Chaque règle du lecteur a son test unitaire (saut de bloc, collection en ligne équilibrée avec `}` dans une chaîne, `''`, échappements, indicateur refusé sur une valeur lue et admis dans un bloc sauté) |
| 3-8 | Chaque fixture donne exactement `expected.json` (composants, membres ignorés, hors registre comptés) ; chaque refus listé dans le Test Scope est un test ; aucune dépendance ajoutée (`git diff` de `vigie/Cargo.toml` et `Cargo.lock` vide) |
| 5 | `npm-alias.json` vert côté Rust, ne contient que `key`, `entry`, `out`, `why` |
| 9 | Version de 129 caractères → version vide ; nom de 215 octets → écarté et compté ; dossier `two-lockfiles` gonflé à 2 001 → aucun `required` retiré tant qu'il reste un `dev`, `complete = false` ; enveloppe ≤ 524 288 octets ; `--omit-dev` qui retire → `complete = false` ; digest stable sur deux constructions |
| 9 | Le BOM sérialisé ne contient que les clés de la liste blanche (comparaison récursive) et passe `validate_own` avec `dropped = 0`, en `Generic` et en `Wordpress` |
| 10-11 | Aucun fichier de `tests/fixtures/inventory-tool/` ne porte un nom de lockfile reconnu par GitHub (`git ls-files` filtré) ; test des hôtes vert |
| 12 | Parité verte ; un écart volontaire (version modifiée dans une copie) la fait échouer |
| 13 | Fuzz vert sous Linux et Windows en moins de 30 s ; commit `feat(inventory): lecture des lockfiles et BOM CycloneDX (#20)` |
