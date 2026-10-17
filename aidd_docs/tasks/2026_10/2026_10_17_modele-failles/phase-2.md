---
status: pending
---

# Instruction: purl, modèle Advisory, gravité, licence et évaluation

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── api/log_text.rs            ✏️ MAX_SUMMARY_CHARS (500), MAX_ATTRIBUTION_CHARS (2 000), constructeurs summary et attribution
    │   └── vulns/
    │       ├── mod.rs                 ✏️ réexports ; Verdict { Affected { fixed, divergence, beyond_last_known }, NotAffected, Unknown(UnknownReason { VersionUnknown, RangeUnknown }) }
    │       ├── purl.rs                ✅ module purl unique (importé par F5) : grammaire commune de failles.md, parse, forme canonique ; from_osv(ecosystem, name) -> Vec<Purl> (1 ou 2)
    │       ├── advisory.rs            ✅ Draft, Advisory::build (validation unique), from_osv(&[u8], dump) ; Affected { purl, scheme, ranges, versions, last_known, unevaluable } ; Score { value, origin } ; licence_for_id ; Tally
    │       ├── range.rs               ✅ évaluation OSV par ligne, puis agrégation par faille (verdict, fixed le plus proche, divergence sur l'union)
    │       └── cvss.rs                ✅ analyse des vecteurs v3.0, v3.1, v4.0 ; score de base v3.1 seulement
    └── tests/
        ├── vulns_model.rs             ✅ fixtures réelles, fictives et hostiles ; fuzz JSON ; purl ; CVSS ; ordre des scores ; licences ; verdicts et agrégation
        └── fixtures/vulns/
            ├── purl.json              ✅ JSON simple [{in, out | null, why}] : grammaire commune, rejoué par le test PHP de l'agent (F5)
            ├── osv-purl.json          ✅ traduction (écosystème OSV, nom) → liste de purl, Rust seul
            ├── cvss.json              ✅ vecteurs v3.0 et v3.1 avec score attendu ; vecteurs v4.0 valides et invalides (analyse seule)
            ├── osv/                   ✅ GHSA Composer, GHSA npm, RUSTSEC, intacts
            ├── osv/NOTICE             ✅ par fichier : source, licence, lien, modifications (« aucune ») ; données publiques de tiers
            ├── fictif/                ✅ cas inventés (exemple/paquet, prestashop/exemplemodule, wpackagist-*, Wordfence et Friends-Of-Presta via Draft, MAL-, plusieurs affected d'un même paquet)
            └── hostile/               ✅ une entrée par raison, issue attendue dans le nom du fichier
```

## Test Scope

```mermaid
journey
  section purl
    purl.json => chaque entrée rend le purl canonique ou le rejet attendus: 5: lib
    Composer Vendor/Name => minuscules ; npm %40Scope/Name et crate Serde_X => tels quels: 5: lib
    Slug WordPress js_composer et Mon.Plugin => acceptés tels quels ; module PrestaShop avec point => rejeté: 1: lib
    Packagist prestashop/prestashop => pkg:prestashop/core/prestashop seul: 5: lib
    Packagist prestashop/exemplemodule => pkg:composer/prestashop/exemplemodule ET pkg:prestashop/module/exemplemodule, deux lignes: 5: lib
    Packagist wpackagist-plugin/exemple-plugin => pkg:wordpress/plugin/exemple-plugin, comparateur Composer: 5: lib
  section Happy path
    GHSA Composer réelle => purl, alias CVE, CWE, score CVSS v3.1 calculé, licence CC-BY-4.0: 5: lib
    GHSA npm réelle à scope => namespace @scope, licence CC-BY-4.0: 5: lib
    RUSTSEC réelle => plage SEMVER, pkg:cargo, licence CC0-1.0: 5: lib
    Draft Wordfence fictif (noyau, informational, copyrights) => pkg:wordpress/core/core, comparateur PHP, attribution assainie: 5: lib
    Draft Friends-Of-Presta fictif à quatre composants => comparateur PHP: 5: lib
  section Gravité
    provided_score Wordfence et vecteur v3.1 => score Wordfence: 5: lib
    Vecteur v3.1 et severity HIGH => score calculé, origine cvss_v31: 5: lib
    Vecteur v4 seul et severity MODERATE => 5, origine ghsa_severity ; aucun calcul v4: 1: lib
    Aucun score => score absent ; MAL- en id ou alias => malicious: 1: lib
  section Verdicts
    Version dans la plage => Affected, fixed le plus proche: 5: lib
    Plage mêlant fixed et last_affected => évaluée selon le pseudo-code OSV: 1: lib
    Deux affected du même paquet (branches 1.x et 2.x) => Affected si l'un l'est, fixed de la branche qui contient la version: 1: lib
    Un affected Affected et un unevaluable => Affected ; un NotAffected et un unevaluable => Unknown(RangeUnknown): 1: lib
    Version listée dans l'union des versions[] mais hors plages => Affected, divergence: 1: lib
    Plage ouverte, version au-delà de last_known => Affected, beyond_last_known: 1: lib
    Version d'inventaire dev-main ou absente => Unknown(VersionUnknown): 1: lib
  section Edge case - hostile
    Entrée withdrawn => ignorée, comptée: 1: lib
    Entrée de 5 Mio, id de 65 caractères, modified absent => faille écartée, raison comptée: 1: lib
    Préfixe ZZZ- => faille gardée, licence inconnue, comptée unknown_license, visible dans vulns sources et show: 1: lib
    Même id deux fois dans un chargement => seconde écartée, comptée duplicate_id: 1: lib
    Nom de paquet hors grammaire => affected écarté, compté bad_purl: 1: lib
    Paquet identifié, événement à deux clés ou borne de 129 caractères => affected gardé unevaluable, Unknown(RangeUnknown): 1: lib
    versions[] avec une entrée de 129 caractères => entrée ignorée seule ; version npm de 74 caractères acceptée, plage gardée: 1: lib
    affected PyPI ou Packagist:https://packages.drupal.org/8 dans un dump Packagist => ignoré, compté out_of_scope: 1: lib
    Référence javascript:, user:pass@ ; vecteur CVSS à métrique répétée ; provided_score 11 => retirés seuls, comptés: 1: lib
    Résumé avec ESC, U+202E et 600 caractères ; alias cve-2026-1 => U+FFFD, 500 caractères ; CVE-2026-1: 1: lib
  section Fuzz
    50 000 mutations des fixtures => aucune panique, sortie bornée: 1: lib
```

## Tasks to do

1. **`purl.rs`**, module unique importé par F5 : analyse `pkg:type/namespace/name@version?qualifiers#subpath` (décodage pourcent, type en minuscules, qualificatifs et sous-chemin validés mais hors clé de rapprochement) ; grammaire commune de `failles.md` : Composer `vendor/nom` ≤ 214 en minuscules ; npm et cargo selon leurs définitions officielles, **tels quels** ; `wordpress` (`plugin|theme` + slug `[A-Za-z0-9._-]{1,200}` tel quel, `core/core`) ; `prestashop` (`module` + `[A-Za-z0-9_-]{1,64}` tel quel, `core/prestashop`) ; version `[0-9A-Za-z.+_-]{1,128}` ; tout le reste rejeté. `from_osv(ecosystem, name) -> Result<Vec<Purl>, OutOfScope | BadName>` : `Packagist` (exact) → `prestashop/prestashop` → `pkg:prestashop/core/prestashop` ; `prestashop/<x>` → `pkg:composer/prestashop/<x>` **et** `pkg:prestashop/module/<x>` ; `wpackagist-plugin|theme/<slug>` → `pkg:wordpress/plugin|theme/<slug>` ; sinon `pkg:composer/…` ; `npm` → `npm` ; `crates.io` → `cargo` ; autre (dont `Packagist:<dépôt>`) → `OutOfScope`. `purl.json` au format simple `[{"in", "out" | null, "why"}]`, sans champ propre à Rust.
2. **`advisory.rs`** : `Draft` (champs bruts) et `Advisory::build(Draft) -> Result<Advisory, Dropped>`, seule validation, utilisée par `from_osv` et par les convertisseurs de F3 ; `from_osv(bytes, dump: SourceEcosystem)` : entrée de 4 Mio au plus, `serde` (champs inconnus ignorés), `withdrawn` ignorée, `affected` d'un autre écosystème ignorés, puis règles du plan (« Aucune suppression silencieuse », bornes mesurées, références, texte, alias normalisés) ; `modified` obligatoire, `published` facultatif ; `licence_for_id` (table fermée ; préfixe inconnu → faille gardée, licence « inconnue », comptée `unknown_license`) ; `attribution` assainie et bornée ; `informational`, `malicious`, `provided_score` ; chaque purl rendu par `from_osv` devient une ligne `Affected` portant le `scheme` de la source. `Tally` par raison (`too_large`, `bad_id`, `bad_date`, `unknown_license`, `duplicate_id`, `no_affected`, `withdrawn`, `bad_purl`, `out_of_scope`, `unevaluable`, `bad_version_entry`, `bad_reference`, `bad_severity`, `bad_last_known`, `purl_mismatch`), sans texte de la source.
3. **`cvss.rs`** : analyse stricte (`CVSS:3.0/`, `CVSS:3.1/`, `CVSS:4.0/` ; métriques de base une fois chacune ; temporelles et environnementales admises, ignorées) ; score de base v3.0 et v3.1 par la formule 3.1 ; aucun calcul v4. `Score::select` : ordre F0, valeur et origine. `cvss.json` tiré des exemples de la spécification 3.1 de FIRST (origine citée).
4. **`range.rs`** : par ligne, bornes pré-analysées à l'import (sinon `unevaluable`), tri des événements avec `Bound::Floor` en tête, pseudo-code « Evaluation » d'OSV (dont `limit`, et le mélange `fixed`/`last_affected`), `last_known` ; puis `match_advisory(lignes du purl, Option<&str>) -> Verdict` : agrégation (Affected > Unknown > NotAffected), `fixed` le plus proche parmi les lignes qui contiennent la version, `divergence` sur l'union des `versions[]`. La version d'inventaire est analysée par le comparateur de chaque ligne.
5. **Fixtures** : télécharger les trois entrées réelles depuis `osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/<ID>.json`, intactes, sur des paquets publics sans lien avec un client ; `osv/NOTICE` (source, licence, lien, modifications, « données publiques de tiers ») ; fictives et hostiles écrites à la main, `example.org` seulement ; aucune donnée Wordfence ou Friends-Of-Presta réelle (formes imitées par `Draft`).
6. **Fuzz** à graine fixe : mutations des fixtures, aucune panique, chaque `Advisory` retenu respecte toutes les bornes (`assert_bounded`).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `purl.json` et `osv-purl.json` verts ; forme canonique idempotente ; `purl.json` ne contient que `in`, `out`, `why` |
| 2, 5 | Les trois fixtures réelles se chargent avec leur licence ; `NOTICE` couvre chaque fichier ; chaque fixture hostile donne exactement l'issue attendue (écart, ligne `unevaluable`, entrée ignorée seule), sans panique |
| 3 | Vecteurs v3 au dixième près ; cas « Gravité » verts ; aucun code de calcul v4 |
| 4 | Cas « Verdicts » verts ; aucun chemin ne rend `NotAffected` pour une version ou une borne illisible |
| 6 | Fuzz vert et reproductible |
| 1-6 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
