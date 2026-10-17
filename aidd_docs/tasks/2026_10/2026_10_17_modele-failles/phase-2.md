---
status: pending
---

# Instruction: purl, modèle Advisory, gravité et évaluation des plages

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── api/log_text.rs            ✏️ MAX_SUMMARY_CHARS (500), constructeur LogText::summary
    │   └── vulns/
    │       ├── mod.rs                 ✏️ réexports ; Verdict { Affected { fixed, divergence, beyond_last_known }, NotAffected, Unknown(reason) }
    │       ├── purl.rs                ✅ Purl { ty, namespace, name, version } ; parse et forme canonique ; table (écosystème OSV, nom) → Purl, traductions prestashop/* et wpackagist-*
    │       ├── advisory.rs            ✅ Advisory, Affected (scheme, last_known), Range, Event, Severity, Score { value, origin }, Reference, malicious ; from_osv(&[u8], source) -> Result<Advisory, Dropped> ; Tally
    │       ├── range.rs               ✅ évaluation OSV des plages ECOSYSTEM et SEMVER, contrôle croisé versions[], last_known, verdict
    │       └── cvss.rs                ✅ analyse des vecteurs v3.0, v3.1 et v4.0 ; score de base v3.1 seulement (aucun calcul v4)
    └── tests/
        ├── vulns_model.rs             ✅ fixtures réelles, fictives et hostiles ; fuzz du JSON ; vecteurs purl et CVSS ; ordre des scores ; verdicts
        └── fixtures/vulns/
            ├── osv/                   ✅ GHSA Composer, GHSA npm (CC-BY 4.0), RUSTSEC Cargo (CC0), publiques et non modifiées
            ├── osv/NOTICE             ✅ par fichier : source, licence, lien vers l'enregistrement, modifications (« aucune »)
            ├── fictif/                ✅ composer, npm, Packagist prestashop/* et wpackagist-*, wordpress plugin/theme/core, prestashop module/core, MAL-, versions[] divergente, last_known
            ├── hostile/               ✅ une entrée par raison d'écart, raison attendue dans le nom du fichier
            ├── purl.json              ✅ vecteurs d'analyse, de casse et de traduction
            └── cvss.json              ✅ vecteurs v3.0 et v3.1 avec score attendu ; vecteurs v4.0 valides et invalides (analyse seule)
```

## Test Scope

```mermaid
journey
  section Happy path
    GHSA Composer réelle => Advisory, purl pkg:composer en minuscules, alias CVE, CWE, score CVSS v3.1 calculé: 5: lib
    GHSA npm réelle à scope => namespace @scope, forme canonique %40scope, casse gardée: 5: lib
    RUSTSEC réelle => plage SEMVER, pkg:cargo, casse gardée: 5: lib
    Packagist prestashop/prestashop => pkg:prestashop/core/prestashop, comparateur Composer: 5: lib
    Packagist prestashop/exemplemodule => pkg:prestashop/module/exemplemodule, comparateur Composer: 5: lib
    Packagist wpackagist-plugin/exemple-plugin => pkg:wordpress/plugin/exemple-plugin, comparateur Composer: 5: lib
    Fictive Wordfence noyau => pkg:wordpress/core/core, comparateur PHP: 5: lib
    Fictive Friends-Of-Presta module à quatre composants => comparateur PHP, verdicts attendus: 5: lib
    fixed sans introduced => introduced 0 ajouté: 5: lib
  section Gravité
    provided_score Wordfence et vecteur v3.1 => score Wordfence, origine Wordfence: 5: lib
    provided_score Friends-Of-Presta et vecteur v3.1 => score FoP: 5: lib
    Vecteur v3.1 et severity HIGH => score calculé, origine CvssV31: 5: lib
    Vecteur v4 seul et severity MODERATE => 5, origine GhsaSeverity ; vecteur v4 gardé, aucun calcul: 1: lib
    Ni score ni vecteur v3 ni severity => score absent: 1: lib
    Identifiant MAL- => malicious: 1: lib
  section Verdicts
    Version dans la plage => Affected avec le fixed le plus proche: 5: lib
    Version sur last_affected => Affected ; juste au-dessus => NotAffected: 5: lib
    Préversion d'une version corrigée (2.0.0-rc.1, fixed 2.0.0) => Affected: 1: lib
    Version listée dans versions[] mais hors plages => Affected, divergence: 1: lib
    Plage ouverte, version au-delà de last_known_affected_version_range => Affected, beyond_last_known: 1: lib
    Version d'inventaire dev-main ou vide => Unknown, jamais NotAffected: 1: lib
    Borne de plage illisible => affected gardé unevaluable, verdict Unknown: 1: lib
    Plage GIT seule sans versions[] => affected ignoré, compté out_of_scope: 1: lib
  section Edge case - hostile
    Entrée withdrawn => ignorée, comptée withdrawn: 1: lib
    Entrée de 2 Mio, id de 65 caractères, alias invalide, date non RFC 3339 => écartée, raison comptée: 1: lib
    Référence javascript:, data:, user:pass@ => référence retirée et comptée, faille gardée: 1: lib
    purl invalide, espace de noms WordPress inconnu => affected écarté et compté: 1: lib
    Événement à deux clés, fixed et last_affected dans une plage => affected écarté et compté: 1: lib
    Écosystème PyPI => ignoré, compté out_of_scope: 1: lib
    Vecteur CVSS à métrique répétée ou inconnue, severity GHSA inconnue, provided_score 11 => gravité écartée et comptée, faille gardée: 1: lib
    Résumé avec ESC, U+202E et 600 caractères => U+FFFD, 500 caractères: 1: lib
  section Fuzz
    50 000 mutations des fixtures (tronque, change de type, insère des octets) => aucune panique, sortie bornée: 1: lib
```

## Tasks to do

1. **`purl.rs`** : analyse `pkg:type/namespace/name@version?qualifiers#subpath` (décodage pourcent, type en minuscules, qualificatifs et sous-chemin validés mais ignorés pour le rapprochement). Casse : **seul `composer`** est mis en minuscules ; `npm` et `cargo` gardés tels quels ; `wordpress` (espace de noms `plugin|theme|core`, slug `[a-z0-9-]`, noyau `pkg:wordpress/core/core`) et `prestashop` (`module|core`, nom technique `[A-Za-z0-9_-]`, noyau `pkg:prestashop/core/prestashop`) ; tout autre type ou espace de noms → erreur. `from_osv(ecosystem, name)` par une table unique : `Packagist` → d'abord `prestashop/prestashop` → `pkg:prestashop/core/prestashop`, `prestashop/<x>` → `pkg:prestashop/module/<x>`, `wpackagist-plugin/<slug>` → `pkg:wordpress/plugin/<slug>`, `wpackagist-theme/<slug>` → `pkg:wordpress/theme/<slug>`, sinon `pkg:composer/<vendor>/<name>` ; `npm` → `npm` ; `crates.io` → `cargo` ; autre écosystème → `OutOfScope`. Noms validés (Composer `vendor/name` à une barre, npm 214 caractères au plus, Cargo `[A-Za-z0-9_-]{1,64}`).
2. **`advisory.rs`** : désérialisation `serde` du sous-ensemble OSV (champs inconnus ignorés), puis validation vers le modèle retenu, bornes et règles du plan (« Bornes », « Références », « Écart et indétermination ») ; `withdrawn` présent → ignorée et comptée ; chaque `affected` garde le `Scheme` de l'écosystème de la source et sa `last_known_affected_version_range` analysée ; `malicious` pour un id ou alias `MAL-` ; dates par `jiff::Timestamp` → secondes Unix ; `summary` par `LogText::summary` ; CWE pris dans `database_specific.cwe_ids` ; `database_specific.severity` lu pour le dernier rang de la gravité ; `source`, `source_url` (http(s)) et `provided_score: Option<(f32, ScoreOrigin)>` passés par l'appelant (F3). `Tally` compte par raison (`too_large`, `bad_id`, `bad_date`, `bad_purl`, `bad_range`, `no_affected`, `withdrawn`, `bad_reference`, `bad_severity`, `bad_last_known`, `out_of_scope`, `unevaluable`, `purl_mismatch`) et ne contient jamais de texte de la source.
3. **`cvss.rs`** : analyse stricte des vecteurs (préfixe `CVSS:3.0/`, `CVSS:3.1/`, `CVSS:4.0/` ; chaque métrique de base une fois ; temporelles et environnementales admises et ignorées) ; score de base par la formule 3.1 (`Roundup` entier de l'annexe A) pour 3.0 et 3.1 ; **aucun calcul v4**, vecteur v4 seulement validé et gardé. `Score::select` applique l'ordre F0 (Wordfence > Friends-Of-Presta > CVSS v3.1 calculé > GHSA `CRITICAL` 9 / `HIGH` 7 / `MODERATE` 5 / `LOW` 3) et rend la valeur et son origine. Vecteurs `cvss.json` tirés des exemples de la spécification 3.1 de FIRST (origine citée dans le fichier).
4. **`range.rs`** : pré-analyse des bornes à l'import avec le comparateur de l'`affected` (marque `unevaluable`), tri des événements, pseudo-code « Evaluation » d'OSV (dont `limit`), contrôle croisé `versions[]`, drapeau `beyond_last_known`, `fixed` le plus proche rendu pour F7. `match_version(&Affected, Option<&str>) -> Verdict` : la version d'inventaire est analysée avec le comparateur de l'`affected` ; absente ou illisible → `Unknown`.
5. **Fixtures** : télécharger les trois entrées réelles depuis `osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/<ID>.json` (joignable), les garder intactes, écrire `osv/NOTICE` (source, licence, lien, modifications) ; fixtures fictives et hostiles écrites à la main, `example.org` seulement ; aucune donnée Wordfence ou Friends-Of-Presta réelle (les cas qui en imitent la forme passent par `provided_score` et des noms fictifs).
6. **Fuzz** à graine fixe des entrées JSON : mutations des fixtures, aucune panique, chaque `Advisory` retenu respecte toutes les bornes (assertion unique `assert_bounded`).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Chaque vecteur de `purl.json` passe (casse, scope npm, quatre traductions Packagist, noyaux) ; forme canonique idempotente (`canon(canon(p)) = canon(p)`) |
| 2, 5 | Les trois fixtures réelles se chargent ; `NOTICE` couvre chaque fichier de `osv/` ; chaque fixture hostile est écartée ou réduite avec exactement la raison attendue, sans panique |
| 3 | Chaque vecteur v3 de `cvss.json` donne le score attendu au dixième près ; chaque cas « Gravité » du Test Scope est un test ; aucun code ne calcule un score v4 |
| 4 | Chaque cas « Verdicts » du Test Scope est un test ; aucun chemin ne rend `NotAffected` pour une version ou une borne illisible |
| 6 | Fuzz vert et reproductible |
| 1-6 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
