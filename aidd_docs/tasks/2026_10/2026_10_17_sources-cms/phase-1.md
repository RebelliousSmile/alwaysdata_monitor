---
status: pending
---

# Instruction: Convertisseur Wordfence Intelligence v3

Convertisseur pur, sans réseau ni base : octets du flux `production` → `Advisory` de F1, écarts comptés. Ne dépend que de F1.

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   └── vulns/
    │       ├── mod.rs                     ✏️ pub mod sources
    │       ├── advisory.rs                ✏️ (F1) borne « plages par ligne » selon SourceEcosystem : 16 OSV, 256 Wordfence ; raisons de Tally ajoutées : attribution_overflow, no_copyrights
    │       └── sources/
    │           ├── mod.rs                 ✅ rôle des convertisseurs ; Redistribution { Internal, FactsOnly, Free } et redistribution(source_id) (table fermée, testée)
    │           └── wordfence.rs           ✅ WfRecord (serde, champs inconnus ignorés) ; parse_feed(impl Read, sink, tally) en flux : Visitor sur l'objet racine, lecteur compteur borné par valeur ; to_draft(WfRecord) ; attribution(copyrights) ; record_url(uuid) ; WORDFENCE_TERMS_REVIEWED: Option<&str> = None
    └── tests/
        ├── vulns_wordfence.rs             ✅ conversion champ par champ, bornes, hostiles, fuzz, cohérence constante ↔ failles.md
        └── fixtures/vulns/wordfence/
            ├── README                     ✅ « données fictives, même structure que le flux production v3 ; aucun enregistrement réel »
            ├── production.json            ✅ flux fictif : extension, thème, noyau à plusieurs branches, informational, sans correctif, borne exclusive, joker, mention MITRE
            └── hostile/                   ✅ une entrée par raison, issue attendue dans le nom du fichier
```

## Test Scope

```mermaid
journey
  section Happy path
    Extension exemple-plugin, * - 1.2.3 inclusif, patched 1.2.4 => pkg:wordpress/plugin/exemple-plugin, Floor, last_affected 1.2.3, fixed 1.2.4, scheme php: 5: lib
    Thème exemple-theme, 2.0 inclusif - 2.1 exclusif => pkg:wordpress/theme/exemple-theme, introduced 2.0, fixed 2.1: 5: lib
    Noyau, 40 branches 3.7 - 3.7.39 … 6.4 - 6.4.1 => pkg:wordpress/core/core, une plage par branche, évaluable: 5: lib
    Id WF-<uuid>, aliases CVE-2099-0001, CWE-79, références, published et updated => champs du modèle: 5: lib
    cvss score 6.1 et vecteur 3.1 => provided_score 6.1, origine wordfence: 5: lib
    copyrights message, defiant et mitre => attribution assemblée dans l'ordre de la source, lien de l'enregistrement: 5: lib
    source_url => https://www.wordfence.com/threat-intel/vulnerabilities/id/<uuid>: 5: lib
  section Verdicts sur les fixtures
    exemple-plugin 1.2.3 => Affected, fixed 1.2.4 ; 1.2.4 => NotAffected: 5: lib
    exemple-plugin 1.2.3.1 (quatre composants) => NotAffected selon version_compare: 1: lib
    Noyau 6.4.1 => Affected ; 6.4.2 => NotAffected: 5: lib
    to_version * et patched false => Affected sans fixed (aucun correctif): 1: lib
    from_inclusive false sur 2.0 => 2.0 Affected (borne prudente, limite écrite): 1: lib
    informational true sans score => informational porté, score absent: 1: lib
  section Edge case - hostile
    Clé de l'objet différente de id, id non UUID => faille écartée, bad_id: 1: lib
    software type plugin-premium => ligne écartée, out_of_scope ; slug avec espace => bad_purl: 1: lib
    Toutes les lignes écartées => faille écartée, no_affected: 1: lib
    from_version 2.0 > to_version 1.0 ou borne 1.0-bogus => ligne gardée unevaluable, Unknown(RangeUnknown): 1: lib
    257 libellés dans affected_versions => ligne unevaluable, jamais écartée: 1: lib
    patched true sans patched_versions supérieure => aucun fixed, aucune erreur: 1: lib
    copyrights absent ou attribution de 2 001 caractères => faille gardée, mention fixe, no_copyrights ou attribution_overflow: 1: lib
    Valeur de 5 Mio ou JSON racine tronqué => erreur de flux, chargement abandonné, génération active intacte (côté F2): 1: lib
    Date 2099-13-45 ou absente partout => bad_date ; format AAAA-MM-JJ hh:mm:ss => lu en UTC: 1: lib
    cvss score 11 => ignoré seul, bad_severity ; vecteur v3.1 gardé: 1: lib
    Même uuid deux fois => seconde écartée, duplicate_id: 1: lib
    Titre avec ESC, U+202E, 600 caractères => assaini, 500 caractères: 1: lib
  section Fuzz
    50 000 mutations du flux fictif => aucune panique, chaque Advisory borné: 1: lib
  section Verrou
    WORDFENCE_TERMS_REVIEWED = None et failles.md « non faite » => cohérents: 5: lib
```

## Tasks to do

1. **`sources/mod.rs`** : `Redistribution` et `redistribution(source_id) -> Redistribution` (`wordfence` → `Internal`, `friends-of-presta` → `FactsOnly`, identifiants OSV de F2 → `Free`, inconnu → `Internal`, le plus restrictif) ; documentation de ce que chaque niveau permet (renvoi à « Redistribution, affichage et fixtures » de `failles.md`).
2. **`wordfence.rs`, lecture** : `parse_feed(reader, sink, tally)` ; `serde_json::Deserializer::from_reader` ; `Visitor` serde sur l'objet racine, entrée par entrée (clé `String`, valeur désérialisée en `WfRecord`) ; lecteur compteur remis à zéro à chaque entrée : valeur de plus de 4 Mio → erreur de flux `EntryTooLarge` ; `WfRecord` en `serde` avec champs inconnus ignorés (`IgnoredAny`), types attendus stricts (un champ de mauvais type écarte la faille : `bad_record`) ; erreur de syntaxe au niveau racine → `Err(FeedError)` (le cadre F2 abandonne alors le chargement, génération active intacte). Plafond d'entrées : 200 000 (`too_many_entries`, erreur de flux).
3. **`wordfence.rs`, conversion** `to_draft(key, WfRecord) -> Result<Draft, Dropped>` selon le tableau « Conversion Wordfence » du plan : id `WF-<uuid>` (clé = `id`, UUID en minuscules), alias CVE, une ligne par `software[]` (purl, `scheme` PHP), une plage par libellé (`*` → `Bound::Floor` ou plage ouverte, `from_inclusive: false` traduit en inclusive, `to_inclusive` → `last_affected` ou `fixed`), `fixed` tiré de `patched_versions` (plus petite version strictement supérieure à `to_version`, comparateur PHP), bornes illisibles ou inversées → `unevaluable` ; dates RFC 3339 ou `AAAA-MM-JJ hh:mm:ss` en UTC ; `modified` = `updated`, sinon `published`, sinon `bad_date` ; `provided_score`, vecteur, CWE, références, `informational`, `source_url`. Tout passe par `Advisory::build`.
4. **Attribution** : `attribution(copyrights, url) -> (String, Option<Reason>)` : `message`, puis par clé dans l'ordre de la source `notice`, `license`, `license_url`, séparés par des sauts de ligne, assainis par `LogText` ; > 2 000 caractères ou vide → mention fixe « Wordfence Intelligence, © Defiant Inc. — <url> » et raison comptée. Licence de la faille : `Wordfence-Intelligence` (chaîne fixe, la licence exacte est dans l'attribution).
5. **F1, borne par source** : `MAX_RANGES_PER_AFFECTED` devient une fonction du `SourceEcosystem` (16 pour `Packagist`, `npm`, `crates.io` ; 256 pour Wordfence ; Friends-Of-Presta : 16) ; les tests F1 existants restent verts.
6. **Verrou** : `WORDFENCE_TERMS_REVIEWED: Option<&str> = None` ; test `terms_review_matches_failles_md` qui lit `vigie/docs/failles.md`, trouve la ligne « Relecture des conditions depuis le VPS » et exige `non faite` ↔ `None`, `faite le AAAA-MM-JJ` ↔ `Some` de la même date (date valide, pas dans le futur du commit).
7. **Fixtures fictives** : `production.json` (une quinzaine d'entrées couvrant le Test Scope ; slugs `exemple-plugin`, `exemple-theme`, CVE `CVE-2099-…`, références `https://example.org/…`, `copyrights` inventés de même forme que la fiche de `failles.md`) ; `hostile/` ; `README`.
8. **Fuzz** à graine fixe (xorshift de `logs/tests.rs`) : mutations d'octets et de champs du flux fictif, aucune panique, `assert_bounded` de F1 sur chaque faille retenue.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Table `redistribution` complète et testée ; identifiant inconnu → `Internal` |
| 2 | Flux fictif lu en flux depuis un `Read` (ni `serde_json::Value` racine, ni corps entier en mémoire) ; mémoire bornée par une entrée et un lot ; flux tronqué ou valeur trop grosse → erreur, jamais un chargement partiel validé |
| 3 | Cas « Happy path », « Verdicts » et « hostile » verts ; aucune version ou borne illisible ne donne `NotAffected` |
| 4 | Attribution identique à la source sur les fixtures ; dépassement et absence comptés, faille gardée |
| 5 | Noyau à 40 branches évaluable ; 257 libellés → `unevaluable` ; tests F1 inchangés et verts |
| 6 | Test de cohérence vert avec `None` et « non faite » ; rouge si l'un des deux change seul (vérifié par un test sur un texte de `failles.md` modifié en mémoire) |
| 7 | Aucune donnée Wordfence réelle : slugs, CVE, liens et mentions inventés ; `README` présent |
| 8 | Fuzz vert et reproductible |
| 1-8 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` et `Cargo.lock` inchangés |
