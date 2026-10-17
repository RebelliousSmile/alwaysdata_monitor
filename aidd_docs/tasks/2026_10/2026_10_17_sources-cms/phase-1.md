---
status: done
---

# Instruction: Convertisseur Wordfence Intelligence v3

Convertisseur pur, sans réseau ni base : octets du flux `production` → `Advisory` de F1, écarts comptés. Ne dépend que de F1.

## Architecture projection

```txt
.
└── vigie/
    ├── Cargo.toml                         ✏️ serde_json : fonctionnalité raw_value (Cargo.lock inchangé)
    ├── src/
    │   └── vulns/
    │       ├── mod.rs                     ✏️ pub mod sources
    │       ├── advisory.rs                ✏️ (F1) raisons de Tally ajoutées : bad_record, attribution_overflow, no_copyrights, empty_copyrights (information) ; Reason::is_drop() (match sans joker : numérateur du max_dropped_ratio de F2) ; borne unique de F1 (256 plages par ligne) inchangée
    │       └── sources/
    │           ├── mod.rs                 ✅ rôle des convertisseurs ; enum Redistribution { Internal, FactsOnly, Free } (porté par SourceMeta en phase 3)
    │           └── wordfence.rs           ✅ WfRecord (serde, champs inconnus ignorés) ; parse_feed(impl Read, sink, tally) : Compteur(BufReader) externe, Visitor, Box<RawValue> puis from_str::<WfRecord> par entrée ; to_draft ; attribution ; record_url ; REDISTRIBUTION = Internal ; WORDFENCE_TERMS_REVIEWED: Option<&str> = None
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
    Id WF-00000000-0000-4000-8000-000000000001, aliases CVE-2099-0001, CWE-79, références, published et updated => champs du modèle: 5: lib
    UUID en majuscules dans la source => id WF-<uuid en minuscules>, clé et id comparées après normalisation: 1: lib
    cvss score 6.1 et vecteur 3.1 => Score { tenths: 61, origin: wordfence } lu comme texte, sans flottant: 5: lib
    copyrights message, puis clés exemple et mitre-fictif => attribution assemblée, message puis clés triées, lien de l'enregistrement ; license_url en texte, jamais en lien actif: 5: lib
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
    257 libellés dans affected_versions (borne unique F1 de 256) => ligne unevaluable, jamais écartée: 1: lib
    patched true sans patched_versions supérieure => aucun fixed, aucune erreur: 1: lib
    copyrights absent ou attribution de 2 001 caractères => faille gardée, mention fixe, no_copyrights ou attribution_overflow: 1: lib
    copyrights vide {} => faille gardée, mention fixe, empty_copyrights (information, hors seuil de rejet): 1: lib
    cvss tableau non vide, cwe chaîne, references objet => champ retiré seul avec sa raison F1, faille gardée: 1: lib
    id nombre, software chaîne, software[].type ou slug de mauvais type => faille écartée seule, bad_record ; les suivantes sont lues: 1: lib
    Valeur de 5 Mio (compteur), erreur de syntaxe JSON ou racine tronquée => erreur de flux, chargement abandonné, génération active intacte (côté F2): 1: lib
    Date 2099-13-45 (ou absente) à la fois dans updated et dans published => faille écartée, bad_date ; format AAAA-MM-JJ hh:mm:ss => lu en UTC: 1: lib
    published illisible ("2026-01-10" sans heure) et updated valide => faille gardée, bad_published (is_drop faux), aucun écart compté dans le seuil: 1: lib
    cvss score 10.1, 6.15, 6e0 ou "6.1" => champ retiré seul, bad_severity ; vecteur v3.1 gardé ; score 10.0 => 100 dixièmes: 1: lib
    null, [] et {} pour cvss, cwe, references, copyrights, patched_versions, cve, dates => champ vide, faille gardée (copyrights => empty_copyrights): 1: lib
    affected_versions null, [] ou de forme inattendue => ligne unevaluable, faille gardée: 1: lib
    Même uuid deux fois => seconde écartée, duplicate_id: 1: lib
    Titre avec ESC, U+202E, 600 caractères => assaini, 500 caractères: 1: lib
  section Fuzz
    50 000 mutations du flux fictif => aucune panique, chaque Advisory borné: 1: lib
  section Verrou
    WORDFENCE_TERMS_REVIEWED = None et failles.md « non faite » => cohérents: 5: lib
```

## Tasks to do

1. **`sources/mod.rs`** : enum `Redistribution { Internal, FactsOnly, Free }`, documentation de ce que chaque niveau permet (renvoi à « Redistribution, affichage et fixtures » de `failles.md`) et règle de fusion `most_restrictive(a, b)` (`Internal` < `FactsOnly` < `Free`) ; `wordfence::REDISTRIBUTION = Internal`. Le niveau entre dans `SourceMeta` en phase 3, et `vulns::sync::registry::redistribution(source_id)` le donne pour un identifiant (phase 3).
2. **`wordfence.rs`, lecture** : `parse_feed(reader, sink, tally)` ; `serde_json::Deserializer::from_reader(Compteur(BufReader::new(file)))`, le compteur d'octets en couche **externe**, partagé par `Rc<Cell<u64>>` ; un `Visitor` sur l'objet racine remet le compteur à zéro avant chaque `next_key`, lit la clé (`String`) puis la valeur en `Box<RawValue>` ; compteur > 4 Mio → erreur de flux `EntryTooLarge` ; erreur de syntaxe JSON → `Err(FeedError)` ; puis, par entrée, `serde_json::from_str::<WfRecord>(raw.get())` : `WfRecord` ne type strictement que `id` et `software[].type` / `slug` (échec → faille écartée seule, `bad_record`, lecture continuée) ; tous les autres champs sont des `Option<Box<RawValue>>` décodés un à un par `decode_field` : `null`, `[]`, `{}` → vide ; échec → champ retiré seul avec sa raison F1 ; `affected_versions` vide ou illisible → ligne `unevaluable` ; champs inconnus ignorés (`IgnoredAny`) ; `cvss.score` décodé comme texte de nombre JSON (`\d{1,2}(\.\d)?`) puis en dixièmes entiers, jamais par flottant. Plafond d'entrées : 200 000 (`too_many_entries`, erreur de flux). Le cadre F2 abandonne le chargement sur toute erreur de flux (génération active intacte).
3. **`wordfence.rs`, conversion** `to_draft(key, WfRecord) -> Result<Draft, Dropped>` selon le tableau « Conversion Wordfence » du plan : id `WF-<uuid>` (clé = `id`, UUID en minuscules), alias CVE, une ligne par `software[]` (purl, `scheme` PHP), une plage par libellé (`*` → `Bound::Floor` ou plage ouverte, `from_inclusive: false` traduit en inclusive, `to_inclusive` → `last_affected` ou `fixed`), `fixed` tiré de `patched_versions` (plus petite version strictement supérieure à `to_version`, comparateur PHP), bornes illisibles ou inversées → `unevaluable` ; dates RFC 3339 ou `AAAA-MM-JJ hh:mm:ss` en UTC ; `modified` = `updated`, sinon `published`, sinon `bad_date` (faille écartée) ; un `published` ou `updated` illisible alors qu'un repli fournit `modified` compte `bad_published` (`is_drop = false`), faille gardée ; `provided_score`, vecteur, CWE, références, `informational`, `source_url`. Tout passe par `Advisory::build`.
4. **Attribution** : `attribution(copyrights, url) -> (String, Option<Reason>)` : `message`, puis les autres clés **triées**, chacune `notice`, `license`, `license_url` (en texte, jamais en lien), séparés par des sauts de ligne, assainis par `LogText`, plus l'URL de l'enregistrement ; `{}` → mention fixe « Wordfence Intelligence, © Defiant Inc. — <url> » et `empty_copyrights` ; absent → même mention et `no_copyrights` ; > 2 000 caractères → même mention et `attribution_overflow`. Licence de la faille : `Wordfence-Intelligence` (chaîne fixe, la licence exacte est dans l'attribution).
5. **Borne de F1** : aucune borne propre à Wordfence ; la borne unique de F1 (256 plages par ligne, au-delà `unevaluable`) suffit au noyau à 40 branches. Si F1 n'a pas encore cette borne à l'implémentation, la phase attend F1 plutôt que d'en créer une par source.
6. **Verrou** : `WORDFENCE_TERMS_REVIEWED: Option<&str> = None` ; test `terms_review_matches_failles_md` qui lit `vigie/docs/failles.md`, trouve la ligne « Relecture des conditions depuis le VPS » et exige `non faite` ↔ `None`, `faite le AAAA-MM-JJ` ↔ `Some` de la même date (date valide, pas dans le futur du commit).
7. **Fixtures fictives** : `production.json` (une quinzaine d'entrées couvrant le Test Scope ; UUID `00000000-0000-4000-8000-0000000000NN`, slugs `exemple-plugin`, `exemple-theme`, CVE `CVE-2099-…`, références `https://example.org/…`, `copyrights` de même forme que la fiche de `failles.md` avec un titulaire inventé « Exemple Intelligence SARL », jamais la mention Defiant ou MITRE réelle) ; `hostile/` ; `README`.
8. **`Reason::is_drop()`** dans le `Tally` de F1, `match` sans joker : `true` pour `bad_record`, `bad_front_matter`, `unknown_category`, `bad_id` et les raisons qui écartent une faille entière (`too_large`, `bad_date`, `duplicate_id`, `no_affected`) ; `false` pour `empty_copyrights`, `no_copyrights`, `attribution_overflow`, `bad_archive_member`, `out_of_scope`, `withdrawn` et les champs retirés seuls (dont `bad_published`) ; test exhaustif sur toutes les variantes.
9. **Fuzz** à graine fixe (xorshift de `logs/tests.rs`) : mutations d'octets et de champs du flux fictif, aucune panique, `assert_bounded` de F1 sur chaque faille retenue.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `most_restrictive` testé sur les neuf paires ; `wordfence::REDISTRIBUTION` = `Internal` |
| 2 | Flux fictif lu en flux depuis un `Read` (ni `serde_json::Value` racine, ni corps entier en mémoire) ; mémoire bornée par une valeur et un lot ; `bad_record` écarte une seule faille ; erreur de syntaxe ou valeur trop grosse → erreur de flux, jamais un chargement partiel validé |
| 3 | Cas « Happy path », « Verdicts » et « hostile » verts ; aucune version ou borne illisible ne donne `NotAffected` |
| 4 | Attribution stable (message puis clés triées) sur les fixtures ; `{}`, absence et dépassement distingués et comptés, faille gardée ; aucune URL de licence en lien actif |
| 5 | Noyau à 40 branches évaluable ; 257 libellés → `unevaluable` ; aucune borne par source dans le code |
| 6 | Test de cohérence vert avec `None` et « non faite » ; rouge si l'un des deux change seul (vérifié par un test sur un texte de `failles.md` modifié en mémoire) |
| 7 | Aucune donnée Wordfence réelle : UUID, slugs, CVE, liens et titulaire des `copyrights` inventés ; `README` présent |
| 8 | `is_drop` couvre chaque variante de `Reason` (ajouter une raison sans la classer ne compile pas) |
| 9 | Fuzz vert et reproductible |
| 1-9 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` modifié de la seule fonctionnalité `raw_value`, `Cargo.lock` inchangé |
