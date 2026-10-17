---
status: done
---

# Instruction: Règle de gravité `vulns/severity.rs` et tables en mémoire

Prérequis : F1 phase 2 livrée (`Advisory`, `Score::select`, alias normalisés, `malicious`, `informational`, `UnknownReason`) avec **`Score { tenths: u8 (0..=100), origin }`**, acquis pour F1 : GHSA 90/70/50/30, `Roundup` CVSS v3.1 en entiers, colonne `score` en dixièmes. Le texte de la phase 2 de F1 (`Score { value, origin }`) est à aligner avant de commencer ; F4 n'ajoute aucune conversion depuis un flottant.

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   └── vulns/
    │       ├── mod.rs                 ✏️ pub mod severity, exploit ; réexports
    │       ├── exploit.rs             ✅ Cve (grammaire KEV), KevFact, EpssFact (millionièmes, génération), DatasetInfo, TablesState ; parse_ppm ; trait Exploitation ; MemoryTables
    │       └── severity.rs            ✅ constantes de seuil ; AdvisoryFacts (from_advisory) ; Rule ; Assessment ; assess ; assess_group ; UnknownAssessment ; assess_unknown
    └── tests/
        └── vulns_severity.rs          ✅ table de vérité, bornes, plusieurs CVE, groupes, inconnues, propriétés sur grille exhaustive, bout à bout depuis Draft
```

## Test Scope

```mermaid
journey
  section Table de vérité
    CVE en KEV, score 5,0 => critique, règle Kev: 5: lib
    Entrée MAL- sans score => critique, règle Malicious: 5: lib
    Score 9,0 => critique ; 8,9 => avertissement CvssHigh: 5: lib
    Score 7,0 => avertissement ; 6,9 sans EPSS => information Default: 5: lib
    Score 4,0 et EPSS 0,1 exact => avertissement Epss ; EPSS 0,099999 => information: 5: lib
    Aucun score, non informational => avertissement UnknownSeverity: 5: lib
    Aucun score, informational => information Informational: 5: lib
    informational et score 9,8 => critique ; informational et CVE en KEV => critique: 1: lib
    Aucun score, informational, EPSS 0,5 => avertissement Epss: 1: lib
    Score 9,8 sans correctif et avec correctif => critique les deux, no_fix porté: 5: lib
  section Sans CVE
    Faille sans CVE (Wordfence, Friends-Of-Presta), score 6,1 => information, ni KEV ni EPSS consultés: 5: lib
    Alias cve-2099-90001 normalisé par F1 => jointure KEV réussie: 1: lib
    Alias CVE-99-1 ou CVE-2099-123 => ignoré pour la jointure: 1: lib
  section Plusieurs CVE
    Deux CVE, le second en KEV => critique, fait KEV du second: 1: lib
    Deux CVE, EPSS 0,02 et 0,3 => EPSS retenu 0,3 et son percentile: 1: lib
  section Groupes fusionnés
    Membre Wordfence sans CVE (score 5,0) + GHSA dont le CVE est dans KEV => critique Kev, membre retenu la GHSA: 5: lib
    Membre Wordfence informational sans score + GHSA sans score => avertissement UnknownSeverity: 5: lib
    Membre Wordfence sans CVE + GHSA à CVE d'EPSS 0,4 => les deux voient l'EPSS de l'union, avertissement: 1: lib
    Même CVE dans deux membres => compté une fois: 1: lib
    Groupe d'un seul membre => identique à assess: 1: lib
  section Inconnues
    Version inconnue, faille critique => avertissement, règle VersionUnknown: 5: lib
    Plage inconnue, faille critique => avertissement, règle RangeUnknown: 5: lib
    Version ou plage inconnue, faille en avertissement ou information => information: 5: lib
  section Ordre du score (bout à bout)
    Draft avec score Wordfence 5,3 et vecteur v3.1 à 9,8 => 53 dixièmes, origine wordfence, information: 1: lib
    Vecteur v3.1 à 9,8 et severity GHSA MODERATE => critique, origine cvss_v31: 1: lib
    Vecteur v4 seul et severity GHSA HIGH => 70 dixièmes, avertissement, origine ghsa_severity: 1: lib
  section Propriétés
    Grille, scores présents => monotonie KEV, malicious, score, EPSS: 5: lib
    Grille entière => fix_available sans effet ; informational ne monte jamais: 5: lib
    Score absent et non informational => au moins avertissement ; EPSS absent et EPSS 0 => même gravité: 5: lib
    assess_group => jamais en dessous du maximum des assess de ses membres sur leurs propres CVE: 1: lib
  section Tables
    TablesState jamais chargé => aucune gravité levée, état porté par Assessment: 1: lib
```

## Tasks to do

1. **`exploit.rs`** :
   - `Cve` : `parse(&str) -> Option<Cve>` selon `^CVE-[0-9]{4}-[0-9]{4,19}$` (préfixe déjà normalisé par F1, aucune autre réécriture), `as_str()` ;
   - `KevFact { date_added: jiff::civil::Date, due_date: Date, known_ransomware: bool, name: String }` ; `EpssFact { generation: i64, epss_ppm: u32, percentile_ppm: u32 }` (0 ..= 1 000 000) ;
   - `parse_ppm(&str) -> Option<u32>`, entiers seulement : `0`, `1`, `0.d{1,9}`, `1.0{1,9}`, ou `d(.d{1,9})?e-NN` (mantisse et exposant en entiers, `NN` de 1 à 2 chiffres), tronqué au millionième ; refus de tout le reste ;
   - `DatasetInfo { generation, version, released: jiff::Timestamp }` (KEV : `dateReleased` complet ; EPSS : `score_date` à minuit UTC) ; `TablesState { kev: Option<DatasetInfo>, epss: Option<DatasetInfo> }` ;
   - `trait Exploitation { fn kev(&self, &Cve) -> Option<KevFact>; fn epss(&self, &Cve) -> Option<EpssFact>; fn state(&self) -> TablesState; }` ;
   - `MemoryTables`, construite depuis des itérateurs de lignes (tests de F4 et de F7).
2. **`severity.rs`** :
   - constantes nommées `CVSS_CRITICAL_TENTHS = 90`, `CVSS_WARNING_TENTHS = 70`, `EPSS_WARNING_PPM = 100_000`, avec renvoi à `decisions.md` ;
   - `AdvisoryFacts { id, cves: Vec<Cve>, malicious, score: Option<Score>, informational, fix_available }` ; `from_advisory(&Advisory, fix_available)` (identifiant s'il est un CVE, plus alias CVE, dédoublonnés) ; F7 passe `fix_available` depuis son verdict ;
   - `Rule { Kev, Malicious, CvssCritical, CvssHigh, Epss, UnknownSeverity, Informational, Default }` et `label()` ;
   - `Assessment { severity, rule, member: String, kev: Option<(Cve, KevFact)>, epss: Option<(Cve, EpssFact)>, score: Option<Score>, no_fix: bool, tables: TablesState }` ;
   - fonction interne `rules(facts, kev, epss) -> (Severity, Rule)` : les huit règles du plan dans un seul `match`, commentaire citant le tableau de F0 ;
   - `assess(&AdvisoryFacts, &impl Exploitation)` : faits KEV et EPSS sur ses CVE (KEV : `dateAdded` le plus ancien, `known_ransomware` si l'un l'est ; EPSS : maximum), puis `rules` ;
   - `assess_group(&[AdvisoryFacts], &impl Exploitation)` : union dédoublonnée des CVE des membres, faits KEV et EPSS sur cette union, `rules` pour chaque membre avec ces faits, maximum ; règle, score et `member` du premier membre (ordre reçu) au maximum ; `no_fix` vrai si aucun membre n'a de correctif ; groupe vide refusé par le type (`NonEmpty` ou `debug_assert` et `Option`) ;
   - `UnknownAssessment { severity, rule: UnknownRule { VersionUnknown, RangeUnknown } }` ; `assess_unknown(UnknownReason, &Assessment)` : critique → avertissement, sinon information.
3. **`tests/vulns_severity.rs`** :
   - table de vérité en tableau Rust (`facts`, `kev`, `epss`, `attendu`, `règle`) couvrant chaque ligne du Test Scope et les bornes 69 / 70 / 89 / 90 dixièmes et 99 999 / 100 000 / 100 001 ppm ;
   - grille exhaustive : KEV {non, oui} × `malicious` × score {absent, 0, 69, 70, 89, 90, 100} × EPSS {absent, 0, 99 999, 100 000, 1 000 000} × `informational` × `fix_available` ; monotonie vérifiée entre scores présents seulement ; propriétés d'absence séparées ;
   - groupes : cas du Test Scope et propriété `assess_group ≥ max(assess(membre))` ;
   - bout à bout : `Draft` fictifs → `Advisory::build` → `AdvisoryFacts::from_advisory` → `assess`, pour l'ordre du score ;
   - `parse_ppm` : `0.1` → 100 000, `0.0999999` → 99 999, `0.100000999` → 100 000, `1` → 1 000 000, `1.0e-05` → 10, `1e-5` → 10, `9.99e-01` → 999 000 ; refus de `-0.1`, `1.1`, `1.e-5`, `.5`, `0.1234567890`, `2.0e+01`, `1e-123`, vide.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `Cve` refuse tout ce qui sort de la grammaire du schéma KEV ; `parse_ppm` exact sur les bornes, sans `f64` (aucun `f32`/`f64` dans `exploit.rs` et `severity.rs`) |
| 2 | Les constantes nommées `CVSS_CRITICAL_TENTHS`, `CVSS_WARNING_TENTHS` et `EPSS_WARNING_PPM` ne sont définies qu'ici et ne sont comparées que dans `rules` ; module sans accès base, horloge ni configuration |
| 3 | Table de vérité, groupes et inconnues verts ; propriétés vertes sur toute la grille ; aucun chemin où `fix_available` change la gravité ; bout à bout conforme à l'ordre F0 du score |
| 1-3 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
