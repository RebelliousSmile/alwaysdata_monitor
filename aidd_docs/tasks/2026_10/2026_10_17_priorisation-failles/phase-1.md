---
status: pending
---

# Instruction: Règle de gravité `vulns/severity.rs` et tables en mémoire

Prérequis : F1 phase 2 livrée (`Advisory`, `Score { value, origin }`, `Score::select`, alias normalisés, `malicious`, `informational`, `UnknownReason`).

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   └── vulns/
    │       ├── mod.rs                 ✏️ pub mod severity, exploit ; réexports
    │       ├── exploit.rs             ✅ Cve (grammaire KEV), KevFact, EpssFact (millionièmes), DatasetInfo, TablesState ; trait Exploitation ; MemoryTables
    │       └── severity.rs            ✅ constantes de seuil ; AdvisoryFacts (from_advisory) ; Rule ; Assessment ; assess() ; assess_unknown()
    └── tests/
        └── vulns_severity.rs          ✅ table de vérité, bornes, plusieurs CVE, propriétés sur grille exhaustive, bout à bout depuis Draft
```

## Test Scope

```mermaid
journey
  section Table de vérité
    CVE en KEV, score 5,0 => critique, règle Kev: 5: lib
    Entrée MAL- sans score => critique, règle Malicious: 5: lib
    Score 9,0 => critique ; 8,9 => avertissement CvssHigh: 5: lib
    Score 7,0 => avertissement ; 6,9 sans EPSS => information Default: 5: lib
    Score 4,0 et EPSS 0,1 exact => avertissement Epss ; EPSS 0,09999 => information: 5: lib
    Aucun score, non informational => avertissement UnknownSeverity: 5: lib
    Aucun score, informational => information Informational: 5: lib
    informational et score 9,8 => critique ; informational et CVE en KEV => critique: 1: lib
    Aucun score, informational, EPSS 0,5 => avertissement Epss: 1: lib
    Score 9,8 sans correctif et avec correctif => critique les deux, no_fix porté: 5: lib
  section Sans CVE
    Faille sans CVE (Wordfence, Friends-Of-Presta), score 6,1 => information, ni KEV ni EPSS consultés: 5: lib
    Alias cve-2026-90001 normalisé par F1 => jointure KEV réussie: 1: lib
    Alias CVE-26-1 ou CVE-2026-123 => ignoré pour la jointure: 1: lib
  section Plusieurs CVE
    Deux CVE, le second en KEV => critique, fait KEV du second: 1: lib
    Deux CVE, EPSS 0,02 et 0,3 => EPSS retenu 0,3 et son percentile: 1: lib
  section Inconnues
    Version inconnue, une faille critique du paquet => avertissement: 5: lib
    Version inconnue, failles au plus avertissement => information: 5: lib
    Plage inconnue, faille critique => information (F0): 1: lib
  section Ordre du score (bout à bout)
    Draft avec score Wordfence 5,3 et vecteur v3.1 à 9,8 => 5,3, origine wordfence, information ou EPSS: 1: lib
    Vecteur v3.1 à 9,8 et severity GHSA MODERATE => critique, origine cvss_v31: 1: lib
    Vecteur v4 seul et severity GHSA HIGH => 7, avertissement, origine ghsa_severity: 1: lib
  section Propriétés
    Grille exhaustive => monotonie KEV, malicious, score, EPSS ; fix_available sans effet ; informational ne monte jamais: 5: lib
  section Tables
    TablesState jamais chargé => aucune gravité levée, état porté par Assessment: 1: lib
```

## Tasks to do

1. **`exploit.rs`** :
   - `Cve` : `parse(&str) -> Option<Cve>` selon `^CVE-[0-9]{4}-[0-9]{4,19}$` (préfixe déjà normalisé par F1 ; aucune autre réécriture), `as_str()` ;
   - `KevFact { date_added: jiff::civil::Date, due_date: Date, ransomware: Option<bool>, name: String }` ; `EpssFact { epss_ppm: u32, percentile_ppm: u32 }` (0 ..= 1 000 000) ; `parse_ppm(&str) -> Option<u32>` : décimal `0`, `1`, `0.d{1,9}` ou `1.0{1,9}`, troncature au millionième, sans `f64` ;
   - `DatasetInfo { version, released }` ; `TablesState { kev: Option<DatasetInfo>, epss: Option<DatasetInfo> }` ;
   - `trait Exploitation { fn kev(&self, &Cve) -> Option<KevFact>; fn epss(&self, &Cve) -> Option<EpssFact>; fn state(&self) -> TablesState; }` ;
   - `MemoryTables` (construite depuis des itérateurs de lignes, pour les tests de F4 et de F7).
2. **`severity.rs`** :
   - constantes `CVSS_CRITICAL_TENTHS = 90`, `CVSS_WARNING_TENTHS = 70`, `EPSS_WARNING_PPM = 100_000`, avec renvoi à `decisions.md` ;
   - `AdvisoryFacts { cves: Vec<Cve>, malicious, score: Option<Score>, informational, fix_available }` et `AdvisoryFacts::from_advisory(&Advisory, fix_available)` (identifiant s'il est un CVE, plus alias CVE ; dédoublonnés) : F7 passe `fix_available` depuis son verdict (`fixed` le plus proche présent) ;
   - `Rule { Kev, Malicious, CvssCritical, CvssHigh, Epss, UnknownSeverity, Informational, Default }` avec `label()` pour la CLI et F7 ;
   - `Assessment { severity: finding::Severity, rule, kev: Option<(Cve, KevFact)>, epss: Option<(Cve, EpssFact)>, score: Option<Score>, no_fix: bool, tables: TablesState }` ;
   - `assess(&AdvisoryFacts, &impl Exploitation) -> Assessment` : faits KEV et EPSS collectés pour tous les CVE (KEV : `dateAdded` le plus ancien, `ransomware` vrai si l'un l'est ; EPSS : maximum), puis les huit règles dans l'ordre du plan, en un seul `match` lisible, commentaire citant le tableau de F0 ;
   - `assess_unknown(UnknownReason, component_max: Option<Severity>) -> Severity` ;
   - comparaison du score en dixièmes (`Score::tenths()` ajouté à F1 s'il manque : `(value * 10).round()`, borné à 0 ..= 100).
3. **`tests/vulns_severity.rs`** :
   - table de vérité en tableau Rust (`facts`, `kev`, `epss`, `attendu`, `règle`) couvrant chaque ligne du Test Scope et les bornes 6,9 / 7,0 / 8,9 / 9,0 et 99 999 / 100 000 / 100 001 ppm ;
   - grille exhaustive : KEV {non, oui} × `malicious` {non, oui} × score {absent, 0,0, 6,9, 7,0, 8,9, 9,0, 10,0} × EPSS {absent, 0, 99 999, 100 000, 1 000 000} × `informational` × `fix_available`, avec les quatre propriétés du plan ;
   - bout à bout : `Draft` fictifs → `Advisory::build` → `AdvisoryFacts::from_advisory` → `assess`, pour l'ordre du score (Wordfence, Friends-Of-Presta, v3.1 calculé, GHSA) ;
   - `parse_ppm` : `0.1` → 100 000, `0.0999999` → 99 999, `0.100000999` → 100 000, `1` → 1 000 000 ; refus de `-0.1`, `1.1`, `1e-5`, `.5`, `0.1234567890`, vide.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `Cve` refuse tout ce qui sort de la grammaire du schéma KEV ; `parse_ppm` exact sur les bornes, sans `f64` |
| 2 | La règle n'existe qu'à un endroit (`grep` : aucun seuil 70, 90 ou 100 000 ailleurs dans `src/vulns`) ; module sans accès base, horloge ni configuration |
| 3 | Table de vérité verte ; quatre propriétés vertes sur toute la grille ; aucun chemin où `fix_available` change la gravité ; bout à bout conforme à l'ordre F0 du score |
| 1-3 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
