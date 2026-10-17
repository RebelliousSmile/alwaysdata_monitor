---
status: pending
---

# Instruction: Rapprochement pur : fusion, verdicts, gravité, dérogations, constats

Fonctions pures, sans base, sans horloge ni configuration : un composant (purl, version) et ses failles candidates en entrée, des groupes évalués et un constat en sortie. **Prérequis** : F1 phase 2 (`Advisory`, `Affected`, `Verdict`, `match_advisory`, `Score { tenths, origin }`, `normalize_alias`), F3 phase 1 (`Redistribution`, `most_restrictive`), F4 phase 1 (`severity.rs`, `exploit.rs`, `MemoryTables`). La phase ne lit aucune table de F1 à F5 : les candidats sont construits en mémoire par les tests, et le type `Candidate` est celui demandé à F1 (prérequis F1-2), défini ici en attendant s'il n'existe pas encore, puis remplacé par celui de F1 à la phase 2.

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   └── vulns/
    │       ├── mod.rs                 ✏️ pub mod matching ; réexports
    │       └── matching/
    │           ├── mod.rs             ✅ rôle (renvoi à docs/failles.md, « Rapprochement (F7) ») ; Component { ecosystem, base: Purl, version: Option<String>, scope, path } ; Candidate (si F1 ne l'a pas encore) ; admitted(kind, ecosystem) via capability::inventory_ecosystems
    │           ├── group.rs           ✅ fusion par identifiants et alias normalisés (union-find), clé de groupe stable ; GroupVerdict ; correctif du groupe
    │           ├── assess.rs          ✅ évaluation d'un groupe : assess_group / assess_unknown (F4), redistribution la plus restrictive (F3), faits gardés (GroupFacts) pour réévaluer sans relire les plages
    │           ├── waiver.rs          ✅ Waiver { base, advisory_ref, version, until, reason } ; applies(waiver, group, version, kev, now) ; WaiverRefusal
    │           └── finding.rs         ✅ component_finding(site, component, groups, waivers, now) -> Option<Finding> ; stale_finding ; detail borné (4 096), première ligne ≤ 200, attributions dédoublonnées jamais tronquées ; KEY_STALE = "inventaire-perime" ; CHECK = "vulns"
    └── tests/
        ├── vulns_matching.rs          ✅ cas de l'issue sur fixtures fictives, MemoryTables de F4
        └── fixtures/vulns/matching/
            ├── README                 ✅ « données fictives : sites site-a et site-b, composants, failles et CVE inventés (CVE-2099-…), liens example.org »
            ├── wordpress.json         ✅ exemple-plugin (Wordfence fictif + GHSA fictive du même CVE), noyau, thème ; une extension à 30 failles
            ├── prestashop.json        ✅ exemplemodule à quatre composants (1.6.1.24), noyau, plage libre « plage inconnue »
            ├── composer.json          ✅ exemple/paquet avec préversion (2.0.0-RC1), cas Packagist énumération ≠ plage
            └── npm.json               ✅ @exemple/paquet, version vide
```

## Test Scope

```mermaid
journey
  section Happy path
    exemple-plugin 1.2.3, faille WF fictive corrigée en 1.2.4 => groupe Affected, constat site-a/vulns/pkg:wordpress/plugin/exemple-plugin: 5: lib
    exemple-plugin 1.2.4 (inventaire suivant) => NotAffected, aucun constat (incident clos rétabli en phase 2): 5: lib
    exemplemodule 1.6.1.24 (quatre composants), plage <= 1.6.1.24 corrigée en 1.6.1.25 => Affected, correctif 1.6.1.25, comparateur PHP: 5: lib
    exemplemodule 1.6.1.25 => NotAffected: 5: lib
    exemple/paquet 2.0.0-RC1, plage introduced 2.0.0-beta1 fixed 2.0.0 => Affected par Composer (préversion comprise): 5: lib
    exemple/paquet 2.0.0 => NotAffected: 5: lib
  section Packagist énumération et plage
    versions[] liste 1.5.0 hors de la plage 1.0.0..1.2.0 => Affected avec divergence, mention « listée hors plage »: 1: lib
    Plage contient 1.1.0, versions[] ne la liste pas => Affected (la plage fait foi, jamais versions[] seule): 1: lib
  section Fusion des doublons
    WF-… (alias CVE-2099-0001) et GHSA-… (alias CVE-2099-0001) => un seul groupe, deux membres, deux sources, attributions des deux: 5: lib
    WF sans CVE et GHSA à CVE => deux groupes distincts (aucun identifiant commun): 1: lib
    A~B par CVE, B~C par GHSA => un seul groupe A, B, C (fermeture transitive): 1: lib
    Groupe WF Internal + GHSA Free => redistribution Internal: 1: lib
    Groupe FOP FactsOnly + GHSA Free => FactsOnly: 1: lib
    Membre WF Affected, membre GHSA NotAffected (plages différentes) => groupe Affected: 1: lib
    Deux membres Affected, correctifs 1.2.4 et 1.2.5 => correctif du groupe 1.2.5: 1: lib
  section Version ou plage inconnue
    @exemple/paquet sans version => groupes Unknown(VersionUnknown), « version inconnue », information: 5: lib
    Même cas, faille critique (CVSS 9,8) => avertissement: 1: lib
    Module à plage libre non reconnue => « plage inconnue », jamais NotAffected: 1: lib
    Plage corrigée par F3 (drapeau corrected) => « plage corrigée » dans le détail: 1: lib
  section Gravité et regroupement
    Une extension, 30 failles => un seul Finding, gravité = maximum des groupes, 30 groupes comptés: 5: lib
    Même composant, CVE ajouté à KEV dans MemoryTables => même clé, gravité critique: 5: lib
    Faille MAL- => critique ; EPSS 0,1 => avertissement ; informational sans score => information: 1: lib
    Tous les groupes NotAffected => None: 1: lib
  section Dérogations (pures, horloge passée en paramètre)
    Dérogation (exemple-plugin, CVE-2099-0002, 1.2.3, until J+30) => groupe listé « sous dérogation », retiré de la gravité: 5: lib
    Seul groupe touché sous dérogation => Finding d'information « toutes les failles sous dérogation »: 1: lib
    Même dérogation à J+31 => expirée, gravité d'origine rendue: 5: lib
    Dérogation sur 1.2.3, version installée 1.2.3.1 => caduque: 1: lib
    Dérogation saisie par GHSA-…, groupe fusionné WF + GHSA => couvre le groupe: 1: lib
    CVE du groupe entré dans KEV => dérogation caduque, critique: 1: lib
    Validation : CVE en KEV, version inconnue, until > now + 90 j, motif vide ou de 501 caractères, groupe non touché => WaiverRefusal typé: 1: lib
  section Détail et clé
    Clé => purl canonique sans version, jamais la version, le chemin ni le nom: 5: lib
    Détail de 30 groupes => ≤ 4 096 caractères, « + K autres : vigie site vulns site-a », attributions entières: 1: lib
    Attribution Wordfence fictive de 2 000 caractères => gardée entière, groupes réduits: 1: lib
    Identifiant ou lien avec ESC, U+202E => U+FFFD ; première ligne ≤ 200 caractères, sans saut de ligne: 1: lib
    Aucun summary ni titre de source dans le détail: 1: lib
  section Écosystème admis
    Composant pkg:prestashop sur un site wordpress => non rapproché: 1: lib
    pkg:cargo sur tout site => rapproché: 1: lib
  section Péremption
    stale_finding(site, dernier seen_at, now) => avertissement inventaire-perime à 7 jours + 1 s, rien à 7 jours - 1 s: 5: lib
  section Fuzz
    20 000 jeux de candidats générés (alias croisés, versions hostiles) => aucune panique, détail borné, clé dans la grammaire: 1: lib
```

## Tasks to do

1. **`matching/mod.rs`** : `Component` (écosystème de `vulns::purl`, purl sans version, version brute ou `None`, scope Vigie, chemin) ; `Candidate` (prérequis F1-2 : source, génération, `Advisory`, lignes `Affected` du purl, `corrected`) ; `admitted(kind, ecosystem)` par `capability::inventory_ecosystems` (F5), `match` sans joker sur l'écosystème.
2. **`group.rs`** :
   - union-find sur les identifiants et alias normalisés (`normalize_alias`, F1) de toutes les candidates d'un composant ; clé de groupe = plus petit `CVE-…` (ordre lexical) sinon plus petit identifiant ;
   - par membre, `match_advisory(lignes, version)` (F1) ;
   - `GroupVerdict` : `Affected { fixed, divergence, beyond_last_known }` si un membre l'est, le correctif étant le plus grand des correctifs des membres touchés comparés par le comparateur de leur ligne (`version::parse`) ; si deux correctifs ne se comparent pas (schémas différents), tous sont gardés et listés ; sinon `Unknown(raison du premier membre)` ; sinon `NotAffected`.
3. **`assess.rs`** :
   - `GroupFacts` : par membre `AdvisoryFacts::from_advisory(&advisory, fix_available)` (F4, `fix_available` = le verdict du membre porte un `fixed`), sérialisable (pour la phase 2 : réévaluation sans relire les plages) ;
   - `assess(group, &impl Exploitation) -> GroupAssessment { severity, rule, kev, epss, score, no_fix }` : `assess_group` (F4) pour `Affected`, `assess_unknown(raison, &assess_group(..))` pour `Unknown` ;
   - redistribution du groupe : `most_restrictive` (F3) sur les sources des membres, par la fonction de F3 qui donne le niveau d'un identifiant de source (prérequis F3-1) ; identifiant inconnu → `Internal` (fail-closed).
4. **`waiver.rs`** :
   - `Waiver { base, advisory_ref, version, until, reason }` ;
   - `validate(waiver, group, installed_version, kev_hit, now) -> Result<(), WaiverRefusal>` : `MAX_WAIVER_DAYS = 90`, motif 1 à 500 caractères, version connue et égale, groupe `Affected` ou `Unknown`, aucun CVE du groupe dans KEV ;
   - `applies(..)` : même règles à la lecture, plus `now < until` ; une dérogation expirée ou caduque n'a aucun effet et est signalée (`Expired`, `VersionChanged`, `Kev`).
5. **`finding.rs`** :
   - `CHECK = "vulns"`, `KEY_STALE = "inventaire-perime"`, `STALE_AFTER = 7 * 86_400`, `MAX_VULNS_DETAIL_CHARS = 4_096`, `MAX_SUBJECT_CHARS = 200` ;
   - `component_finding(site, component, groups, waivers, now) -> Option<Finding>` : clé = `base.canonical()` ; gravité = maximum des groupes hors dérogation ; s'il n'en reste aucun mais qu'un groupe est sous dérogation, `Severity::Info` ; aucun groupe `Affected`/`Unknown` → `None` ;
   - détail : première ligne (purl sans version, version, nombre de failles, nombre de critiques, « corriger : ≥ <v> » ou « aucun correctif ») ; lignes de groupes triées (gravité décroissante, puis clé) : identifiants des membres, état (« touchée », « version inconnue », « plage inconnue », « plage corrigée », « listée hors plage », « sous dérogation jusqu'au AAAA-MM-JJ »), CVSS en décimal (dixièmes ÷ 10), « KEV », EPSS en %, version corrigée, lien `source_url` ; puis « Sources : » et les attributions dédoublonnées ; les lignes de groupes cèdent la place, jamais les attributions ; chaque morceau passé par `LogText` ;
   - `stale_finding(site, last_seen_or_declared, now) -> Option<Finding>` : avertissement au-delà de `STALE_AFTER`.
6. **Fixtures** fictives (`tests/fixtures/vulns/matching/`) au format des `Draft` de F1 (passés par `Advisory::build`), avec `README` ; aucun enregistrement réel, aucune mention Defiant ou MITRE réelle (titulaire inventé comme F3).
7. **Tests** `tests/vulns_matching.rs` : chaque cas du Test Scope ; KEV et EPSS par `MemoryTables` (F4) ; fuzz à graine fixe (xorshift de `logs/tests.rs`).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Cas « Fusion des doublons » et « Packagist » verts ; un groupe n'est jamais `NotAffected` quand un membre est `Affected` ou `Unknown` |
| 3 | Gravité obtenue seulement par `assess_group` et `assess_unknown` de F4 (aucune comparaison de seuil dans `matching/`) ; redistribution la plus restrictive vérifiée sur les paires |
| 4 | Cas « Dérogations » verts ; aucune dérogation n'agit au-delà de 90 jours, sur une autre version ou sur une faille KEV |
| 5 | Une extension à 30 failles donne un seul `Finding` ; clé = purl sans version ; détail ≤ 4 096 caractères, première ligne ≤ 200 sans saut de ligne ; attributions jamais tronquées ; aucun `summary` dans le détail |
| 6-7 | Fixtures fictives seulement (`README`), fuzz vert et reproductible en moins de 10 s en debug |
| 1-7 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
