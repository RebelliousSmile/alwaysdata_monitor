---
status: pending
---

# Instruction: Rapprochement pur : fusion, verdicts, gravité, dérogations, constats

Fonctions pures, sans base, sans horloge ni configuration : les composants d'un même purl sans version, vus par une ou deux sources d'inventaire, et leurs failles candidates en entrée ; des groupes évalués et au plus un constat en sortie. **Prérequis** : F1 phase 2 (`Advisory`, `Affected`, `Verdict`, `match_advisory`, `Score { tenths, origin }`, `normalize_alias`) et le type `Candidate { source, generation, advisory, lines, corrected }` de F1 (`phase-3.md` l. 74 ; défini ici à l'identique si F1 phase 3 n'est pas encore fusionnée, puis remplacé), F3 phase 1 (`Redistribution`, `most_restrictive`), F4 phase 1 (`severity.rs`, `exploit.rs`, `MemoryTables`). La phase ne lit aucune table.

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   └── vulns/
    │       ├── mod.rs                 ✏️ pub mod matching ; réexports
    │       └── matching/
    │           ├── mod.rs             ✅ rôle (renvoi à docs/failles.md, « Rapprochement (F7) ») ; InventorySide { Agent, Ci } ; Component { side, ecosystem, base: Purl, version: Option<String>, scope, path, carried: bool } ; admitted(kind, ecosystem) via capability::inventory_ecosystems
    │           ├── group.rs           ✅ fusion par identifiants et alias normalisés (union-find), clé de groupe stable ; GroupVerdict (RangeUnknown prioritaire) ; correctif du groupe
    │           ├── assess.rs          ✅ assess_group / assess_unknown (F4) ; redistribution la plus restrictive (F3) ; GroupFacts sérialisables (réévaluation sans plages) ; membres = (identifiant, source), jamais l'attribution copiée
    │           ├── waiver.rs          ✅ Waiver { side, base, advisory_ref, version, covered_ids, until, reason } ; validate (avant toute requête : until, motif) ; applies -> Ok | Expired | VersionChanged | GroupChanged | Kev
    │           └── finding.rs         ✅ base_finding(site, base, views, waivers, already_open, now) -> Option<Finding> ; stale_finding(site, side, since, threshold, now) ; détail borné ; KEY_STALE_AGENT, KEY_STALE_CI ; CHECK = "vulns"
    └── tests/
        ├── vulns_matching.rs          ✅ cas de l'issue sur fixtures fictives, MemoryTables de F4
        └── fixtures/vulns/matching/
            ├── README                 ✅ « données fictives : sites site-a et site-b, composants, failles, CVE (CVE-2099-…) et attributions inventés (titulaire « Exemple Intelligence SARL »), liens example.org seulement »
            ├── wordpress.json         ✅ exemple-plugin (Wordfence fictif + GHSA fictive du même CVE), noyau, thème ; extension à 30 failles
            ├── prestashop.json        ✅ exemplemodule à quatre composants (1.6.1.24), noyau, plage libre « plage inconnue »
            ├── composer.json          ✅ exemple/paquet avec préversion (2.0.0-RC1), cas Packagist énumération ≠ plage
            └── npm.json               ✅ @exemple/paquet, version vide
```

## Test Scope

```mermaid
journey
  section Happy path
    exemple-plugin 1.2.3 (agent), faille WF fictive corrigée en 1.2.4 => groupe Affected, constat site-a/vulns/pkg:wordpress/plugin/exemple-plugin: 5: lib
    exemple-plugin 1.2.4 => NotAffected, already_open vrai => None (clos rétabli en phase 2): 5: lib
    exemplemodule 1.6.1.24 (quatre composants), plage <= 1.6.1.24 corrigée en 1.6.1.25 => Affected, correctif 1.6.1.25, comparateur PHP: 5: lib
    exemple/paquet 2.0.0-RC1, plage introduced 2.0.0-beta1 fixed 2.0.0 => Affected par Composer (préversion comprise): 5: lib
  section Packagist énumération et plage
    versions[] liste 1.5.0 hors de la plage 1.0.0..1.2.0 => Affected avec divergence, « listée hors plage »: 1: lib
    Plage contient 1.1.0, versions[] ne la liste pas => Affected (la plage fait foi): 1: lib
  section Fusion des doublons
    WF-… et GHSA-… de même alias CVE-2099-0001 => un seul groupe, deux membres, deux sources: 5: lib
    WF sans CVE et GHSA à CVE => deux groupes: 1: lib
    A~B par CVE, B~C par GHSA => un seul groupe A, B, C: 1: lib
    Groupe WF Internal + GHSA Free => Internal ; FOP FactsOnly + GHSA Free => FactsOnly: 1: lib
    Membre WF Affected, membre GHSA NotAffected => groupe Affected: 1: lib
    Correctifs 1.2.4 et 1.2.5 => correctif du groupe 1.2.5: 1: lib
    Membres gardés => (identifiant, source), aucune attribution copiée: 1: lib
  section Version ou plage inconnue
    @exemple/paquet sans version => Unknown(VersionUnknown), information: 5: lib
    Même cas, faille critique (CVSS 9,8) => avertissement: 1: lib
    Un membre RangeUnknown, un autre VersionUnknown => Unknown(RangeUnknown): 1: lib
    Plage corrigée par F3 (Candidate.corrected) => « plage corrigée »: 1: lib
  section Deux sources, un constat par base
    exemple-plugin agent 1.2.3 et ci 1.2.4 => un Finding, détail « agent : 1.2.3 ; ci : 1.2.4 », gravité de la vue agent: 5: lib
    Deux chemins Composer du même paquet (agent) à deux versions => un Finding, les deux versions listées: 1: lib
    Composant reporté (carried) => « absent d'un relevé partiel »: 1: lib
  section Seuils d'ouverture
    Une extension, 30 failles => un seul Finding, gravité maximale: 5: lib
    Groupes d'information seulement, already_open faux => None: 5: lib
    Mêmes groupes, already_open vrai => Finding en information: 5: lib
    EPSS 0,09 (info, already_open faux) => None ; 0,11 => avertissement ; 0,09 avec already_open vrai => information, jamais None: 1: lib
    CVE ajouté à KEV dans MemoryTables => même clé, critique: 5: lib
  section Dérogations (pures, horloge en paramètre)
    Dérogation (agent, exemple-plugin, CVE-2099-0002, 1.2.3, J+30) => groupe « sous dérogation », hors gravité: 5: lib
    Seul groupe touché sous dérogation, already_open faux => Finding en information (tenu ouvert): 1: lib
    À J+31 => Expired, gravité rendue: 5: lib
    Version agent 1.2.3.1 => VersionChanged ; dérogation ci sans effet sur la vue agent: 1: lib
    Saisie par GHSA-…, groupe WF + GHSA, covered_ids = {WF, GHSA, CVE} => couvre ; membre GHSA-nouveau ajouté au groupe => GroupChanged: 1: lib
    CVE entré dans KEV => Kev, critique: 1: lib
    validate : until > now + 90 j, dans le passé, motif vide ou de 501 caractères => refus avant toute requête: 1: lib
  section Détail et clé
    Clé => purl canonique sans version, jamais la version, le chemin, la source ni le nom: 5: lib
    Détail de 30 groupes => ≤ 4 096 caractères, « + K autres : vigie site vulns site-a », attributions entières: 1: lib
    Attribution fictive de 2 000 caractères => entière, groupes réduits: 1: lib
    ESC, U+202E dans un identifiant ou un lien => U+FFFD ; première ligne ≤ 200 sans saut de ligne: 1: lib
  section Péremption
    stale_finding(agent, 7 j) à 7 j + 1 s => avertissement inventaire-perime-agent ; à 7 j - 1 s => None: 5: lib
    stale_finding(ci, 35 j) => inventaire-perime-ci au-delà de 35 j seulement: 1: lib
  section Écosystème admis
    pkg:prestashop sur un site wordpress => non rapproché ; pkg:cargo partout => rapproché: 1: lib
  section Fuzz
    20 000 jeux générés (alias croisés, versions hostiles, deux sources) => aucune panique, détail borné, clé dans la grammaire: 1: lib
```

## Tasks to do

1. **`matching/mod.rs`** : `InventorySide { Agent, Ci }` (valeurs stockées `agent`, `ci`, comme la colonne `site_inventory.source` de F6) ; `Component` (côté, écosystème, purl sans version, version brute ou `None`, scope, chemin, `carried`) ; `admitted(kind, ecosystem)` par `capability::inventory_ecosystems` (F5), `match` sans joker.
2. **`group.rs`** : union-find sur les identifiants et alias normalisés des candidates d'un purl sans version ; clé de groupe = plus petit `CVE-…`, sinon plus petit identifiant ; par membre et par composant, `match_advisory(lignes, version)` ; `GroupVerdict` : `Affected` si un membre l'est (correctif = le plus grand des correctifs comparables, sinon tous listés), sinon `Unknown` avec `RangeUnknown` prioritaire sur `VersionUnknown`, sinon `NotAffected`.
3. **`assess.rs`** : `GroupFacts` par membre (`AdvisoryFacts::from_advisory`, F4), sérialisables ; `assess(group, &impl Exploitation)` par `assess_group` ou `assess_unknown` ; redistribution par `registry::redistribution` et `most_restrictive` (F3), `None` → `Internal` ; membres = `(identifiant, source)`.
4. **`waiver.rs`** : `Waiver { side, base, advisory_ref, version, covered_ids, until, reason }` ; `validate(&Waiver, now)` (échéance ≤ 90 jours et future, motif 1 à 500 caractères) appelé **avant** toute lecture en base ; `validate_against(&Waiver, group, installed_version, kev_hit)` (version connue et égale, groupe `Affected` ou `Unknown`, aucun CVE en KEV) ; `applies(..)` : `Ok`, `Expired`, `VersionChanged`, `GroupChanged` (un identifiant ou alias du groupe hors de `covered_ids`), `Kev`.
5. **`finding.rs`** :
   - `CHECK = "vulns"`, `KEY_STALE_AGENT = "inventaire-perime-agent"`, `KEY_STALE_CI = "inventaire-perime-ci"`, `MAX_VULNS_DETAIL_CHARS = 4_096`, `MAX_SUBJECT_CHARS = 200` ;
   - `base_finding(site, base, views: &[(Component, Vec<GroupResult>)], waivers, already_open, now) -> Option<Finding>` : agrégé sur toutes les vues (sources et chemins) du purl sans version ; gravité = maximum des groupes hors dérogation ; **retour** : `Some` à l'avertissement ou au-dessus ; `Some(Info)` si `already_open` et qu'un groupe `Affected`/`Unknown` subsiste, ou si un groupe est sous dérogation valide ; `None` sinon ;
   - détail : première ligne (purl sans version, versions par source, nombre de failles, de critiques, « corriger : ≥ <v> » ou « aucun correctif ») ; lignes de groupes triées ; « + K autres » ; attributions dédoublonnées (fournies par l'appelant à partir des identifiants de source), jamais tronquées ; `LogText` partout ;
   - `stale_finding(site, side, since, threshold, now)` : avertissement au-delà du seuil (le seuil vient de F6, `agent` 7 jours, `ci` 35 jours ; constante lue, jamais redéfinie ici).
6. **Fixtures** fictives au format des `Draft` de F1, passées par `Advisory::build` ; attributions fictives (titulaire inventé, liens `example.org`), aucun nom de domaine réel ; `README`.
7. **Tests** `tests/vulns_matching.rs` : chaque cas du Test Scope ; KEV et EPSS par `MemoryTables` ; fuzz à graine fixe (xorshift de `logs/tests.rs`).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Cas « Fusion des doublons », « Packagist » et « Version ou plage inconnue » verts ; un groupe n'est jamais `NotAffected` quand un membre est `Affected` ou `Unknown` |
| 3 | Gravité seulement par F4 (aucun seuil comparé dans `matching/`) ; aucune attribution copiée dans `GroupFacts` ni dans les membres |
| 4 | Cas « Dérogations » verts, dont « groupe changé » ; `validate` refuse avant toute lecture |
| 5 | Un `Finding` par purl sans version quelles que soient les sources ; cas « Seuils d'ouverture » verts (aucun `Some(Info)` sans incident déjà ouvert ni dérogation) ; détail ≤ 4 096, première ligne ≤ 200, attributions entières |
| 6-7 | Fixtures et attributions fictives (`README`), aucun domaine réel ; fuzz vert et reproductible en moins de 10 s en debug |
| 1-7 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.toml` inchangé |
