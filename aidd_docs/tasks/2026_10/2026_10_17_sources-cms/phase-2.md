---
status: pending
---

# Instruction: Convertisseur Friends-Of-Presta (archive, en-tête, plages libres)

Convertisseur pur : flux d'octets d'une archive `.tar.gz` du dépôt → `Advisory` de F1, écarts comptés. Ne dépend que de F1 ; `flate2` est promu en dépendance par F2 (si la phase 2 passe avant F2, elle fait cette promotion elle-même, sans crate nouvelle au `Cargo.lock`).

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   └── vulns/
    │       ├── advisory.rs                    ✏️ (F1) raisons de Tally ajoutées : bad_front_matter, unknown_category, bad_archive_member
    │       └── sources/
    │           ├── tar.rs                     ✅ lecteur ustar borné (F2 n'en écrit pas) en flux : en-têtes pax et GNU L pour le nom, fichiers ordinaires seulement, commentaire pax global
    │           ├── release.rs                 ✅ grammaire fermée de « Impacted release » → Vec<Range> ou Unrecognized ; partagée avec les corrections de plage (phase 4)
    │           └── friends_of_presta.rs       ✅ parse_archive(reader, sink, tally) ; front_matter() ; summary() ; to_draft() ; post_url()
    └── tests/
        ├── vulns_friends_of_presta.rs         ✅ archive construite par le test, conversion champ par champ, grammaire, hostiles, fuzz
        └── fixtures/vulns/friends-of-presta/
            ├── README                         ✅ « avis fictifs, même structure que les fichiers _posts/ du dépôt ; aucun avis réel »
            ├── _posts/                        ✅ avis fictifs (module, noyau, dependancies, quatre composants, plages libres variées)
            └── hostile/                       ✅ un avis par raison, issue attendue dans le nom du fichier
```

## Test Scope

```mermaid
journey
  section Archive
    Archive construite par le test (racine security-advisories-main/) => seuls _posts/*.md lus, révision lue dans le commentaire pax global: 5: lib
    Fichiers README, _layouts, images => ignorés sans compte: 5: lib
    Membre ../x.md, /etc/x, lien symbolique, lien dur, périphérique => ignoré, bad_archive_member: 1: lib
    Nom long par en-tête pax path ou GNU L => lu ; nom de plus de 4 096 octets => bad_archive_member: 1: lib
    Archive tronquée, somme d'en-tête fausse, gzip corrompu => erreur de flux, aucun chargement validé: 1: lib
    Plafonds : 50 001 membres, 512 Mio décompressés, avis de 1 Mio + 1 => erreur de flux ou too_large selon le cas: 1: lib
  section Happy path
    Module exemplemodule, <= 1.5.0 (1.5.1 fixed the vulnerability) => pkg:prestashop/module/exemplemodule, Floor, last_affected 1.5.0, fixed 1.5.1, scheme php: 5: lib
    Id FOP-2099-01-15-exemplemodule, alias CVE-2099-0002, CWE-89, published 2099-01-15 => champs du modèle: 5: lib
    severity critical (9.8) => provided_score 9.8, origine friends_of_presta ; vecteur CVSS:3.1 gardé: 5: lib
    Licence CC-BY-SA-4.0, attribution Friends-Of-Presta + lien GitHub de l'avis: 5: lib
    Catégorie core => pkg:prestashop/core/prestashop: 5: lib
    En-tête categories en scalaire, en [modules] et en puces => même résultat: 1: lib
  section Grammaire de Impacted release
    < 2.0.0 ; = 1.0.0 ; 1.0.0 ; v1.2.3 => plages attendues: 5: lib
    >= 1.0.0 <= 2.0.0 ; >= 1.0.0, < 2.0.0 ; 1.0.0 - 2.0.0 ; from 1.0 to 2.0 ; between 1.0 and 2.0 ; >= 3.0 => plages attendues: 5: lib
    <= 1.6.1.24 (fixed in 1.6.1.25) => quatre composants, fixed 1.6.1.25: 5: lib
    <= 1.5.0 (1.4.0 fixed the vulnerability) => contradiction, unevaluable: 1: lib
    <= 1.5.0 (WARNING NO PATCH) => remarque ignorée, aucun fixed: 1: lib
    all versions ; <= 1.2 and 2.0 ; 1.x ; <= 1.0-bogus ; vide => Unrecognized, ligne unevaluable: 1: lib
  section Verdicts sur les fixtures
    exemplemodule 1.5.0 => Affected, fixed 1.5.1 ; 1.5.1 => NotAffected: 5: lib
    Module à plage inconnue, toute version => Unknown(RangeUnknown), jamais NotAffected: 1: lib
  section Edge case - hostile
    Catégorie dependancies => écartée, out_of_scope ; catégorie absente ou inconnue => unknown_category: 1: lib
    Product mod.ule ou liste a, b => bad_purl, faille écartée et comptée: 1: lib
    En-tête sans --- final, de 65 lignes, avec ancre &a ou bloc | sur title => bad_front_matter: 1: lib
    Aucune section Summary ou aucun Product => aucun paquet identifié, faille écartée, no_affected: 1: lib
    Nom de fichier hors grammaire ou de plus de 64 caractères => bad_id: 1: lib
    Published at absent => date du nom de fichier ; illisible partout => bad_date: 1: lib
    severity critical (12) => ignoré seul, bad_severity: 1: lib
    Titre avec ESC, U+202E, 600 caractères => assaini, 500 caractères: 1: lib
  section Fuzz
    50 000 mutations des avis fictifs et 2 000 de l'archive => aucune panique, chaque Advisory borné: 1: lib
```

## Tasks to do

1. **`tar.rs`** : lecture en flux depuis un `Read` (gzip de `flate2::read::GzDecoder`), blocs de 512 octets, somme de contrôle vérifiée, tailles octales bornées ; en-têtes pax (`path`, `comment` global) et GNU `L` lus pour le nom seulement, 4 096 octets au plus ; rend les fichiers ordinaires (type `0` ou `\0`) avec leur nom et un lecteur borné ; les autres types sont sautés ; chemins normalisés, tout `..`, chemin absolu ou octet nul → `bad_archive_member` ; plafonds passés en paramètre (membres, octets décompressés), dépassement → erreur de flux.
2. **`friends_of_presta.rs`, sélection** : racine unique de l'archive (premier composant commun), seuls `<racine>/_posts/<nom>.md` ; `nom` → id `FOP-<nom>` (`[A-Za-z0-9._-]`, 64 caractères au plus) ; fichier de plus de 1 Mio → `too_large` ; révision = commentaire pax global (40 caractères hexadécimaux, sinon absente), rendue au cadre F2 pour `vuln_sources`.
3. **En-tête** `front_matter(text)` : premier `---` en ligne 1, fermeture `---` dans les 64 premières lignes et 8 Kio ; lignes `clé: valeur` ; valeurs nues, `"…"` (échappements `\"` et `\\` seulement) ou `'…'` ; `categories` en scalaire (séparé par espaces), `[a, b]` ou puces `- a` ; clés autres que `title`, `categories`, `severity` ignorées (puces d'`author` comprises) ; ancre, alias, `|`, `>` ou indentation inattendue sur une clé retenue → `bad_front_matter`.
4. **Corps** `summary(text)` : section `## Summary` jusqu'au titre suivant ; puces `*` ou `-` de forme `**Clé**: valeur` (clés comparées sans casse et sans espaces superflus) ; liens Markdown `[texte](url)` réduits au texte ; `CVE ID` (tous les CVE, 32 au plus), `Published at`, `Product`, `Impacted release`, `Weakness` (`CWE-\d+`, 8 au plus), `Severity` ; ligne `**Vector string**` cherchée dans tout le corps (`CVSS:3.0/` ou `CVSS:3.1/`, validé par `cvss.rs`).
5. **`release.rs`** : grammaire fermée du plan (« Grammaire fermée de `Impacted release` »), mots-clés sans casse, `v` initial retiré, chaque version analysée par le comparateur PHP de F1 ; rend `Ok(Vec<Range>)` ou `Unrecognized` ; la remarque entre parenthèses n'est reconnue que sous les trois formes listées ; borne basse > borne haute → `Unrecognized`. Vecteurs dans `tests/fixtures/vulns/friends-of-presta/release.json` (`[{"in", "out" | null, "why"}]`).
6. **Conversion** `to_draft(...)` : catégories (`modules`, `core`, `dependancies` → `out_of_scope`, autre → `unknown_category`) ; `Product` validé par la grammaire commune (`purl.rs`) ; plage reconnue → ligne évaluable, sinon ligne `unevaluable` (la faille est **gardée**) ; score de `severity` de l'en-tête, sinon de la puce ; `published` = `Published at`, sinon date du nom de fichier, `modified` = `published` ; licence `CC-BY-SA-4.0` ; attribution « Friends-Of-Presta, CC BY-SA 4.0 — <lien> » ; `source_url` = `post_url(nom)` ; `summary` = `title` assaini ; aucun autre texte de l'avis stocké. Tout passe par `Advisory::build`.
7. **Fixtures fictives** : une douzaine d'avis `_posts/2099-…-<module>.md` de même structure que les vrais (en-tête, `## Summary`, `## CVSS base metrics`, `**Vector string**`), modules inventés (`exemplemodule`, `autremodule`), CVE `CVE-2099-…`, liens `example.org` ; `hostile/` ; `README`. L'archive `.tar.gz` est construite par le test (en-tête pax global avec une empreinte inventée), jamais commitée.
8. **Fuzz** à graine fixe : mutations des avis (en-tête, puces, plages) et des octets de l'archive ; aucune panique ; `assert_bounded` sur chaque faille retenue.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Cas « Archive » verts ; aucune écriture sur disque ; mémoire bornée par le plus gros membre lu (1 Mio) |
| 2-4 | Cas « Happy path » et « hostile » verts ; aucun texte de l'avis hors `title` assaini n'atteint le modèle |
| 5 | `release.json` vert ; aucune formulation hors grammaire n'est reconnue ; aucune contradiction n'aboutit à une plage évaluable |
| 6 | Cas « Verdicts » verts ; une plage inconnue donne `Unknown(RangeUnknown)` pour toute version, jamais `NotAffected` ; `dependancies` compté `out_of_scope` |
| 7 | Aucun avis réel : modules, CVE et liens inventés ; `README` présent ; aucune archive binaire dans le dépôt |
| 8 | Fuzz vert et reproductible |
| 1-8 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.lock` sans crate nouvelle |
