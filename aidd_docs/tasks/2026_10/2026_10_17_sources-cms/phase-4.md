---
status: pending
---

# Instruction: Corrections de plage auditées, documentation et procédure VPS

Corrections de plage pour les versions libres de Friends-Of-Presta, documentation de F3, puis gestes sur le VPS : relecture des conditions Wordfence, mesures, synchronisation réelle à la main.

## Architecture projection

```txt
.
├── CHANGELOG.md                           ✏️ entrée F3 (#17) sous Unreleased
└── vigie/
    ├── README.md                          ✏️ vigie vulns correct | corrections ; sources Wordfence et Friends-Of-Presta
    ├── migrations/
    │   └── 00NN.sql                       ✅ vuln_range_corrections en ajout seul (numéro : prochain libre à l'implémentation)
    ├── src/
    │   ├── store.rs                       ✏️ entrée de MIGRATIONS, SCHEMA_* ; tests de migration et instantané du schéma
    │   ├── main.rs                        ✏️ vigie vulns correct <advisory_id> <purl> (--range <expr> | --clear) --reason <motif> ; vigie vulns corrections [--audit [--verify]]
    │   ├── command/audit.rs               ✏️ chaîne réservée _veilleur (hors grammaire des identifiants de site) ; évènements range-corrected, range-correction-cleared
    │   └── vulns/
    │       ├── corrections.rs             ✅ add / clear (transaction IMMEDIATE : ligne + entrée d'audit) ; active(source, id, purl) ; état : active, sans objet, orpheline
    │       └── store.rs                   ✏️ (F1) candidates() : une ligne unevaluable de friends-of-presta prend la plage de la correction active, marquée « corrigée »
    ├── tests/
    │   └── vulns_corrections.rs           ✅ saisie, retrait, audit vérifié, application à la lecture, sans objet, orpheline, refus
    └── docs/
        ├── failles.md                     ✏️ fiches Wordfence et Friends-Of-Presta complétées ; relecture consignée et datée (au moment de la relecture)
        ├── decisions.md                   ✏️ sous-section « Sources CMS (issue #17) »
        └── hebergement.md                 ✏️ jeton Wordfence (inventaire « Secrets »), activation, corrections, relevé masqué de la synchronisation réelle
```

## Test Scope

```mermaid
journey
  section Corrections
    vigie vulns correct FOP-2099-… pkg:prestashop/module/modulelibre --range "<= 3.1.0" --reason "…" => ligne ajoutée, entrée _veilleur signée: 5: cli
    vigie vulns match pkg:prestashop/module/modulelibre@3.0.0 => Affected, « plage corrigée » ; @3.2.0 => NotAffected: 5: cli
    vigie vulns correct … --clear --reason "…" => retour à « plage inconnue », retrait audité: 5: cli
    vigie vulns corrections --audit --verify => chaîne _veilleur intègre et correspondance dans les deux sens: 5: cli
    Ligne d'audit altérée, entrée range-* sans correction, correction sans entrée d'audit (insérée hors outil) => vérification en échec: 1: cli
    Opérateur => nom du compte de getpwuid(geteuid()), même si USER est posé à autre chose: 1: lib
    ranges illisible en base (JSON cassé) => ligne toujours « plage inconnue », correction signalée illisible: 1: lib
  section Edge case
    UPDATE ou DELETE sur vuln_range_corrections => refusé par la base: 1: lib
    Sans [commands] => correction refusée, message clair, code 2: 1: cli
    Faille d'une autre source (WF-…, GHSA-…) => refusée, code 2: 1: cli
    Expression hors grammaire, remarque entre parenthèses, motif vide ou de 501 caractères => refusée, code 2: 1: cli
    Avis devenu lisible à la synchronisation suivante => plage de la source, correction « sans objet » dans vulns corrections: 1: cli
    Avis disparu de la source => correction « orpheline », sans effet: 1: cli
    Resynchronisation (nouvelle génération) => correction toujours appliquée: 1: lib
  section Documentation
    Test de cohérence constante ↔ failles.md => vert avant et après la relecture: 5: lib
```

## Tasks to do

1. **Migration** (prochain numéro libre) : `vuln_range_corrections` (`id INTEGER PRIMARY KEY AUTOINCREMENT`, `source`, `advisory_id`, `purl` sans version, `ranges` JSON ou NULL, `reason`, `operator`, `at`, `audit_hash`) ; index `(source, advisory_id, purl, id)` ; déclencheurs qui refusent `UPDATE` et `DELETE` ; `CHECK` sur les longueurs. Hors des générations : jamais purgée par `Load`.
2. **`corrections.rs`** : `add(store, audit_key, key, ranges, reason, now)` et `clear(...)` : vérifie que la faille et le purl existent dans la génération active de `friends-of-presta` ; expression analysée par `release.rs` (grammaire fermée, sans remarque) ; motif 1 à 500 caractères assaini ; opérateur = nom du compte de `getpwuid(geteuid())` (jamais `$USER` ; uid seul sans entrée passwd ou hors Unix) ; une transaction IMMEDIATE écrit la ligne et l'entrée d'audit (`audit::append`, chaîne `_veilleur`, évènements `range-corrected` / `range-correction-cleared`, détail JSON : clé, plage, motif, opérateur) et garde son hash dans `audit_hash` ; `active(...)` = ligne la plus récente non NULL ; `ranges` illisible à la relecture → correction ignorée (la ligne reste « plage inconnue ») et signalée ; état de chaque correction : `active`, `sans objet` (ligne de la source évaluable), `orpheline` (faille ou purl absent), `illisible`.
3. **Application à la lecture** : dans `candidates()` de F1, jointure sur la correction active ; seule une ligne `unevaluable` de `friends-of-presta` prend la plage corrigée ; verdict accompagné du drapeau `corrected` affiché « plage corrigée (motif) » par `match` et `show`.
4. **CLI** : `vigie vulns correct` (écrivain, `Store::open`) et `vigie vulns corrections [--audit [--verify]]` (lecture seule) ; `--verify` réutilise `audit::verify` sur la chaîne `_veilleur` **et** contrôle la correspondance dans les deux sens : chaque ligne de `vuln_range_corrections` a son entrée d'audit (`audit_hash`) au contenu égal, chaque entrée `range-*` de la chaîne a sa ligne ; tout écart → code 1 ; erreurs d'usage → `UsageError`, code 2 ; sans `[commands]` → refus, code 2.
5. **`failles.md`** :
   - fiche Wordfence : flux `production` retenu et pourquoi, lecture en flux (`Box<RawValue>` par entrée), attribution (message puis clés triées, `{}` distingué de l'absence, URL de licence jamais en lien actif), débit par le mécanisme de F2, conversion (tableau bornes → événements, `patched_versions` → `fixed`, borne basse exclusive traduite en inclusive), champs gardés et non stockés, attribution et ses deux comptes, borne de 256 plages, verrou à deux clés et la façon de consigner une relecture (constante, ligne de `failles.md`, `terms_reviewed`), débit, `Redistribution::Internal` ;
   - fiche Friends-Of-Presta : **ligne « Attribution » alignée sur le code** (lien GitHub de l'avis, `https://github.com/friends-of-presta/security-advisories/blob/main/_posts/<fichier>`, au lieu du site security.friendsofpresta.org), identifiants longs raccourcis par SHA-256, `Product` en liste découpé en plusieurs lignes, archive et hôtes, lecteur tar, en-tête et puces lus, identifiant, dates, catégories, grammaire fermée de `Impacted release` avec exemples, corrections de plage (saisie, audit, sans objet, orpheline), `Redistribution::FactsOnly` ;
   - plafonds des deux sources ; **limites connues** : extensions premium hors wordpress.org, slug homonyme, borne basse exclusive, versions libres hors grammaire, permalien du site Jekyll non utilisé, en-tête `Bearer` [NV] jusqu'à la relecture ; fixtures fictives.
6. **`decisions.md`** : sous-section « Sources CMS (issue #17) » de « Failles connues », une ligne par décision du plan et sa raison.
7. **`hebergement.md`** : jeton Wordfence dans l'inventaire « Secrets » (`~vigie/vigie/keys/wordfence-token`, 0600 dans un dossier 0700, vérifié par le code à chaque synchronisation) ; procédure : créer le compte et le jeton (section « Integrations »), `install -m 600`, relecture, puis activation ; corrections de plage ; hôtes à ouvrir. **Avertissement** à l'exploitant : déclarer `wordfence` et `[vulns.wordfence]` avant que la relecture soit consignée dans le binaire déployé fait sortir `vigie vulns sync` en **code 1** (source refusée, unité `failed`) et ouvre `vulns-sync/wordfence` au bout de 3 jours ; ne déclarer la source qu'avec un binaire dont `WORDFENCE_TERMS_REVIEWED` est posé. Premier passage à la main avant le timer pour chaque source.
8. **Sur le VPS, après le merge des phases 1 à 3** (gestes de l'exploitant, consignés sans valeur réelle) :
   1. vérifier la joignabilité de `www.wordfence.com`, `github.com`, `codeload.github.com` ;
   2. **relire** depuis le VPS les conditions Wordfence Intelligence et la page v3 (liste « À vérifier depuis le VPS », point 2) : forme de l'en-tête, conditions du jeton « Integrations », ETag ou Last-Modified, gzip, format v3 identique au v2, texte réel de `copyrights`, affichage permis ou non aux clients d'un prestataire ;
   3. **consigner** dans `failles.md` : date, URL relues, réponses ; dans le même commit, `WORDFENCE_TERMS_REVIEWED = Some("<date>")` et, si l'en-tête diffère, la forme corrigée dans `wordfence.rs` ; si les conditions excluent l'usage prévu, la source reste à `None`, la décision est écrite dans `decisions.md` et l'issue mise à jour ;
   4. Friends-Of-Presta (sans attendre la relecture Wordfence) : déployer, ajouter `friends-of-presta` à `[vulns] sources`, **premier passage à la main** `vigie vulns sync --source friends-of-presta`, relevé consigné (point 5), **puis seulement** laisser le timer le prendre en charge ; Wordfence, après la relecture : poser le jeton et `terms_reviewed`, déclarer la source, `vigie vulns sync --source wordfence` à la main, relevé, puis timer ;
   5. relevé **masqué** dans `hebergement.md` : durée, taille téléchargée, entrées, écartées par raison, `out_of_scope`, lignes `unevaluable`, longueur maximale d'attribution, nombre maximal de plages par ligne, **longueur maximale des noms de fichiers `_posts/`** (part des identifiants `FOP-…` raccourcis), mémoire de pointe (`/usr/bin/time -v`), sans jeton ni identifiant de compte ;
   6. ajuster les plafonds et seuils provisoires (y compris `max_dropped_ratio`) sur ces mesures (facteur ≥ 4), dans un commit séparé ; si `attribution_overflow` n'est pas nul, relever la borne avant tout affichage.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Migration depuis la version précédente verte ; `UPDATE` et `DELETE` refusés ; instantané du schéma à jour |
| 2-4 | Cas « Corrections » et « Edge case » verts ; une correction ne change jamais une ligne évaluable de la source ; chaque saisie et chaque retrait figurent dans la chaîne `_veilleur` vérifiée |
| 5-7 | Chaque décision et limite du plan figure dans `failles.md` ou `decisions.md` ; `hebergement.md` liste le jeton dans « Secrets » ; aucune donnée de production (règle « dépôt public ») |
| 8 | Relecture consignée et datée dans `failles.md` avant toute activation ; test de cohérence vert ; relevé masqué consigné ; issue #17 cochée sur la synchronisation réelle |
| 1-7 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `Cargo.lock` sans crate nouvelle |
