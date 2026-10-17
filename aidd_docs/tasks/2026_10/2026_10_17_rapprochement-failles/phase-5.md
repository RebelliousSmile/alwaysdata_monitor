---
status: pending
---

# Instruction: Console (écran Failles, sources), contrat et documentation

Lecture seule dans la console : aucune action d'écriture. Puis la documentation de toute la série F7. **Prérequis** : phase 4.

## Architecture projection

```txt
.
├── CHANGELOG.md                               ✏️ entrée F7 (#21) sous Unreleased
└── vigie/
    ├── app/
    │   ├── CHANGELOG.md                       ✏️ écran Failles, sources de failles
    │   ├── src-tauri/
    │   │   ├── src/client.rs                  ✏️ components(site, cursor), vulns(site, cursor), vuln_sources() ; types limités aux champs affichés, champs facultatifs requis (nullable)
    │   │   ├── src/lib.rs                     ✏️ trois commandes Tauri ; test du nombre de commandes mis à jour
    │   │   └── tests/contract.rs              ✏️ routes de F7 contre le routeur en processus, base rapprochée par tick::run_with
    │   └── src/
    │       ├── lib/api.ts                     ✏️ types Component, Vuln, VulnSource ; appels
    │       ├── lib/features.ts                ✏️ « wordpress » pointe vers l'écran Failles
    │       ├── router/index.ts                ✏️ /s/:site/failles, /reglages/sources
    │       ├── views/Failles.vue              ✅ composants touchés, failles, gravité, corrections disponibles, dérogations (lecture), attributions, mentions « usage interne » et « faits seulement »
    │       ├── views/SourcesFailles.vue       ✅ âge et issue de chaque source, attributions, constat vulns-sync ouvert (lien vers l'incident)
    │       ├── components/SideNav.vue         ✏️ entrée « Failles » (site) et « Sources de failles » (réglages)
    │       ├── test/veilleur.ts               ✏️ faux veilleur : site-a avec failles fictives, sources fictives
    │       └── views/views.spec.ts            ✏️ deux écrans, états vide, 404, hors ligne, pagination
    └── docs/
        ├── failles.md                         ✏️ section « Rapprochement (F7) » ; « Contrôle vulns » et « Dérogations » complétées ; limites connues
        ├── api-console.md                     ✏️ trois routes, DTO, pagination, 404, « Écrans »
        ├── decisions.md                       ✏️ sous-section « Rapprochement inventaire × failles (issue #21) » de « Failles connues »
        └── hebergement.md                     ✏️ activation sur le VPS (ordre, relevé masqué du premier rapprochement)
```

## Test Scope

```mermaid
journey
  section Écran Failles
    site-a avec deux composants touchés => liste triée par gravité, version installée, version corrigée, KEV, EPSS, lien de la source, attributions sous chaque faille: 5: console
    Groupe Wordfence => mention « usage interne » ; groupe Friends-Of-Presta => « faits seulement »: 5: console
    Groupe sous dérogation => échéance affichée, sans motif, sans bouton: 5: console
    Version inconnue ou plage inconnue => libellé dédié, jamais « aucune faille »: 1: console
    Liste longue => page suivante chargée, sans doublon ; 409 => rechargement depuis le début: 1: console
    Site sans [sites.inventory] (404) => écran « non alimenté » de features.ts, aucune donnée d'exemple: 1: console
    Aucun bouton, aucune commande Tauri d'écriture ajoutée: 5: console
  section Écran Sources de failles
    Sources fictives => âge, dernière issue, attributions (GitHub Advisory Database CC-BY 4.0, Wordfence, Friends-Of-Presta, CISA KEV, See EPSS at https://www.first.org/epss): 5: console
    Source en retard => constat vulns-sync affiché, lien vers l'incident: 1: console
  section Contrat
    contract.rs : client Tauri contre le vrai routeur => trois routes lues, champs consommés présents ; un champ renommé côté veilleur fait échouer le test: 5: ci
  section Texte
    Attribution avec U+202E (déjà neutralisée par l'API) => affichée en texte, jamais en v-html ; license_url jamais en lien: 1: console
  section Documentation
    failles.md, api-console.md, decisions.md => chaque décision et limite du plan présentes ; aucun domaine, site ou composant réel: 5: doc
```

## Tasks to do

1. **Client Tauri** (`client.rs`) : `components(site, cursor)`, `vulns(site, cursor)`, `vuln_sources()` ; types ne portant que les champs affichés, facultatifs en `nullable` (règle du module, l. 4-6) ; trois commandes `#[tauri::command]` dans `lib.rs`, et le test qui compte les commandes mis à jour ; aucune commande d'écriture.
2. **Types et appels** (`lib/api.ts`), routes (`/s/:site/failles`, `/reglages/sources`), navigation (`SideNav.vue`, et `SegmentedNav` si l'écran entre dans un groupe existant) ; `features.ts` : la fonctionnalité `wordpress` renvoie vers « Failles » (lien `{ label: 'Voir les failles', name: 'failles' }`), son texte « manque » n'apparaît plus que sur un 404.
3. **`Failles.vue`** : composants touchés (gravité, purl, version, nombre de failles, correction disponible), puis pour chacun ses groupes (identifiants, état, CVSS, KEV, EPSS, version corrigée ou « aucun correctif », liens, attributions, mention de redistribution, dérogation : échéance et état) ; pagination par `next_cursor`, 409 → rechargement ; texte en interpolation seulement (`vue/no-v-html` en erreur) ; aucune action d'écriture ; un rappel : « mettre à jour se fait sur le site ».
4. **`SourcesFailles.vue`** : une ligne par source (âge de la dernière réussite, issue, entrées, licence, attribution, jeu KEV/EPSS), constat `vulns-sync` ouvert avec lien vers l'écran d'alerte existant.
5. **Faux veilleur** (`test/veilleur.ts`) : données fictives (site-a, `exemple-plugin`, `CVE-2099-…`, `example.org`) ; tests `views.spec.ts` (deux écrans, vide, 404, hors ligne, pagination, 409).
6. **Test de contrat** (`src-tauri/tests/contract.rs`) : veilleur en processus avec `[sites.inventory]` sur site-a, base remplie par les bibliothèques de F1, F4 et F5 puis rapprochée par `tick::run_with` ; lecture des trois routes par le client ; pagination parcourue jusqu'au bout.
7. **Documentation** :
   - `failles.md` : section « Rapprochement (F7) » : déclenchement par état comparé dans `tick` (inventaire, `match_epoch`, `enrich_epoch`, échéance de dérogation), budget et lots, sites à tour de rôle, runs et bascule, cache, sources admises par écosystème, fusion par alias et verdict du groupe, gravité (renvoi à `vulns/severity.rs`), un constat par composant et sa clé, détail (contenu, bornes, attributions), résolution (version corrigée, disparition sur inventaire complet, report sur inventaire incomplet), « inventaire périmé », dérogations (règles, caducité, audit, information au lieu de clôture), redistribution affichée ; « Contrôle `vulns` » : `Needs::InventorySource`, écart à l'issue ; **limites connues** : slug homonyme, `wpackagist` sur `generic`, fusion par alias erroné, audit non purgé, rapprochement au passage suivant (une minute) ;
   - `api-console.md` : trois routes (DTO, pagination, 404, curseur), écrans « Failles » et « Sources de failles », section « Base de données » (tables de F7) ;
   - `decisions.md` : sous-section « Rapprochement inventaire × failles (issue #21) » de « Failles connues », une ligne par décision du plan et sa raison, dont les écarts à l'issue (déclenchement par `tick`, contrôle surveillé selon la source déclarée, dérogation en information au lieu de clôture, `source` de l'API en attente de F6) ;
   - `hebergement.md` : activation (veilleur à jour, `[vulns]` et `[sites.inventory]`, premier `tick`), relevé **masqué** du premier rapprochement (nombre de sites, composants, incidents ouverts par gravité, passages nécessaires) ;
   - `README.md` (renvoi), `CHANGELOG.md` (racine et console).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Aucune commande Tauri d'écriture ajoutée ; test du nombre de commandes vert |
| 3-5 | Cas « Écran Failles », « Écran Sources de failles » et « Texte » verts ; `pnpm lint` (dont `vue/no-v-html`) et `pnpm test` verts ; attributions visibles sur chaque faille et chaque source |
| 6 | `cargo test --test contract` de la console vert ; un champ retiré côté veilleur le fait échouer (vérifié une fois, noté dans la PR) |
| 7 | `failles.md`, `api-console.md` et `decisions.md` (section F7) couvrent chaque décision et limite du plan ; aucune donnée de production (règle « dépôt public ») ; issue #21 cochée |
| 1-7 | fmt, clippy, tests verts sur Linux et Windows (veilleur et console) ; musl vert ; build Android et Windows de la console inchangés |
