---
status: pending
---

# Instruction: API /api/v1 : composants, failles, sources

Trois routes en lecture, avec les garde-fous de #5 : authentification par jeton d'appareil, limite de débit, `LogText`, instantané des clés JSON, 404 uniforme. **Prérequis** : phase 2 (résultats stockés), phase 3 (états des dérogations).

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── api.rs                     ✏️ routes /sites/{id}/components, /sites/{id}/vulns, /vulns/sources ; DTO en liste blanche ; check_text étendu à vulns ; vulns_site_index (404 si non surveillé)
    │   └── api/
    │       └── page.rs                ✏️ ComponentCursor et VulnCursor : runs actifs de chaque source (agent, ci), rang de gravité, base, path, group_key
    └── tests/
        ├── api_vulns.rs               ✅ routes contre le routeur en processus, base rapprochée par tick::run_with
        ├── api_guards.rs              ✏️ valeurs semées (motif de dérogation, opérateur, vigie:path) absentes des réponses
        └── fixtures/api-keys.json     ✏️ clés des nouveaux DTO, relues puis enregistrées (VIGIE_WRITE_API_KEYS=1)
```

## Test Scope

```mermaid
journey
  section Happy path
    GET /api/v1/sites/site-a/components => runs, puis items : source, purl, version, scope, vulns, severity ; trié gravité puis purl: 5: api
    GET /api/v1/sites/site-a/vulns => runs, puis items : group, ids, component (purl), versions par source, verdict, corrected, fixed, severity, rule, kev, epss, score, redistribution, waiver, links, attributions: 5: api
    GET /api/v1/vulns/sources => une entrée par source : id, kind, last_success_at, last_outcome, entries, license, attribution, redistribution, dataset, incident vulns-sync ouvert: 5: api
    Incident vulns de site-a par /api/v1/incidents/{id} => clé et détail assainis par LogText: 5: api
  section Pagination
    limit=2 sur 5 composants => trois pages, sans doublon ni trou: 5: api
    tick bascule un nouveau run (rapprochement ou réévaluation KEV) entre deux pages => page suivante 409 cursor_expired, reprise au début: 1: api
    Curseur forgé, de 257 caractères ou d'une autre route => 400 bad_request: 1: api
  section 404 uniforme
    Site inconnu, non surveillé, jamais rapproché, base antérieure => 404 not_found identique: 1: api
    OPTIONS, POST sur ces routes => 404 commun: 1: api
  section Garde-fous
    Sans jeton ou jeton révoqué => 401 ; au-delà du débit => 429 avec Retry-After: 1: api
    Clés JSON => égales à api-keys.json: 5: api
    Motif de dérogation, opérateur, vigie:path, corps d'inventaire, summary de source => jamais dans une réponse (valeurs semées): 1: api
    Identifiant, lien ou attribution avec ESC, U+202E, bidi => U+FFFD ; license_url jamais un champ de lien: 1: api
  section Sources sans données
    Aucune source déclarée => liste vide ; kev jamais chargé => last_success_at null, incident null: 1: api
```

## Tasks to do

1. **Routes** dans `routes()` (`api.rs` l. 74-111), chacune avec `.fallback(not_found)` :
   - `GET /api/v1/sites/{id}/components` : `vulns_site_index` (site de la configuration, `capability::watched(site, "vulns", ..)`, schéma ≥ `SCHEMA_VULNS_MATCH`, au moins un `active_run` ; sinon 404 commun) ; réponse `{ site, runs: { agent, ci }, items: [ComponentJson { source, purl, version, scope, vulns, severity }], next_cursor }` ; `version` `null` si inconnue, `severity` `null` sans faille ;
   - `GET /api/v1/sites/{id}/vulns` : `{ site, runs, items: [VulnJson { group, ids, component, versions: [{ source, version }], verdict ("affected" | "version_unknown" | "range_unknown"), corrected, divergence, fixed, severity, rule, kev: { date_added, ransomware } | null, epss: { score, percentile } | null (millionièmes), score (dixièmes), redistribution ("internal" | "facts_only" | "free"), waiver: { source, until, state } | null, links: [{ source, url }], attributions: [texte] }], next_cursor }` : chaque faille **embarque** son composant et ses versions ; attributions relues à partir des identifiants de source (faille par `advisory`, sinon `vuln_sources`) ; le motif d'une dérogation n'est pas servi ;
   - `GET /api/v1/vulns/sources` : `SourceJson { id, kind ("vulns" | "enrichment"), last_success_at, last_outcome, entries, license, attribution, redistribution, dataset: { version, released } | null, incident: { id, severity, opened_at } | null }` par `sync_state` (F2), `datasets()` (F4) et les incidents ouverts `_veilleur/vulns-sync/<source>` ; non paginé.
2. **Curseurs** (`api/page.rs`) : `ComponentCursor` et `VulnCursor` portent les runs actifs de chaque source au moment de la première page ; une page dont un run n'est plus l'actif → 409 `cursor_expired` ; la réévaluation écrivant toujours un nouveau run (phase 2), aucune page ne voit une gravité changée en place : « sans doublon ni trou » tient ; `limit` 1..100, défaut 50.
3. **Texte** : tout champ venu d'une source par `LogText` ; `check_text` (`api.rs` l. 764-773) traite `vulns` comme `logs` ; liens `http`/`https` seulement.
4. **État du site** : inchangé (`api.rs` l. 712-718) ; un incident `vulns` critique rend le site « non conforme », un incident d'information ne compte pas ; test qui le fixe.
5. **Minimisation** : `/components` sert à la console appairée tous les composants surveillés du site, sans `vigie:path` ni `name` brut ; limite écrite dans `api-console.md` (phase 5).
6. **Tests** : `api_vulns.rs` (Test Scope) ; `api_guards.rs` (valeurs semées, instantané des clés) ; journal d'appel : gabarit de route seulement, jamais un purl.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Cas « Happy path », « 404 uniforme » et « Sources sans données » verts ; aucune route n'expose `vigie:path`, motif, opérateur ni texte d'avis |
| 2 | Pagination sans doublon ni trou ; 409 sur run basculé, réévaluation comprise ; 400 sur curseur invalide |
| 3 | Valeurs hostiles neutralisées ; instantané des clés vert |
| 4 | État du site conforme à la règle existante, testé avec un incident `vulns` critique et un d'information |
| 6 | Cas « Garde-fous » verts |
| 1-6 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
