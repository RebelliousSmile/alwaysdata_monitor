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
    │   ├── api.rs                     ✏️ routes /sites/{id}/components, /sites/{id}/vulns, /vulns/sources ; DTO en liste blanche ; check_text étendu à vulns ; vulns_site_index (404 sans [sites.inventory])
    │   └── api/
    │       └── page.rs                ✏️ ComponentCursor (run, rang de gravité, base, path), VulnCursor (run, rang de gravité, base, path, group_key)
    └── tests/
        ├── api_vulns.rs               ✅ routes contre le routeur en processus, base rapprochée par tick::run_with
        ├── api_guards.rs              ✏️ valeurs semées (motif de dérogation, chemin vigie:path, opérateur) absentes des réponses
        └── fixtures/api-keys.json     ✏️ clés des nouveaux DTO, relues puis enregistrées (VIGIE_WRITE_API_KEYS=1)
```

## Test Scope

```mermaid
journey
  section Happy path
    GET /api/v1/sites/site-a/components => première page : purl, version, scope, source, vulns, severity ; trié gravité puis purl: 5: api
    GET /api/v1/sites/site-a/vulns => groupes touchés et inconnus : group, ids, component, version, verdict, fixed, severity, rule, kev, epss, score, redistribution, waiver, links, attributions: 5: api
    GET /api/v1/vulns/sources => une entrée par source : id, kind, last_success_at, last_outcome, age, entries, license, attribution, redistribution, incident vulns-sync ouvert: 5: api
    Incident vulns de site-a par /api/v1/incidents/{id} => détail assaini par LogText: 5: api
  section Pagination
    limit=2 sur 5 composants => trois pages, sans doublon ni trou: 5: api
    tick bascule un nouveau run entre deux pages => page suivante 409 cursor_expired, reprise au début: 1: api
    Curseur forgé, de 257 caractères ou d'une autre route => 400 bad_request: 1: api
  section 404 uniforme
    Site inconnu, site sans [sites.inventory], site jamais rapproché, base antérieure => 404 not_found identique: 1: api
    OPTIONS, POST sur ces routes => 404 commun: 1: api
  section Garde-fous
    Sans jeton ou jeton révoqué => 401 ; au-delà du débit => 429 avec Retry-After: 1: api
    Clés JSON => égales à api-keys.json, aucun champ de plus: 5: api
    Motif de dérogation, opérateur, vigie:path, corps d'inventaire, summary de source => jamais dans une réponse (valeurs semées): 1: api
    Identifiant, lien ou attribution avec ESC, U+202E, bidi => U+FFFD: 1: api
    Licence d'URL Wordfence (license_url) => texte, jamais un champ de lien: 1: api
  section Sources sans données
    Aucune source déclarée => liste vide ; kev jamais chargé => last_success_at null, incident null: 1: api
```

## Tasks to do

1. **Routes** dans `routes()` (`api.rs` l. 74-111), chacune avec `.fallback(not_found)` :
   - `GET /api/v1/sites/{id}/components` : `vulns_site_index` (site de la configuration, `capability::watched(site, "vulns", ..)`, schéma ≥ `SCHEMA_VULNS_MATCH`, `active_run` présent ; sinon 404 commun) ; page de `components_page` ; DTO `ComponentJson { purl, version, scope, source, vulns, severity }` (`source` = `agent` ou valeur de F6 quand elle existera, prérequis F5-2 ; `version` `null` si inconnue ; `severity` `null` sans faille) ;
   - `GET /api/v1/sites/{id}/vulns` : page de `items_page` ; DTO `VulnJson { group, ids, component, version, verdict ("affected" | "version_unknown" | "range_unknown"), corrected, divergence, fixed, severity, rule, kev: { date_added, ransomware } | null, epss: { score, percentile } | null (millionièmes), score (dixièmes), redistribution ("internal" | "facts_only" | "free"), waiver: { until, state } | null, links: [{ source, url }], attributions: [texte] }` ; le motif de la dérogation n'est pas servi (il reste sur le VPS) ;
   - `GET /api/v1/vulns/sources` : `SourceJson { id, kind ("vulns" | "enrichment"), last_success_at, last_outcome, entries, license, attribution, redistribution, dataset: { version, released } | null, incident: { id, severity, opened_at } | null }`, lu par `sync_state` (F2), `datasets()` (F4) et les incidents ouverts `_veilleur/vulns-sync/<source>` ; non paginé (7 sources au plus).
2. **Curseurs** (`api/page.rs`) : `ComponentCursor` et `VulnCursor`, préfixés comme `IncidentCursor` et `VerdictCursor` ; le `run` fixe l'instantané ; run qui n'est plus l'actif → 409 `cursor_expired` ; `limit` 1..100, défaut 50.
3. **Texte** : tout champ venu d'une source (identifiants, liens, attributions) par `LogText` (`MAX_ATTRIBUTION_CHARS` pour les attributions) ; `check_text` (`api.rs` l. 764-773) traite `vulns` comme `logs` (clé et détail des incidents) ; liens en `http`/`https` seulement (déjà validés par F1, revérifiés).
4. **État du site** : inchangé (`api.rs` l. 712-718) ; un incident `vulns` critique rend le site « non conforme », un incident d'information ne compte pas ; test qui le fixe.
5. **Tests** : `api_vulns.rs` (chaque cas du Test Scope, base rapprochée par `tick::run_with` sur fixtures fictives) ; `api_guards.rs` (valeurs semées, instantané des clés étendu, `VIGIE_WRITE_API_KEYS=1` pour enregistrer après relecture) ; journal d'appel : gabarit de route seulement, jamais un purl.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Cas « Happy path », « 404 uniforme » et « Sources sans données » verts ; aucune route n'expose `vigie:path`, motif, opérateur ni texte d'avis |
| 2 | Pagination sans doublon ni trou ; 409 sur run basculé ; 400 sur curseur invalide |
| 3 | Valeurs hostiles neutralisées ; instantané des clés vert |
| 4 | État du site conforme à la règle existante, testé avec un incident `vulns` critique et un d'information |
| 5 | Cas « Garde-fous » verts (401, 429, débit après authentification) |
| 1-5 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
