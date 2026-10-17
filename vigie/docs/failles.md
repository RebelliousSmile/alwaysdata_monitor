# Failles connues : sources, standards et conventions

Ce document fixe d'où viennent les failles connues que Vigie rapproche des
composants d'un site, sous quels standards, et à quelles conditions (issue #14,
F0). Les issues #15 à #22 s'y appuient. Les décisions datées sont dans
[`decisions.md`](./decisions.md#failles-connues-issues-14-à-22).

Recherche du 2026-10-17. Chaque fait porte sa marque :

- **[V]** vérifié directement, par une requête depuis le conteneur de
  développement ou la lecture du fichier source ;
- **[S]** rapporté par une source secondaire (moteur de recherche, miroir,
  dépôt tiers), la page primaire n'étant pas joignable ;
- **[NV]** non vérifié ou déduit. Chaque [NV] qui compte figure dans
  [À vérifier depuis le VPS](#à-vérifier-depuis-le-vps).

## Principe

Le site ne connaît aucune base de failles. L'extension posée sur le site
décrit ses composants (inventaire CycloneDX) et l'envoie au veilleur, comme un
rapport. Le veilleur télécharge **chaque base en entier**, sur le VPS, et fait
le rapprochement en local.

```text
extension (site)                   veilleur (VPS)
inventaire CycloneDX ──signé──▶    inventaire du site (purl + version)
                                     │
bases complètes ──téléchargées──▶  rapprochement local
(OSV, Wordfence, Friends-Of-Presta,  │
 KEV, EPSS)                          ▼
                                   constats `vulns`
```

- Aucune API n'est jamais interrogée par composant : la liste des composants
  d'un client ne sort jamais du VPS, pas même sous forme de requête.
- Une base se télécharge avec une requête conditionnelle (`If-None-Match`,
  `If-Modified-Since`) quand la source le permet : un 304 ne coûte rien.
- Les tests n'appellent aucun hôte : ils lisent des fixtures locales, faites
  de composants et de failles publics ou fictifs.

## Standards

| Standard | Version retenue | Rôle dans Vigie | Référence |
| --- | --- | --- | --- |
| purl (Package URL) | spécification de `package-url/purl-spec`, branche main | identifiant de chaque composant, des deux côtés du rapprochement | `purl-types-index.json` et `types/<type>-definition.json` [V] |
| CycloneDX | **1.7** émis ; 1.6 et 1.7 acceptés | format de l'inventaire envoyé par l'extension | `bom-1.7.schema.json` [V] |
| Schéma OSV | **1.9.x** | modèle interne d'une faille, quelle que soit la source | `ossf/osv-schema`, `validation/schema.json` [V] |

### purl

- [V] Types enregistrés utiles : `composer`, `npm`, `cargo`. Le type
  `composer` a pour namespace le vendor, en minuscules, et pour dépôt par
  défaut https://packagist.org (`types/composer-definition.json`).
- [V] Aucun type `wordpress` enregistré (`types/wordpress-definition.json`
  répond 404). Proposition ouverte : issue purl-spec n° 347, « Add new PURL
  type: 'wordpress' », ouverte le 2024-11-20, ajoutée le 2026-06-10 au projet
  « Register new PURL types » (colonne Todo). Syntaxe suggérée :
  `pkg:wordpress/{core|theme|plugin}/{slug}@{version}`.
- [S] osv-scalibr définit déjà `TypeWordpress = "wordpress"` ; AWS Inspector
  écrit `pkg:generic/wordpress/core/wordpress@6.0.0`.
- [V] Aucun type ni aucune proposition pour PrestaShop (aucun résultat dans les
  issues de purl-spec).

### CycloneDX

- [V] Dernière version stable : 1.7. `bom-1.8` et `bom-2.0` répondent 404 dans
  `CycloneDX/specification`.
- [V] `$id` : `http://cyclonedx.org/schema/bom-1.7.schema.json`, JSON Schema
  draft-07, `specVersion` « 1.7 ». Fichier brut :
  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json
  (315 722 o).
- [S] Publiée le 2025-10-21, ratifiée comme ECMA-424 2e édition en
  décembre 2025 ; la 1.6 était la 1re édition (juin 2024).

### Schéma OSV

- [V] Spécification en version 1.9.2 du 2026-10-13 (`docs/schema.md` de
  `ossf/osv-schema`). Schéma JSON :
  https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json
- [V] Les exports OSV.dev observés portent `"schema_version": "1.9.0"`. Le
  schéma promet que les versions mineures restent rétrocompatibles.
- Les sources qui ne sont pas au format OSV (Wordfence, Friends-Of-Presta)
  sont converties vers ce modèle à l'import.

## Sources admises

### OSV.dev : exports par écosystème

| Élément | Valeur |
| --- | --- |
| URL | `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip` [V] |
| Écosystèmes | `Packagist`, `npm`, `crates.io`, casse exacte de `ecosystems.txt` [V]. Aucun écosystème WordPress ni PrestaShop [V] |
| Authentification | aucune [V] |
| Licence | pas de licence globale : chaque enregistrement relève de sa source [V] (tableau ci-dessous) |
| Attribution | celle de la source de l'enregistrement, lue dans son préfixe d'identifiant ; CC-BY 4.0 pour GHSA et EEF |
| Format | ZIP d'un JSON OSV par faille, `schema_version` 1.9.0 [V] |
| Taille (2026-10-17) | Packagist 10 956 660 o (≈ 10,4 Mio), npm 218 455 616 o (≈ 208 Mio), crates.io 3 610 436 o (≈ 3,4 Mio) [V] |
| Fréquence | export « continuously » ; mises à jour observées plusieurs fois par jour [V] |
| ETag / 304 | ETag et Last-Modified présents ; `If-None-Match` et `If-Modified-Since` → 304 ; `cache-control: public, max-age=3600` [V] |
| Joignabilité | conteneur de dev : oui ; VPS : à confirmer |

Champs utiles d'un enregistrement [V] : `id`, `aliases[]` (CVE), `modified`,
`published`, `withdrawn`, `summary`, `details`,
`affected[].package.{ecosystem,name,purl}`, `affected[].ranges[]` (type
`ECOSYSTEM`, événements `introduced`, `fixed`, `last_affected`),
`affected[].versions[]`, `severity[]` (`CVSS_V3`, `CVSS_V4`), `references[]`,
`database_specific.severity`. Les entrées `DRUPAL` ajoutent dans
`ranges[].database_specific.constraint` la contrainte Composer d'origine
(`">= 10.3.0 < 10.6.19"`).

Mise à jour incrémentale [V] : `…/<Ecosystem>/modified_id.csv` (Packagist :
357 803 o, ETag et Last-Modified), une ligne `<date ISO>,<id>` par faille, du
plus récent au plus ancien ; chaque enregistrement est aussi servi seul à
`…/<Ecosystem>/<ID>.json`.

Contenu observé le 2026-10-17 [V] :

| Écosystème | Entrées par préfixe |
| --- | --- |
| Packagist | 6 575 GHSA, 728 DRUPAL, 1 MAL |
| crates.io | 1 604 GHSA, 1 315 RUSTSEC, 21 MAL |
| npm | majoritairement GHSA, plus MAL et EEF (première page du listage seulement) |

Licences par source, d'après `docs/data.md` de `google/osv.dev` [V] :

| Préfixe | Source | Licence |
| --- | --- | --- |
| `GHSA-` | GitHub Advisory Database | CC-BY 4.0 |
| `RUSTSEC-` | RustSec | CC0 1.0 |
| `DRUPAL-` | Drupal Advisory Database | MIT |
| `MAL-` | OpenSSF Malicious Packages | Apache 2.0 |
| `EEF-` | EEF | CC-BY 4.0 |

Ordre des versions Packagist : l'issue google/osv.dev n° 426 (« *there is no
correct implementation of Packagist version ordering support* ») est fermée
depuis le 2022-07-06, renvoyée vers la n° 230 [V]. Les entrées Packagist
portent désormais une énumération `versions[]` [V]. L'état de la n° 230 n'est
pas vérifié [NV]. Vigie évalue toujours les `ranges` avec son propre
comparateur Composer et se sert de `versions[]` comme contrôle croisé.

#### GitHub Advisory Database (via OSV)

- [V] Licence CC-BY 4.0 (`LICENSE.md` de `github/advisory-database`). README :
  « *This project is licensed under the terms of the CC-BY 4.0 open source
  license.* », avec renvoi vers
  https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#12-advisory-database
- [NV] Forme exacte de l'attribution attendue : lien vers
  https://github.com/advisories ou vers chaque enregistrement, de mémoire.
  En attendant, Vigie affiche l'identifiant GHSA, un lien vers
  `https://github.com/advisories/<GHSA-ID>` et la mention « GitHub Advisory
  Database, CC-BY 4.0 ».
- [V] Format OSV ; Composer, npm et crates.io couverts. Tous les GHSA sont dans
  les exports OSV : le dépôt n'est pas téléchargé à part.
- [V] Couvre le **noyau PrestaShop** : l'API Packagist renvoie 31 avis pour
  `prestashop/prestashop`, tous de source « GitHub ».

#### FriendsOfPHP/security-advisories (non importé séparément)

- [V] Licence The Unlicense, sans attribution. Le README avertit : « *This
  database must not serve as the primary source of information for security
  issues, it is not authoritative* ».
- [V] Ce n'est pas une source d'OSV, mais le README de
  `github/advisory-database` cite « *The FriendsOfPHP Database* » parmi ses
  sources : son contenu arrive dans les GHSA, donc dans l'export OSV
  Packagist. L'importer aussi créerait des doublons.
- [V] Format pour mémoire : un YAML par faille (`title`, `link`, `reference`
  `composer://vendor/package`, `branches.<nom>.versions` en contraintes
  Composer, `cve`), sans numéro de schéma.

### Wordfence Intelligence v3

| Élément | Valeur |
| --- | --- |
| URL | `https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production` ; variante allégée `…/vulnerabilities/scanner` [V], lu dans `wordfence/api/intelligence.py` de wordfence-cli |
| Authentification | jeton gratuit, créé dans la section « Integrations » du compte Wordfence [S]. En-tête de wordfence-cli : `Authorization: Bearer cli-<licence>` [V] ; pour un jeton « Integrations », `Bearer <jeton>` probable [NV]. Le jeton vit dans un fichier 0600 sur le VPS, jamais dans le dépôt |
| Historique | flux v1 et v2 sans clé désactivés le 2026-03-09 [S] (le v2 répond 410 [S]) ; wordfence-cli n° 357 (2026-01-05), fermée par la PR n° 364 le 2026-01-28 [V] |
| Débit | une requête toutes les 30 minutes par défaut, `Retry-After` sur les 429 [S]. Vigie synchronise une fois par jour |
| Licence | « *perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable* », reproduction, affichage, sous-licence et distribution compris, sous condition de maintenir la mention de copyright de Defiant, la licence et celle de tout concédant [S]. « *publicly available for free for personal and commercial use, with token-based authentication* » [S] |
| Attribution | non fixe : **fournie dans chaque enregistrement** par `copyrights` (`message`, puis `<clé>.notice`, `.license`, `.license_url`, dont Defiant et, le cas échéant, MITRE) [S]. Elle est reproduite partout où la faille est affichée, avec un lien vers `https://www.wordfence.com/threat-intel/vulnerabilities/id/<id>` [S] |
| Format | un objet JSON dont les clés sont les UUID des failles ; pas de numéro de schéma, la version n'est que dans l'URL [V] (validateurs de wordfence-cli). Format v3 supposé identique au v2 [S] |
| Taille | ≈ 117 Mo (octobre 2025) à ≈ 123 Mo de JSON brut (flux production) [S] |
| Fréquence de la source | non documentée ici [NV] |
| ETag / 304 | non vérifié [NV] ; le miroir aringo/wfence compare une empreinte SHA-256 [S] |
| Joignabilité | conteneur de dev : refusé (403 du proxy, ENOTFOUND par WebFetch) ; VPS seulement |

Champs utiles [V] (flux scanner) : `id`, `title`, `software[].type`
(`core`, `plugin`, `theme`), `software[].slug`, `software[].name`,
`software[].affected_versions` (`{ "<libellé>": {from_version,
from_inclusive, to_version, to_inclusive} }`, `*` pour « depuis
toujours »), `software[].patched`, `software[].patched_versions[]`,
`informational`, `references[]`, `published`, `copyrights`. Le flux
production ajoute `description`, `cwe`, `cvss` (`vector`, `score`, `rating`),
`cve`, `cve_link`, `researchers[]`, `updated`, `software[].remediation`.

Le flux production est retenu : `cve` sert au rapprochement avec KEV et EPSS,
`cvss` à la gravité. Exemple reconstruit à partir des validateurs, l'hôte
n'étant pas joignable du conteneur [NV] :

```json
{"<uuid>": {"id": "<uuid>", "title": "Plugin X <= 1.2.3 - Reflected XSS",
  "software": [{"type": "plugin", "name": "Plugin X", "slug": "plugin-x",
    "affected_versions": {"* - 1.2.3": {"from_version": "*", "from_inclusive": true,
      "to_version": "1.2.3", "to_inclusive": true}},
    "patched": true, "patched_versions": ["1.2.4"]}],
  "cve": "CVE-…", "cvss": {"vector": "CVSS:3.1/…", "score": 6.1, "rating": "Medium"},
  "copyrights": {"message": "…", "defiant": {"notice": "…", "license": "…", "license_url": "…"}}}}
```

### Friends-Of-Presta : modules PrestaShop

| Élément | Valeur |
| --- | --- |
| Dépôt | `friends-of-presta/security-advisories`, branche `main`, site Jekyll publié sur https://security.friendsofpresta.org [V] |
| URL | archive `https://github.com/friends-of-presta/security-advisories/archive/refs/heads/main.tar.gz` [NV] (URL standard de GitHub, refusée dans le conteneur par la politique de la session) |
| Authentification | aucune |
| Licence | avis : **CC BY-SA 4.0**, d'après `_layouts/post.html` et `search.json` (« *This advisory and patch is licensed under https://creativecommons.org/licenses/by-sa/4.0/* ») [V]. Ambiguïté : `LICENSE.txt` à la racine est la licence MIT du thème minima, déclarée pour tout le dépôt [V]. Vigie retient CC BY-SA 4.0 pour les avis |
| Usage | interne, affiché avec attribution ; aucune redistribution publique, ce qui écarte la clause de partage dans les mêmes conditions |
| Attribution | « Friends-Of-Presta, CC BY-SA 4.0 », avec un lien vers l'avis sur https://security.friendsofpresta.org |
| Format | Markdown avec en-tête YAML, un fichier `_posts/AAAA-MM-JJ-<module>.md` par avis [V] |
| Taille | non mesurée [NV] |
| Fréquence | au fil des contributions ; nombre de fichiers et date du dernier commit non vérifiés [NV] |
| ETag / 304 | non vérifié pour l'archive [NV] |
| Joignabilité | conteneur de dev : site refusé (403), archive refusée par la politique GitHub de la session, fichiers bruts joignables sur raw.githubusercontent.com ; VPS : à confirmer |

Champs utiles [V] :

- en-tête : `title` (contient `[CVE-…]`), `categories` (`modules`, `core`,
  `dependancies`), `severity` (« `critical (9.8)` ») ;
- section `## Summary` du corps, en puces : `**CVE ID**`, `**Published at**`,
  `**Product**` (nom technique du module), `**Impacted release**` (texte libre,
  par exemple `<= 1.5.0 (1.5.1 fixed the vulnerability)`), `**Weakness**`,
  `**Vector string**` (`CVSS:3.1/…`).

Les versions affectées ne sont pas un champ machine : l'import analyse
`Impacted release` avec prudence ; une formulation non reconnue donne une
faille « plage inconnue » (`decisions.md`). `search.json` et `feed.xml` ne
contiennent pas les versions [V] : ils ne servent pas.

### CISA KEV

| Élément | Valeur |
| --- | --- |
| URL retenue | miroir officiel de CISA : `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` [V] |
| URL canonique | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (refusée dans le conteneur ; ETag non vérifié [NV]) |
| Authentification | aucune |
| Licence | CC0 1.0 : « *You may use this data in any legal manner* » (README de `cisagov/kev-data`, renvoi vers https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) [V]. Ni logo CISA ni sceau DHS ; les liens tiers relèvent de leurs licences |
| Attribution | aucune exigée ; Vigie nomme la source (« CISA KEV ») sans logo |
| Format | JSON ; schéma `known_exploited_vulnerabilities_schema.json` dans le même dépôt ; CSV aussi disponible [V] |
| Taille | 1 792 713 o, 1 748 entrées (`catalogVersion` 2026.10.16) [V] |
| Fréquence | « *typically happens weekdays during normal US Eastern business hours* » ; miroir synchronisé « *within minutes* » [V] |
| ETag / 304 | ETag présent, `If-None-Match` → 304 sur le miroir [V] |
| Joignabilité | conteneur de dev : miroir oui, cisa.gov non ; VPS : à confirmer |

Champs utiles [V] : en-tête `catalogVersion`, `dateReleased`, `count` ; par
entrée `cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`,
`vulnerabilityName`, `requiredAction`. Champ récent observé :
`forensicTriage`. La correspondance se fait par CVE, à partir des `aliases`
des autres sources.

### FIRST EPSS

| Élément | Valeur |
| --- | --- |
| URL | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` ; ancienne URL encore servie `https://epss.cyentia.com/epss_scores-current.csv.gz` ; suivre les redirections [S] |
| Authentification | aucune : « *EPSS scores are published daily, free of charge, with no registration required* » [S] |
| Licence | « FIRST EPSS Usage Agreement », sans licence nommée (copie ScanCode `first-epss-usage.LICENSE`, catégorie *Permissive*) [V] ; page d'origine https://www.first.org/epss/#Usage-Agreement. La FAQ traite de l'usage commercial [S] |
| Attribution | « See EPSS at https://www.first.org/epss » [V] |
| Format | CSV gzip : ligne de commentaire `#model_version:…,score_date:…`, puis `cve,epss,percentile` [S] |
| Taille | ≈ 382 600 CVE au 2026-10-04 [S] ; poids non mesuré [NV] |
| Fréquence | quotidienne [S] |
| ETag / 304 | non vérifié [NV] |
| Joignabilité | conteneur de dev : refusé ; VPS seulement |

L'API `https://api.first.org/data/v1/epss` n'est pas utilisée : elle ne sert
pas aux téléchargements en masse [S], et l'interroger par CVE dirait quelles
failles touchent les sites.

## Sources écartées

| Source | Raison citée |
| --- | --- |
| WPScan | « *For non-commercial use, the API can be used up to 25 API calls per day* » ; « *Permanent storage of our vulnerability data is not permitted. API vulnerability data caching is not permitted.* » ; « *Companies using our data to create their own services […] must use an Enterprise account.* » [S] (https://wpscan.com/api/, https://wpscan.com/docs/api/v3/) |
| Patchstack | Le « Threat Intelligence API » est « *custom pricing* » et « *activated on request* » [S] ; l'« App API » gratuite gère un compte et ne fournit pas de failles [S] ; aucune condition trouvée qui autorise le stockage de la base web. Ses CVE (Patchstack est CNA) arrivent en partie via Wordfence [NV] |
| NVD | Pas une source de détection : pas de correspondance fiable avec les composants WordPress, PrestaShop ou Composer. Enrichissement possible plus tard |
| API Packagist security-advisories | Interrogée par paquet (`?packages[]=vendor/pkg`) : contraire au principe ; conditions non vérifiées [NV]. Son contenu (GHSA et FriendsOfPHP) est déjà dans OSV |
| Archive de `github/advisory-database` | Redondante avec les exports OSV, et volumineuse (tous les écosystèmes) |

## Conventions purl

Côté extension comme côté veilleur, un composant est un purl avec version.
Le rapprochement compare le purl sans version, puis la version avec le
comparateur de l'écosystème.

| Composant | purl | Règle |
| --- | --- | --- |
| paquet Composer | `pkg:composer/<vendor>/<nom>@<v>` | vendor et nom en minuscules [V] |
| paquet npm | `pkg:npm/<nom>@<v>`, `pkg:npm/%40<scope>/<nom>@<v>` | scope en namespace, `@` encodé ; nom en minuscules (normalisation de la spec [NV]) |
| crate | `pkg:cargo/<nom>@<v>` | pas de namespace ; nom tel que publié (normalisation de la spec [NV]) |
| extension WordPress | `pkg:wordpress/plugin/<slug>@<v>` | proposition purl-spec n° 347 ; slug du répertoire wordpress.org, en minuscules |
| thème WordPress | `pkg:wordpress/theme/<slug>@<v>` | idem |
| noyau WordPress | `pkg:wordpress/core/wordpress@<v>` | la n° 347 suggère `core/core` ; Vigie écrit `core/wordpress`, comme AWS Inspector [S] |
| module PrestaShop | `pkg:prestashop/module/<nom_technique>@<v>` | par symétrie, aucune proposition ; nom technique du module (nom de son dossier), en minuscules |
| noyau PrestaShop | `pkg:prestashop/core/prestashop@<v>` | par symétrie |

Les types `wordpress` et `prestashop` ne sont pas enregistrés : ces
conventions sont à revoir si la spécification officialise autre chose.

## Correspondance source → purl

| Source | Champ lu | purl |
| --- | --- | --- |
| OSV `Packagist` | `affected[].package.name` = `vendor/nom` (ou `package.purl`, déjà en `pkg:composer/…` [V]) | `pkg:composer/vendor/nom` |
| OSV `Packagist`, `prestashop/prestashop` | idem | `pkg:prestashop/core/prestashop` (le noyau est déclaré ainsi par l'extension) |
| OSV `npm` | `affected[].package.name` (`@scope/nom` ou `nom`) | `pkg:npm/%40scope/nom` ou `pkg:npm/nom` |
| OSV `crates.io` | `affected[].package.name` | `pkg:cargo/nom` |
| Wordfence, `software[].type` = `plugin` | `software[].slug` | `pkg:wordpress/plugin/<slug>` |
| Wordfence, `software[].type` = `theme` | `software[].slug` | `pkg:wordpress/theme/<slug>` |
| Wordfence, `software[].type` = `core` | — | `pkg:wordpress/core/wordpress` |
| Friends-Of-Presta, catégorie `modules` | `**Product**` | `pkg:prestashop/module/<product>` |
| Friends-Of-Presta, catégorie `core` | — | `pkg:prestashop/core/prestashop` (doublons avec GHSA rapprochés par CVE) |
| Friends-Of-Presta, catégorie `dependancies` | `**Product**` | pas de règle fixée : point ouvert |
| CISA KEV | `cveID` | aucun : enrichit les failles par CVE |
| FIRST EPSS | `cve` | aucun : enrichit les failles par CVE |

## Hôtes à joindre depuis le VPS

En HTTPS (443), en sortie seulement :

| Hôte | Usage |
| --- | --- |
| `osv-vulnerabilities.storage.googleapis.com` | exports OSV Packagist, npm, crates.io |
| `www.wordfence.com` | flux Wordfence Intelligence v3 |
| `raw.githubusercontent.com` | miroir CISA KEV |
| `github.com`, `codeload.github.com` | archive Friends-Of-Presta (redirection de `github.com` vers `codeload`) |
| `epss.empiricalsecurity.com`, `epss.cyentia.com` | CSV EPSS (redirection entre les deux) |
| `www.cisa.gov` | URL canonique de KEV, en secours du miroir |

Aucun autre hôte : en particulier ni `api.osv.dev`, ni `api.first.org`, qui
s'interrogent par composant ou par CVE.

## À vérifier depuis le VPS

1. Joignabilité de chaque hôte de la liste ci-dessus.
2. Wordfence : relire https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/
   et https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/ ;
   forme exacte de l'en-tête (`Bearer <jeton>` ?), conditions propres au jeton
   « Integrations », ETag ou Last-Modified, compression gzip, format v3
   identique au v2 sur un vrai téléchargement, texte réel de `copyrights`.
3. EPSS : URL finale après redirection, en-têtes (ETag, Last-Modified), poids
   du fichier, conditions sur https://www.first.org/epss/#Usage-Agreement.
4. cisa.gov : ETag et 304 sur l'URL canonique.
5. Friends-Of-Presta : archive `main.tar.gz` joignable, ETag, taille, nombre
   d'avis et date du dernier commit.
6. GitHub Advisory Database : texte d'attribution exact sur la page
   docs.github.com citée plus haut.
7. Packagist : état de l'issue google/osv.dev n° 230 (ordre des versions).
