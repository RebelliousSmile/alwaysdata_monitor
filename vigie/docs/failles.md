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

- L'inventaire d'un client ne sort jamais du VPS, pas même sous forme de
  requête : aucune API n'est interrogée par composant d'un site. Cette règle
  vise les inventaires des clients. Le contrôle des lockfiles de Vigie
  elle-même (F8, CI) interroge `api.osv.dev` : ces dépendances sont publiques
  dans le dépôt, la requête ne dit rien d'un client.
- Une base se télécharge avec une requête conditionnelle (`If-None-Match`,
  `If-Modified-Since`) quand la source le permet : un 304 ne coûte rien.
- Les tests n'appellent aucun hôte : ils lisent des fixtures locales, faites
  de composants et de failles publics ou fictifs (règles dans
  [Redistribution, affichage et fixtures](#redistribution-affichage-et-fixtures)).

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
- [S] osv-scalibr définit déjà `TypeWordpress = "wordpress"`.
- L'issue #14 proposait `pkg:wordpress-plugin/<slug>` ; Vigie suit la n° 347,
  un seul type `wordpress` et la catégorie en namespace.
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
| Attribution | celle de la source de l'enregistrement, lue dans son préfixe d'identifiant et conservée avec lui : CC-BY 4.0 pour GHSA et EEF, mention MIT pour DRUPAL, mention Apache-2.0 pour MAL ; rien n'est exigé pour RUSTSEC (CC0) |
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
  `prestashop/prestashop`, tous de source « GitHub ». Les modules natifs
  (`prestashop/<module>`) ont aussi des GHSA ; les modules tiers ne sont
  couverts que par Friends-Of-Presta.

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

### Wordfence Intelligence v3 (admis sous réserve)

L'import Wordfence (#17) n'est pas branché avant que les conditions
d'utilisation et la page v3 aient été relues depuis le VPS, et cette relecture
consignée et datée ci-dessous. Tant que ces conditions ne disent pas si les
failles peuvent être montrées aux clients d'un prestataire, l'usage reste
interne à l'exploitant : aucune faille Wordfence n'entre dans un document
transmis à un client.

Relecture des conditions depuis le VPS : **non faite au 2026-10-17**. À
consigner ici : date, URL relues, forme de l'en-tête d'authentification,
conditions propres au jeton, réponse sur l'affichage aux clients.

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
| Usage | interne, affiché avec attribution ; texte des avis jamais redistribué au sens de [Redistribution, affichage et fixtures](#redistribution-affichage-et-fixtures) : un document destiné à un client ne reprend que des faits, jamais le texte de l'avis |
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
faille « plage inconnue » ([Modèle interne et versions](#modèle-interne-et-versions)).
Les avis de catégorie `dependancies` sont écartés
([Correspondance source → purl](#correspondance-source--purl)). `search.json` et `feed.xml` ne
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
| paquet npm | `pkg:npm/<nom>@<v>`, `pkg:npm/%40<scope>/<nom>@<v>` | scope en namespace, `@` encodé ; sensible à la casse (`case_sensitive: true` dans la définition officielle) : comparé tel quel |
| crate | `pkg:cargo/<nom>@<v>` | pas de namespace ; sensible à la casse (`case_sensitive: true`) : comparé tel quel |
| extension WordPress | `pkg:wordpress/plugin/<slug>@<v>` | proposition purl-spec n° 347 ; slug du répertoire wordpress.org, tel quel (nom du dossier) |
| thème WordPress | `pkg:wordpress/theme/<slug>@<v>` | idem |
| noyau WordPress | `pkg:wordpress/core/core@<v>` | forme suggérée par la n° 347 |
| module PrestaShop | `pkg:prestashop/module/<nom_technique>@<v>` | par symétrie, aucune proposition ; nom technique du module (nom de son dossier), tel quel |
| noyau PrestaShop | `pkg:prestashop/core/prestashop@<v>` | par symétrie |

Seul `composer` passe en minuscules ; `npm` et `cargo` sont comparés tels
quels. Les types `wordpress` et `prestashop` ne sont pas enregistrés : ces
conventions sont à revoir si la spécification officialise autre chose.

**Grammaire commune** (un seul module `vigie/src/vulns/purl.rs`, écrit en F1 et
importé par l'inventaire F5 ; un seul fichier de vecteurs partagé par le Rust
et l'agent PHP) :

| Élément | Grammaire | Casse |
| --- | --- | --- |
| slug WordPress (extension, thème) | `[A-Za-z0-9._-]{1,200}` | tel quel |
| module PrestaShop | `[A-Za-z0-9_-]{1,64}` (règle `Validate::isModuleName` : pas de `.`) | tel quel |
| nom Composer | `vendor/nom` de Composer, longueur ≤ 214 | minuscules |
| nom npm, crate | définitions purl officielles | tel quel |
| version | `[0-9A-Za-z.+_-]{1,128}` | telle quelle |

Un composant hors grammaire est écarté et compté, côté agent comme côté
veilleur ; les deux appliquent la même grammaire, si bien qu'aucun composant
émis n'est écarté en silence à la réception.

Bedrock : un site WordPress géré par Composer déclare ses extensions comme
`wpackagist-plugin/<slug>` et ses thèmes comme `wpackagist-theme/<slug>`.
Ces paquets sont traduits en `pkg:wordpress/plugin/<slug>` et
`pkg:wordpress/theme/<slug>`, jamais rapprochés comme paquets Composer.
Limite : WPackagist ne reflète que le répertoire wordpress.org. Une extension
premium installée depuis un dépôt privé garde son propre vendor et n'est pas
traduite ; son slug, déclaré par l'extension de Vigie, peut aussi coïncider
avec celui d'une autre extension de wordpress.org.

## Correspondance source → purl

| Source | Champ lu | purl |
| --- | --- | --- |
| OSV `Packagist` | `affected[].package.name` = `vendor/nom` (ou `package.purl`, déjà en `pkg:composer/…` [V]) | `pkg:composer/vendor/nom` |
| OSV `Packagist`, `prestashop/prestashop` | idem | `pkg:prestashop/core/prestashop` (le noyau est déclaré ainsi par l'extension) |
| OSV `Packagist`, `prestashop/<x>` avec x ≠ `prestashop` | idem | indexé sous **les deux** purl `pkg:composer/prestashop/<x>` et `pkg:prestashop/module/<x>` : les modules natifs ont des GHSA, mais le vendor publie aussi des bibliothèques (`decimal`, `circuit-breaker`…) déclarées en `pkg:composer` ; F5 retire déjà le doublon Composer des vrais modules |
| OSV `npm` | `affected[].package.name` (`@scope/nom` ou `nom`) | `pkg:npm/%40scope/nom` ou `pkg:npm/nom` |
| OSV `crates.io` | `affected[].package.name` | `pkg:cargo/nom` |
| Wordfence, `software[].type` = `plugin` | `software[].slug` | `pkg:wordpress/plugin/<slug>` |
| Wordfence, `software[].type` = `theme` | `software[].slug` | `pkg:wordpress/theme/<slug>` |
| Wordfence, `software[].type` = `core` | — | `pkg:wordpress/core/core` |
| Friends-Of-Presta, catégorie `modules` | `**Product**` | `pkg:prestashop/module/<product>` |
| Friends-Of-Presta, catégorie `core` | — | `pkg:prestashop/core/prestashop` |
| Friends-Of-Presta, catégorie `dependancies` | — | aucun : écarté à l'import et compté (raison `out_of_scope`) |
| CISA KEV | `cveID` | aucun : enrichit les failles par CVE |
| FIRST EPSS | `cve` | aucun : enrichit les failles par CVE |

- Une faille présente dans GHSA et dans Friends-Of-Presta est fusionnée par
  CVE : une seule faille, les deux sources et leurs attributions.
- Côté extension (F5) : dans une boutique PrestaShop, un composant Composer de
  type `prestashop-module` est remplacé par le module de même nom, avec la
  version du module lue d'abord dans le littéral `$this->version` de son fichier principal (`config.xml` n'est qu'un cache régénéré par PrestaShop), avec repli sur `modules/<x>/config.xml` ; un écart entre les deux est signalé.
- Côté WordPress : voir Bedrock ci-dessus.
- Les avis Friends-Of-Presta de catégorie `dependancies` visent des
  bibliothèques tierces embarquées dans des modules. Ces bibliothèques sont
  détectées par OSV, sur les composants `composer` et `npm` de l'inventaire.
  Limite : une bibliothèque copiée dans un module sans `composer.lock` n'est
  pas vue.

## Inventaire reçu (CycloneDX)

Le veilleur accepte un sous-ensemble strict de CycloneDX 1.6 et 1.7, par
liste blanche. Un inventaire qui porte `authors`, `supplier`, `licenses` ou
une propriété hors de l'espace `vigie:*` est refusé en entier, pas seulement
le champ, par le 404 muet du point d'entrée, et compté au journal : ces champs
n'aident pas au rapprochement et peuvent porter des données du client.

## Modèle interne et versions

- Sous-ensemble du schéma OSV 1.9.x ; champs inconnus ignorés, champs retenus
  validés et bornés ; une entrée invalide est écartée et comptée.
- Entrées `withdrawn` ignorées.
- Plages `ECOSYSTEM` et `SEMVER` évaluées ; plages `GIT` ignorées (aucun
  composant n'est identifié par un commit).
- `affected[].database_specific.last_known_affected_version_range` des GHSA
  est lu quand aucun événement ne ferme la plage.
- Le comparateur est choisi selon l'écosystème de la source
  (`affected[].package.ecosystem`, ou le type de la source pour Wordfence et
  Friends-Of-Presta), jamais selon le site : Composer selon `composer/semver` (normalisation de `VersionParser` puis `version_compare`)
  (pré-versions comprises), npm et Cargo selon semver, WordPress et PrestaShop
  selon la sémantique de `version_compare`. Chaque comparateur est écrit et
  testé par Vigie.
- `versions[]` sert de contrôle croisé des `ranges`, toujours évaluées.
- Une version non analysable donne le constat « version inconnue », une plage
  libre de Friends-Of-Presta non reconnue le constat « plage inconnue », signalé
  pour toute version du module. Les deux sont de gravité information, sauf sur une faille critique (avertissement).

Le modèle est écrit par l'issue #15 (F1) : `src/vulns/` (plan
`aidd_docs/tasks/2026_10/2026_10_17_modele-failles/`). Les sous-sections
qui suivent en fixent les règles.

### Bornes

Mesurées le 2026-10-17 sur les exports OSV (crates.io et Packagist en
entier ; npm par son répertoire central et un échantillon de 1 600 entrées) :

| Mesure | crates.io | Packagist | npm (échantillon) | Borne |
| --- | --- | --- | --- | --- |
| taille d'une entrée | 146 124 o | 34 543 o | 1 148 610 o | 4 Mio (au-delà : faille écartée, `too_large`) |
| `affected` par faille | 406 | 24 | 92 | 1 024 (au-delà : `too_large`) |
| plages par `affected` | 1 | 6 | 2 | 256 (au-delà : ligne gardée `unevaluable`) |
| événements par plage | 46 | 2 | 2 | 128 (au-delà : ligne `unevaluable`) |
| `versions[]` par `affected` | 2 | 2 340 | 148 | 10 000 (entrée de trop ignorée seule) |
| longueur d'une version | 14 | 31 | 74 | 128, grammaire commune |
| alias | 16 | 6 | 8 | 32 |
| références | 146 | 121 | 149 | toutes lues, 10 gardées (`ADVISORY`, `FIX`, `WEB`, puis ordre de la source) |
| `severity[]` | 2 | 2 | 2 | 4 |
| CWE | 6 | 5 | 5 | 8 |
| longueur d'un id | 19 | 23 | 19 | 64 (`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`) |
| résumé | 163 car. | 241 car. (728 sans `summary`, DRUPAL) | 210 car. | 500 car. ; à défaut, première ligne de `details` ; `details` jamais stocké |

Le résumé et l'attribution (2 000 caractères) sont assainis comme le texte
des logs (`LogText` : contrôles, séparateurs Unicode et bidirectionnels en
U+FFFD). Les alias sont normalisés (`cve-` → `CVE-`, préfixes connus en
majuscules).

### Comparateurs

Le comparateur suit l'écosystème de la source (`SourceEcosystem`), jamais
celui du site : `Packagist` → Composer, `npm` et `crates.io` → semver,
Wordfence et Friends-Of-Presta → `version_compare`. Une plage OSV `SEMVER`
passe par semver quel que soit l'écosystème. Une plage Packagist sur
`pkg:prestashop/module/<x>` ou `pkg:wordpress/plugin/<slug>` reste une
plage Composer. Toute version est d'abord dans la grammaire commune
`[0-9A-Za-z.+_-]{1,128}` ; un composant numérique de plus de 18 chiffres est
illisible (sauf identifiant de préversion semver).

- **semver** (npm, Cargo) : semver 2.0 strict, sans `v`, `=`, forme
  partielle ni zéro initial (`1.2`, `v1.2.3`, `01.2.3` illisibles) ;
  préversions selon la §11 (`1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta.2 <
  1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0`), identifiants numériques comparés par
  longueur puis ordre lexical (aucun débordement) ; build ignoré
  (`1.0.0+a` = `1.0.0+b`), au contraire de la crate `semver`.
- **version_compare** (WordPress, PrestaShop) : canonisation exacte de
  `php_canonicalize_version` (`ext/standard/versioning.c`), puis comparaison
  par composants (`5.9 < 5.9.0`, `6.4-beta1 < 6.4-RC1 < 6.4 < 6.4.1`,
  `1.0 < 1.0pl1`, `1.01` = `1.1`). **Domaine accepté** : PHP apparie un mot
  inconnu par préfixe (`bogus` vaut `b`) et n'est pas transitif sur ces
  mots ; Vigie n'accepte que `dev`, `alpha`, `a`, `beta`, `b`, `RC`, `rc`,
  `pl`, `p`, sensibles à la casse comme PHP (`1.0-ALPHA`, `1.0-patch`,
  `1.0-bogus` illisibles), et refuse un composant vide (`1.0.`, `.1`). Sur ce
  domaine, l'ordre est total et identique à PHP (test différentiel).
- **Composer** (Packagist) : `VersionParser::normalize` de `composer/semver`
  (branche `main` du 2026-10-17, version 3.5.1), puis `version_compare` sur
  la forme normalisée : `v` et `+build` retirés, quatre composants
  (`1.2` → `1.2.0.0`), majeur de 5 chiffres au plus, sinon versions-dates
  (`20260101`, `2026-01-01` → `2026.01.01` ; `2026.01.01` reste une forme
  classique, `2026.01.01.0`), suffixes insensibles à la casse (`b2` →
  `beta2`, `rc1` → `RC1`, `p1`/`pl1`/`patch1` → `patch1`, `-stable`
  retiré), `-dev` final ; ordre `1.0.0-dev < 1.0.0-alpha < 1.0.0-beta2 <
  1.0.0-RC1 < 1.0.0 < 1.0.0-patch1`. Branches (`dev-main`, `1.x-dev`) et
  contraintes illisibles.
- **Plancher** : `introduced: "0"` est le plancher « depuis toujours »
  (`Bound::Floor`), jamais analysé comme version (`0` n'est pas semver) ;
  une plage avec `fixed` sans `introduced` reçoit ce plancher.

Vecteurs : `tests/fixtures/versions/<écosystème>.json` (Composer : cas de
`VersionParserTest`, texte MIT complet dans `NOTICE`) ; fuzz à graine fixe
(aucune panique, réflexivité, antisymétrie, transitivité) ; test
différentiel `tests/vulns_php_diff.rs` contre `version_compare` de PHP 8.1
en CI (`VIGIE_PHP`).

### Verdicts et agrégation

Par plage, le pseudo-code « Evaluation » d'OSV (événements triés, plancher
en tête, `introduced`, `fixed`, `last_affected`, `limit`), y compris une
plage qui mêle `fixed` et `last_affected`. Une ligne `affected` est touchée
si l'une de ses plages l'est. Pour un purl, une faille est :

1. **touchée** si l'une de ses lignes l'est, avec le plus petit `fixed`
   supérieur à la version parmi les lignes qui la contiennent (une GHSA
   peut porter une ligne par branche) ;
2. sinon **touchée avec `divergence`** si la version figure dans l'union
   des `versions[]` de ses lignes (contrôle croisé ; l'union d'OSV est la
   lecture prudente) ;
3. sinon **inconnue** si l'une des lignes l'est : « plage inconnue »
   (ligne `unevaluable`) avant « version inconnue » (version absente ou
   illisible pour le comparateur) ;
4. sinon **non touchée**.

Une plage ouverte au-delà de `last_known_affected_version_range` (`< v`,
`<= v`) reste touchée, drapeau `beyond_last_known`. Aucun chemin ne rend
« non touchée » pour une version ou une plage illisible.

### Écarts comptés

Aucune faille d'un paquet identifié n'est supprimée en silence. Chaque
écart est compté par raison (`Tally`), sans texte de la source :

| Issue | Raisons |
| --- | --- |
| faille perdue (`Reason::is_drop`, numérateur du taux d'écart de F2) | `too_large`, `bad_json`, `bad_id`, `bad_date` (`modified` absent ou non RFC 3339), `duplicate_id` (la seconde), `no_affected`, `bad_entry_name` (F2) |
| faille non gardée, exclusion normale | `withdrawn`, `no_affected_out_of_scope` (chaque `affected` d'un autre écosystème) |
| `affected` écarté seul | `bad_purl` (nom hors grammaire), `out_of_scope` (autre écosystème, dont `Packagist:https://packages.drupal.org/8`) |
| ligne gardée `unevaluable` (« plage inconnue ») | événement à zéro ou plusieurs clés, borne vide, hors grammaire ou illisible, type de plage inconnu, plus de 128 événements, plus de 256 plages, ni plage ni version : `unevaluable` |
| faille gardée | `unknown_license` (licence « inconnue », visible dans `vulns sources` et `show`) |
| entrée ignorée seule | `bad_version_entry`, `bad_reference`, `bad_severity`, `bad_last_known`, `bad_alias`, `bad_cwe` ; `purl_mismatch` (`package.purl` d'OSV différent du purl calculé, qui l'emporte) |

### Licences et attribution

Chaque faille porte sa licence et son attribution, reproduites partout où
elle est affichée. Table fermée par préfixe d'identifiant : `GHSA`, `EEF` →
`CC-BY-4.0` ; `DRUPAL` → `MIT` ; `MAL` → `Apache-2.0` ; `RUSTSEC` →
`CC0-1.0`. Un préfixe inconnu dans un dump OSV garde la faille, licence
« inconnue », attribution « OSV.dev » et lien vers l'enregistrement : une
faille connue ne disparaît jamais du rapprochement pour une raison
administrative. Les convertisseurs de F3 passent leur licence et leur
attribution (`copyrights` de Wordfence) par `Draft` et la même validation
(`Advisory::build`).

### Stockage par générations

Migration 15 : `vuln_sources`, `vuln_advisories`, `vuln_aliases`,
`vuln_affected` (`src/vulns/store.rs`). Seule la synchronisation (F2) écrit ;
`serve` lit. Un chargement réserve une génération (`next_generation`,
jamais réutilisée) sous bail de 6 h ; un second chargement est refusé tant
que le bail court, le reprend après. Les failles s'écrivent par lots de 500
(une transaction IMMEDIATE chacun, bail revérifié à chaque lot) ; la bascule
de `active_generation` est un compare-and-swap (génération active attendue
et bail détenu, sinon échec et génération orpheline) ; la purge retire par
lots tout sauf l'active et celle sous bail, puis `PRAGMA
wal_checkpoint(PASSIVE)`. Un lecteur ne voit que l'ancien jeu complet ou le
nouveau. Les corrections de plage de Friends-Of-Presta (F3) seront clées
`(source, advisory_id, purl)`, hors des générations.

### CLI

`vigie vulns sources | show <id|alias> | match <purl>`, en lecture seule
(`README.md`). `match` sans version donne chaque faille du paquet en
« version inconnue », jamais « aucune faille ». Un purl ou un identifiant
mal formé sort en code 2 ; une base absente ou antérieure à la migration 15
répond « aucune base de failles ».

### Fixtures

`tests/fixtures/vulns/osv/` : trois enregistrements réels intacts (GHSA
Composer, GHSA npm à scope, RUSTSEC), avec `NOTICE` (source, licence, lien,
modifications). `fictif/` et `hostile/` : cas inventés (`example.org`) ;
Wordfence et Friends-Of-Presta toujours fictifs, imités par `Draft`.
`purl.json` (format `[{"in", "out", "why"}]`) est rejoué par l'agent PHP
(F5) ; `osv-purl.json` et `cvss.json` (exemples de la spécification 3.1 de
FIRST) sont propres au Rust.

### Limites connues

- Aucun score n'est calculé depuis un vecteur CVSS v4 ; un vecteur v3.0 est
  calculé par la formule 3.1 (arrondi au dixième près, rarement différent).
- Les dépôts `Packagist:<url>` (Drupal) sont hors périmètre : Drupal n'est
  pas une typologie de Vigie.
- La borne basse exclusive de Wordfence (`from_inclusive: false`) est
  traduite en `introduced` inclusif par F3 : un signalement de trop plutôt
  qu'en moins.
- `last_known_affected_version_range` n'est qu'une information : il ne
  réduit jamais le verdict.
- Les contraintes Composer d'origine (`database_specific.constraint` des
  DRUPAL) ne sont pas conservées ; seules les plages OSV comptent.
- Les plages `GIT` sont ignorées (aucun composant n'est identifié par un
  commit) ; une ligne sans autre plage ni `versions[]` est `unevaluable`.
- Sémantique de `version_compare` : `1.0.0` est au-dessus de `1.0`, si bien
  qu'une borne Wordfence ou Friends-Of-Presta `last_affected: 1.0`
  n'inclut pas une version installée `1.0.0` ; c'est le comportement de
  PHP, gardé tel quel.
- La forme canonique d'un purl ne garde ni qualificatifs ni sous-chemin
  (validés, hors clé de rapprochement) ; elle encode chaque segment comme
  `rawurlencode` (`@` en `%40`, `+` d'une version en `%2B`).

## Gravité

Score CVSS lu dans cet ordre, le premier présent l'emporte. Il est stocké en
**dixièmes entiers** (98 pour 9,8, `Score { tenths }`, 0 à 100) : aucun
flottant ne sort du modèle, et les seuils ci-dessous se comparent à 90 et 70.
Le texte décimal d'une source (`9.8`) est lu en dixièmes ; plus d'une
décimale, plus de 10,0, un signe ou un exposant sont refusés.

1. `cvss.score` de Wordfence ;
2. score de la ligne `severity` de Friends-Of-Presta (`critical (9.8)` → 9,8) ;
3. CVSS v3.1 calculé depuis le vecteur `CVSS_V3` de `severity[]` d'OSV ;
4. sinon `database_specific.severity` des GHSA : `CRITICAL` = 9, `HIGH` = 7,
   `MODERATE` = 5, `LOW` = 3.

Aucun score n'est jamais calculé depuis un vecteur CVSS v4.

| Gravité | Condition |
| --- | --- |
| critique | un CVE de la faille est dans KEV, ou entrée `MAL-` (paquet malveillant), ou CVSS ≥ 9,0 |
| avertissement | CVSS ≥ 7,0, ou EPSS ≥ 0,1, ou gravité inconnue (sauf une entrée Wordfence `informational: true` sans score, classée information) ; « version inconnue » ou « plage inconnue » sur une faille critique (KEV, `MAL-`, CVSS ≥ 9,0) |
| information | tout le reste |

Les règles se lisent de haut en bas ; la première qui s'applique fixe la
gravité. Une faille qui relève d'une règle critique ou d'avertissement garde
ce niveau même si Wordfence la marque `informational: true` : ce drapeau ne
classe en information qu'une faille qu'aucune autre règle ne retient.
« Version inconnue » et « plage inconnue » sont de gravité information, sauf sur une faille critique : avertissement.

« Aucun correctif » est toujours affiché et ne fait jamais baisser la gravité.

## Dérogations

- Par site, composant et faille, jamais globales ; motif obligatoire.
- Expiration à 90 jours au plus. Ce plafond vaut pour les failles des sites ;
  le contrôle des dépendances de Vigie (F8, CI) a sa propre règle de 92 jours.
- Liée à la version du composant : une autre version la rend caduque.
- Inscrite dans l'audit.
- Interdite pour une faille dont un CVE est dans KEV.
- Distincte de la **correction de plage** : pour une plage libre de
  Friends-Of-Presta non reconnue, l'exploitant peut saisir sur le VPS la plage
  machine équivalente. Cette correction est auditée et vaut pour tous les
  sites, mais ne masque rien : elle remplace « plage inconnue » par une plage
  évaluée.

## Contrôle `vulns`

- Déclaré dans le registre de capacités (#4).
- Surveillé si le site a une source d'inventaire : agent PHP avec inventaire
  activé, ou clé d'inventaire enregistrée (#20). Les sites `node` et `static`
  sont donc couverts par la clé d'inventaire.
- Sans inventaire reçu depuis plus de 7 jours : constat d'avertissement
  « inventaire périmé ». Le contrôle reste surveillé : jamais de perte de
  surveillance en silence.
- Sources consultées : Wordfence pour un site `wordpress`, Friends-Of-Presta
  pour un site `prestashop`, OSV pour tout composant `composer`, `npm` ou
  `cargo`, quel que soit le site.
- Conservation : dernier inventaire et 30 jours d'historique ; détails des
  incidents `vulns` masqués 30 jours après leur clôture ; tout est purgé par
  `site remove`.

## Redistribution, affichage et fixtures

- **Redistribution** : tout ce qui est publié ou transmis à un tiers, client
  compris (e-mail, rapport, export, dépôt public).
- Wordfence : usage interne à l'exploitant tant que la relecture des
  conditions n'a pas tranché l'affichage aux clients (section Wordfence).
- Friends-Of-Presta : un document destiné à un client ne reprend que des faits
  (CVE, module, plage, vecteur CVSS, CWE, date), avec le lien vers l'avis,
  jamais le texte de l'avis.
- Fixtures Wordfence et Friends-Of-Presta : toujours fictives, de même
  structure que les vraies.
- Fixtures OSV et GHSA : de vrais enregistrements sont admis seulement avec un
  fichier `NOTICE` dans leur dossier (source, licence, lien, modifications).
- Aucune fixture ne reprend l'inventaire d'un client.

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

Aucun autre hôte depuis le VPS : en particulier ni `api.osv.dev`, ni
`api.first.org`, qui s'interrogent par composant ou par CVE. Le contrôle des
lockfiles de Vigie (F8) appelle `api.osv.dev` depuis la CI, pas depuis le VPS.

## À vérifier depuis le VPS

1. Joignabilité de chaque hôte de la liste ci-dessus.
2. Wordfence : relire https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/
   et https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/ ;
   forme exacte de l'en-tête (`Bearer <jeton>` ?), conditions propres au jeton
   « Integrations », ETag ou Last-Modified, compression gzip, format v3
   identique au v2 sur un vrai téléchargement, texte réel de `copyrights`,
   affichage permis ou non aux clients d'un prestataire. Consigner le résultat,
   daté, dans la section Wordfence.
3. EPSS : URL finale après redirection, en-têtes (ETag, Last-Modified), poids
   du fichier, conditions sur https://www.first.org/epss/#Usage-Agreement.
4. cisa.gov : ETag et 304 sur l'URL canonique.
5. Friends-Of-Presta : archive `main.tar.gz` joignable, ETag, taille, nombre
   d'avis et date du dernier commit.
6. GitHub Advisory Database : texte d'attribution exact sur la page
   docs.github.com citée plus haut.
7. Packagist : état de l'issue google/osv.dev n° 230 (ordre des versions).
