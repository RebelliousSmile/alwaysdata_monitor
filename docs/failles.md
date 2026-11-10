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

#### Import Wordfence (#17)

Code : `src/vulns/sources/wordfence.rs`. Plan :
`aidd_docs/tasks/2026_10/2026_10_17_sources-cms/`.

- **Verrou à deux clés.** Constante du binaire `WORDFENCE_TERMS_REVIEWED`
  (`None` aujourd'hui) et `[vulns.wordfence] terms_reviewed = "AAAA-MM-JJ"`,
  qui doivent être égales ; `wordfence` dans `[vulns] sources` exige la
  section, et réciproquement. Constante `None` ou dates différentes : refus
  explicite à chaque synchronisation (« source wordfence désactivée :
  relecture des conditions non consignée dans docs/failles.md »), sans
  aucune requête, visible dans `vulns sources`, `vulns sync` en code 1 ; au
  bout de 3 jours, le constat `vulns-sync/wordfence` s'ouvre. `fetch`
  revérifie le verrou juste avant la requête. La configuration reste valide :
  ni `serve` ni `tick` ne s'arrêtent. Un test lit la ligne de relecture
  ci-dessus et exige qu'elle dise la même chose que la constante
  (`non faite` ↔ `None`, `faite le AAAA-MM-JJ` ↔ `Some`). **Consigner une
  relecture** : dans un même commit, remplir cette ligne (« faite le
  AAAA-MM-JJ », URL relues, réponses), poser
  `WORDFENCE_TERMS_REVIEWED = Some("AAAA-MM-JJ")`, corriger l'en-tête si
  besoin ; puis, sur le VPS, `terms_reviewed` à la même date. Pas
  d'expiration : les conditions sont « *irrevocable* » [S].
- **Jeton** : fichier 0600 dans un dossier 0700 au propriétaire du veilleur
  (`secret.rs`, mêmes règles que les clés du canal de commandes), fichier
  ordinaire exigé avant l'ouverture (une FIFO ne bloque pas), 1 Kio lu au
  plus, `[A-Za-z0-9._~+/=-]{16,512}`, lu à chaque synchronisation, jamais
  copié en base ni en journal ; `Authorization: Bearer <jeton>` [NV] en
  valeur d'en-tête marquée sensible. Seul hôte `www.wordfence.com` : une
  redirection vers un autre hôte est refusée, le jeton ne part nulle part
  ailleurs. 401 et 403 : « jeton refusé », sans le corps.
- **Débit** : intervalle minimal de 30 min déclaré dans `SourceMeta`, tenu
  par le débit de F2 (`last_request_at`, `retry_after_until`) ; un refus de
  `fetch` consomme aussi la fenêtre.
- **Lecture en flux** : corps écrit par `Download` (512 Mio au plus), relu
  par `serde_json` entrée par entrée en `Box<RawValue>` (4 Mio par valeur,
  compteur d'octets en couche externe, remis à zéro à chaque clé ; 200 000
  entrées au plus ; 15 min). Syntaxe JSON, valeur trop grosse, trop
  d'entrées : erreur de flux, chargement abandonné. `id` et
  `software[].type` / `slug` seuls sont stricts (`bad_record`, faille
  écartée) ; tout autre champ est décodé à part, `null`, `[]` et `{}` valent
  « vide », un échec retire ce seul champ (`bad_severity`, `bad_cwe`,
  `bad_reference`, `bad_alias`, `bad_published`).
- **Conversion** : id `WF-<uuid>` (UUID validé, en minuscules, clé et `id`
  égales sinon `bad_id`) ; `cve` en alias ; un `software[]` par ligne
  (`plugin` → `pkg:wordpress/plugin/<slug>`, `theme` →
  `pkg:wordpress/theme/<slug>`, `core` → `pkg:wordpress/core/core`, autre
  type `out_of_scope`, slug hors grammaire `bad_purl`), comparateur PHP ; un
  libellé de `affected_versions` par plage :

  | Wordfence | Événement |
  | --- | --- |
  | `from_version: "*"` | plancher |
  | `from_version: A` (inclusive ou non) | `introduced A` (borne exclusive traduite en inclusive) |
  | `to_version: "*"` | plage ouverte |
  | `to_version: B`, `to_inclusive: true` | `last_affected B` |
  | `to_version: B`, `to_inclusive: false` | `fixed B` |
  | `patched: true` | `fixed` = plus petit `patched_versions[]` strictement au-dessus de `last_affected` |
  | borne illisible, `A` > `B`, libellé incomplet, `affected_versions` vide ou illisible | ligne `unevaluable` |

  `title` → résumé (assaini, 500 caractères) ; `cvss.score` lu **comme
  texte** et converti en dixièmes exacts (`6.1` → 61 ; `10.1`, `6.15`,
  `6e0` ou `"6.1"` : `bad_severity`) ; `cvss.vector` gardé ; `cwe.id` →
  `CWE-<id>` ; `references[]` (`WEB`) ; `informational` ; `published` ;
  `modified` = `updated`, sinon `published` (RFC 3339 ou `AAAA-MM-JJ
  hh:mm:ss` lu en UTC [NV]), sinon `bad_date`. `description`,
  `remediation`, `researchers` ne sont pas stockés. Licence
  `Wordfence-Intelligence`. Borne unique de F1 : 256 plages par ligne (le
  noyau en a une par branche).
- **Attribution** : `copyrights.message`, puis les autres clés **triées**,
  chacune `notice`, `licence <license>`, `license_url` (en texte, jamais en
  lien actif), séparées par « ; », puis « — » et le lien de
  l'enregistrement. `{}` (ou `[]`, `null`) : mention fixe « Wordfence
  Intelligence, © Defiant Inc. — <lien> », comptée `empty_copyrights` ;
  absente ou illisible : même mention, `no_copyrights` ; au-delà de
  2 000 caractères : même mention, `attribution_overflow`. La faille est
  toujours gardée ; ces trois comptes ne sont pas des pertes.
- **Redistribution** : `Internal` (usage interne à l'exploitant).
- `LOADER_VERSION = 1`, taux d'écart 1 % (provisoire, à confirmer par le
  relevé du VPS).

### Friends-Of-Presta : modules PrestaShop

| Élément | Valeur |
| --- | --- |
| Dépôt | `friends-of-presta/security-advisories`, branche `main`, site Jekyll publié sur https://security.friendsofpresta.org [V] |
| URL | archive `https://github.com/friends-of-presta/security-advisories/archive/refs/heads/main.tar.gz` [NV] (URL standard de GitHub, refusée dans le conteneur par la politique de la session) |
| Authentification | aucune |
| Licence | avis : **CC BY-SA 4.0**, d'après `_layouts/post.html` et `search.json` (« *This advisory and patch is licensed under https://creativecommons.org/licenses/by-sa/4.0/* ») [V]. Ambiguïté : `LICENSE.txt` à la racine est la licence MIT du thème minima, déclarée pour tout le dépôt [V]. Vigie retient CC BY-SA 4.0 pour les avis |
| Usage | interne, affiché avec attribution ; texte des avis jamais redistribué au sens de [Redistribution, affichage et fixtures](#redistribution-affichage-et-fixtures) : un document destiné à un client ne reprend que des faits, jamais le texte de l'avis |
| Attribution | « Friends-Of-Presta, CC BY-SA 4.0 — <lien> », lien GitHub de l'avis `https://github.com/friends-of-presta/security-advisories/blob/main/_posts/<fichier>` (le permalien du site Jekyll n'est pas vérifié [NV]) |
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

#### Import Friends-Of-Presta (#17)

Code : `src/vulns/sources/friends_of_presta.rs`, `tar.rs`, `release.rs`,
`src/vulns/corrections.rs`.

- **Archive** : `main.tar.gz` par `github.com`, redirigée vers
  `codeload.github.com` (deux seules origines), conditionnelle et comparée
  par SHA-256 (F2). Plafonds provisoires : 64 Mio compressés, 512 Mio
  décompressés, 50 000 membres, 1 Mio par avis (`too_large`), 10 min.
- **Lecteur tar maison** (pas de crate `tar`) : gzip mono-membre (un second
  membre est une erreur) ; blocs de 512 octets, somme de contrôle vérifiée,
  tailles octales seulement (base 256 refusée) ; en-têtes pax de 64 Kio au
  plus, enregistrements validés, `path` et `comment` lus, `size` refusée ;
  GNU `L` pour le nom (4 096 octets) ; données des membres sautés et
  bourrage comptés dans le plafond décompressé ; fin : deux blocs nuls puis
  10 240 octets de bourrage nul au plus. Racine unique exigée ; seuls les
  fichiers ordinaires `<racine>/_posts/*.md` sont lus ; chemin absolu,
  `..`, lien, périphérique ou nom trop long : ignoré et compté
  `bad_archive_member`. Rien n'est écrit sur le disque hors du dump. Le
  commentaire pax global (commit, 40 hexadécimaux) devient la **révision**
  de la source (`vigie vulns sources`).
- **En-tête YAML** lu par un analyseur ligne à ligne fermé : clés `title`,
  `categories`, `severity`, scalaires nus ou entre guillemets, `categories`
  en scalaire, `[a, b]` ou puces ; 64 lignes et 8 Kio au plus ; ancre,
  alias, bloc `|` ou `>`, indentation inattendue sur une clé retenue :
  `bad_front_matter` (faille perdue).
- **Corps** : puces `**Clé**: valeur` de `## Summary` (`CVE ID`, `Published
  at`, `Product`, `Impacted release`, `Weakness`, `Severity`), liens réduits
  à leur texte ; ligne `**Vector string**` cherchée dans tout le corps.
- **Identifiant** : nom du fichier sans `.md` (`[A-Za-z0-9._-]`, sinon
  `bad_id`) ; `FOP-<nom>` jusqu'à 60 caractères, sinon `FOPH-<47 premiers
  caractères>-<8 hexadécimaux du SHA-256 du nom>` (61 caractères, stable,
  préfixe distinct). Dates `AAAA-MM-JJ` → minuit UTC ; `published` =
  `Published at`, sinon date du nom de fichier (`bad_published` si
  `Published at` est illisible), sinon `bad_date` ; `modified` =
  `published`.
- **Catégories** : `modules` → `pkg:prestashop/module/<Product>`, `Product`
  découpé sur `,` et `/` (16 noms au plus), une ligne par module, nom hors
  grammaire `bad_purl` ; `core` → `pkg:prestashop/core/prestashop` ;
  `dependancies` → `out_of_scope` ; absente ou inconnue →
  `unknown_category` (faille perdue).
- **Score** : nombre entre parenthèses de `severity` de l'en-tête, sinon de
  la puce, en dixièmes exacts (`critical (9.8)` → 98 ; `(12)`, `(9.85)`,
  `(9,8)` : `bad_severity`) ; vecteur `CVSS:3.x` gardé.
- **Grammaire fermée de « Impacted release »** (mots-clés sans casse, `v`
  initial retiré, versions PHP) :

  | Forme | Plage |
  | --- | --- |
  | `<= 1.5.0` | plancher, `last_affected 1.5.0` |
  | `< 2.0.0` | plancher, `fixed 2.0.0` |
  | `1.0.0`, `= 1.0.0`, `v1.0.0` | `introduced 1.0.0`, `last_affected 1.0.0` |
  | `>= 1.0 <= 2.0`, `>= 1.0, <= 2.0`, `1.0 - 2.0`, `1.0 to 2.0`, `from 1.0 to 2.0`, `between 1.0 and 2.0` | `introduced 1.0`, `last_affected 2.0` |
  | `>= 1.0 < 2.0`, `>= 1.0, < 2.0` | `introduced 1.0`, `fixed 2.0` |
  | `>= 3.0` | `introduced 3.0`, ouverte |
  | `<= 1.5.0 (1.5.1 fixed the vulnerability)`, `(fixed in V)`, `(V fixes …)` | `fixed V` ajouté si V dépasse la borne `last_affected` ; égal à une borne `fixed` : rien ; sinon, ou sur une plage ouverte : « plage inconnue » |
  | autre remarque entre parenthèses (`(WARNING NO PATCH)`) | ignorée |
  | tout le reste (`1.0-2.0`, `all versions`, `1.x`, plusieurs plages, bornes inversées ou plage vide) | « plage inconnue » pour toute version |

  Vecteurs : `tests/fixtures/vulns/friends-of-presta/release.json`.
- **Corrections de plage** : voir [Dérogations](#dérogations).
- **Redistribution** : `FactsOnly`. Aucun texte de l'avis n'est stocké hors
  du titre assaini. `LOADER_VERSION = 1`, taux d'écart 1 % (provisoire).

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

Mesures du miroir du 2026-10-17 [V] : `200`, `content-type: text/plain;
charset=utf-8`, `cache-control: max-age=300`, pas de `Last-Modified` ; ETag
fort (64 caractères hexadécimaux entre guillemets), `If-None-Match` → 304 ;
1 792 713 o en clair (197 247 o si gzip était demandé, ce que Vigie ne fait
jamais) ; `catalogVersion` `2026.10.16`, `dateReleased`
`2026-10-16T17:15:48.8752Z`, `count` 1 748 = nombre d'entrées ; `cveID`
uniques, 16 caractères au plus ; `knownRansomwareCampaignUse` : `Known` 361,
`Unknown` 1 387 ; `vulnerabilityName` 161 caractères au plus. Schéma
`known_exploited_vulnerabilities_schema.json` (draft-07) : par entrée,
`cveID` (`^CVE-[0-9]{4}-[0-9]{4,19}$`), `vendorProject`, `product`,
`vulnerabilityName`, `dateAdded` et `dueDate` (`format: date`),
`shortDescription`, `requiredAction` requis.

**Lecture par Vigie (F4)** (`src/vulns/sources/kev.rs`, `LOADER_VERSION` 1) :
miroir d'abord, cisa.gov en secours (cisa.gov d'abord avec
`--accept-shrink`, geste explicite qui porte sur la source canonique) ;
document de 16 Mio et 20 000 entrées au plus, lu en mémoire et contrôlé
**avant toute écriture** ; champs de la liste lus en texte puis validés
(champ requis absent → `missing_field`, CVE hors grammaire → `bad_cve`, date
hors `AAAA-MM-JJ` → `bad_date`, CVE répété → `duplicate`) ;
`knownRansomwareCampaignUse` : `Known` → oui, `Unknown` ou absent → non,
autre → non et compté `unknown_ransomware` ; `count` différent du nombre
d'entrées → `count_mismatch` (compté, sans échec) ; `vulnerabilityName`
assaini et coupé à 200 caractères ; autres champs ignorés. **Régression** :
un catalogue dont `dateReleased` (horodatage complet, comparé à la seconde)
est antérieur à celui de l'actif est refusé : le miroir peut retarder sur
cisa.gov, et revenir au catalogue N après N+1 ferait disparaître des CVE
ajoutés. Si aucun hôte n'offre mieux, la synchronisation réussit « inchangé
(périmé) » (`stale_count` + 1, données et validateurs actifs gardés). Détail
du secours : [Priorisation (F4)](#priorisation-f4).

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

**Lecture par Vigie (F4)** (`src/vulns/sources/epss.rs`, `LOADER_VERSION` 1),
format toléré jusqu'au relevé du VPS (« À vérifier », point 3) : CSV gzip
lu **en flux** (`MultiGzDecoder`, plusieurs membres admis), jamais entier en
mémoire ; `Content-Encoding: gzip` admis **sans décodage**
(`SourceMeta::raw_content_encodings`), octets gardés tels quels et empreinte
calculée sur eux, tout autre encodage refusé ; lignes de 128 octets au plus,
`\r` final et dernière ligne vide tolérés ; première ligne
`#model_version:<v>,score_date:<date>` exigée (version de 32 caractères au
plus, date lue par son préfixe `AAAA-MM-JJ`, gardée à minuit UTC) ; en-tête
exactement `cve,epss,percentile` ; puis `CVE,score,percentile`, nombres de
`[0, 1]` écrits `0`, `1`, `0.d{1,9}`, `1.0{1,9}` ou `d(.d{1,9})?e-NN`, lus
en **millionièmes tronqués** par des entiers seuls (`parse_ppm` : 0,1 =
100 000 ; la troncature ne fait jamais franchir 0,1). Ligne fautive écartée
et comptée (`bad_cve`, `bad_value`, `missing_field`) ; CVE répété :
`duplicate`. Plafonds **provisoires**, à confirmer par le relevé : 32 Mio
compressés, 64 Mio décompressés, 2 000 000 lignes, 15 min.

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

Contrat complet (enveloppe, champs, propriétés `vigie:path`, `vigie:scope`,
`vigie:parent`, `vigie:config-version`, ordre des vérifications) :
[`protocole-agent.md`](./protocole-agent.md#inventaire-des-composants-issue-19),
issue #19 (F5).

Côté extension (agent PHP 0.5.0, `agent-php.md`) :

- **Doublons** : pour `wordpress` et `prestashop`, un composant par purl sans
  version, le relevé du disque l'emportant sur un lockfile (Bedrock,
  `prestashop-module`) ; pour `composer` et `npm`, un par (purl complet,
  `vigie:path`) : deux lockfiles peuvent porter deux versions réelles du même
  paquet. Le veilleur garde sa règle `(purl, path)` : un inventaire de l'agent
  n'y perd rien.
- **`complete`** : faux dès qu'une source attendue est refusée ou illisible
  (lien symbolique, hors racine, lecture en échec, lockfile trop gros,
  invalide ou en version non gérée), qu'un composant ou un paquet hors
  registre est écarté (`skipped`), ou qu'une borne (2 000 composants, 500
  entrées par dossier, 20 s, 512 Kio) a tronqué le relevé. **Seul un
  inventaire complet vaut absence d'un composant** : F7 ne conclut jamais
  « faille corrigée » d'un composant qui manque à un relevé partiel.
- **Hors registre** (règle commune avec l'outil #20) : un paquet de
  `composer.lock` vient d'un registre s'il porte `notification-url` ou si son
  nom est `wpackagist-plugin/…` ou `wpackagist-theme/…` ; dans
  `package-lock.json`, `resolved` en `git+`, `git:`, `github:`, `file:` ou
  hors de la forme `…/-/<fichier>.tgz` est hors registre. Hors registre :
  écarté et compté dans `skipped`. Membres du projet (workspaces, liens) : ni
  émis ni comptés.
- **Alias npm** : nom réel lu dans le champ `name` de l'entrée, sinon après le
  dernier `node_modules/` de la clé ; vecteurs communs à l'agent et à l'outil
  dans `tests/fixtures/inventory/npm-alias.json` (`[{key, entry, out, why}]`).
- **Outil de CI** (`vigie-inventory`, #20, `inventaire.md`) : mêmes règles
  de registre, d'alias et de doublons pour `composer.lock` et
  `package-lock.json` (test de parité sur les fixtures de l'agent), plus
  `pnpm-lock.yaml`, `yarn.lock` et `Cargo.lock` ; inventaire de source `ci`.
- **Limites V1** : disposition Bedrock complète, `roots/wordpress` et
  `johnpbloch/wordpress` comme cœur, `vendor/composer/installed.json` seul,
  `package-lock.json` v1, yarn et pnpm (outil #20), drop-ins, thèmes
  PrestaShop, licences et hachages ; extension à fichier unique nommée comme
  son fichier (`hello.php` n'est pas `hello-dolly`) ; un `wpackagist-*` sur un
  site `generic` reste `pkg:composer` et n'est jamais rapproché.

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
| entrée ignorée seule | `bad_version_entry`, `bad_reference`, `bad_severity`, `bad_last_known`, `bad_alias`, `bad_cwe` ; `purl_mismatch` (`package.purl` d'OSV différent du purl calculé, qui l'emporte) ; `bad_published` (F3 : date de publication illisible, repli sur une autre date) |
| faille perdue, sources de F3 | `bad_record` (Wordfence : `id` ou `software[]` de forme inattendue), `bad_front_matter`, `unknown_category` (Friends-Of-Presta) |
| note, sources de F3 | `empty_copyrights`, `no_copyrights`, `attribution_overflow` (mention Wordfence remplacée par la mention fixe), `bad_archive_member` (membre de l'archive ignoré) |

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
jamais réutilisée) sous bail (6 h au plus ; F2 : plafond de durée de la
source + 30 min) ; un second chargement est refusé tant que le bail court,
le reprend après. Les failles s'écrivent par lots de 500
(une transaction IMMEDIATE chacun, bail revérifié à chaque lot) ; la bascule
de `active_generation` est un compare-and-swap (génération active attendue
et bail détenu, sinon échec et génération orpheline) ; la purge retire par
lots tout sauf l'active et celle sous bail, puis `PRAGMA
wal_checkpoint(PASSIVE)`. Un lecteur ne voit que l'ancien jeu complet ou le
nouveau. Les corrections de plage de Friends-Of-Presta (F3, migration
`0018.sql`) sont clées `(source, advisory_id, purl)`, hors des générations
([Dérogations](#dérogations)).

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
Wordfence et Friends-Of-Presta toujours fictifs : `wordfence/` (flux
`production` fictif, UUID `00000000-0000-4000-8000-0000000000NN`, titulaire
inventé « Exemple Intelligence SARL », `CVE-2099-…`) et `friends-of-presta/`
(avis `_posts/` fictifs, `release.json`), chacun avec son `README` ;
l'archive `.tar.gz` est construite par le test, jamais commitée.
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
- Wordfence : les extensions premium hors wordpress.org (type autre que
  `plugin`, `theme`, `core`) sont hors périmètre ; un slug homonyme d'une
  extension sans rapport donne un faux positif ; l'en-tête `Bearer` reste
  [NV] jusqu'à la relecture depuis le VPS.
- Friends-Of-Presta : une formulation de « Impacted release » hors de la
  grammaire fermée donne « plage inconnue » jusqu'à une correction de plage ;
  le permalien du site Jekyll n'est pas utilisé (lien GitHub de l'avis).
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

## Synchronisation (F2)

Issue #16, plan `aidd_docs/tasks/2026_10/2026_10_17_synchro-failles/`. Code :
`src/vulns/sync/` (cadre, téléchargeur, lecteur zip, moteur, registre,
constat de fraîcheur) et `src/vulns/sources/osv.rs`.

### Commande et timer

`vigie vulns sync [--source <id>] [--accept-shrink]`, lancée chaque jour par
`vigie-vulns-sync.timer` (`OnCalendar=*-*-* 03:40:00`,
`RandomizedDelaySec=45min`, `Persistent=true`), distincte de `tick` : le
passage d'une minute ne télécharge jamais de dump. Seule cette commande écrit
les tables de failles ; `tick` lit `vuln_sources`, `serve` lit les failles.

| Situation | Sortie |
| --- | --- |
| aucune source déclarée (`[vulns]` absente ou `sources = []`) | « aucune source de failles déclarée », code 0 |
| sources chargées, inchangées (304, même empreinte), `busy` ou `rate_limited` | une ligne par source, code 0 |
| une source `failed` ou `refused_shrink` | les autres continuent, code 1 (unité `failed`) |
| configuration invalide, `--source` hors de `[vulns] sources`, `--accept-shrink` sans `--source` | code 2 |

`rate_limited` sort en code 0, accepté : un 429 ou un 503 d'OSV avec
`Retry-After`, ou une fenêtre de débit pas encore rouverte, n'est pas une
panne du veilleur. `retry_after_until` garde la date ; si l'attente dure, le
constat `vulns-sync` le signale à 3 jours.

### Sources et ordre

`[vulns] sources` est une liste fermée (`vulns::sync::registry::KNOWN`) :
`osv-crates-io`, `osv-packagist`, `friends-of-presta`, `wordfence`
(avec `[vulns.wordfence]`, #17), `osv-npm`, synchronisées dans cet ordre
(petites d'abord), une échéance par source ; puis les tables de
priorisation `kev` et `epss` (F4), ajoutées d'office
([Priorisation (F4)](#priorisation-f4)). `registry::redistribution(id)`
donne le niveau de redistribution de chaque identifiant (`wordfence` →
`Internal`, `friends-of-presta` → `FactsOnly`, OSV, `kev`, `epss` → `Free`) ;
un identifiant inconnu du binaire rend `None`, traité comme `Internal` par
F7. Identifiant inconnu, doublon ou
clé inconnue : erreur de configuration (code 2). Aucune URL n'est
configurable : l'origine `https://osv-vulnerabilities.storage.googleapis.com`
(port 443) est codée en dur, chaque redirection revérifiée (3 au plus).
Les tests épinglent leur propre origine par le code (`SyncOptions`), jamais
par la configuration.

### Plafonds

Facteur ≈ 3 sur la mesure du 2026-10-17, à confirmer par le relevé réel
(`hebergement.md`) :

| Source | Compressé | Décompressé | Entrées | Durée | Mesure (compressé, décompressé, entrées) |
| --- | --- | --- | --- | --- | --- |
| `osv-crates-io` | 32 Mio | 64 Mio | 20 000 | 15 min | 3 610 436 o, 7 206 166 o, 2 940 |
| `osv-packagist` | 64 Mio | 256 Mio | 50 000 | 15 min | 10 956 660 o, 26 601 548 o, 7 303 |
| `osv-npm` | 640 Mio | 1,5 Gio | 700 000 | 90 min | 218 455 616 o, 386 676 813 o, 230 382 |

Pour toutes : 4 Mio par entrée (borne F1 ; au-delà, entrée sautée et
comptée `too_large`), répertoire central de 64 Mio, taux d'écart de 1 %.
Contrôle **avant** décompression (`Content-Length`, nombre d'entrées, somme
des tailles déclarées) et **pendant** (octets reçus, octets réellement
décompressés, échéance) : une bombe zip est arrêtée par les tailles
déclarées, puis par les tailles réelles si elles mentent.

### Lecteur zip

Lecteur maison (`vulns/sync/zip.rs`), pas la crate `zip` : les dumps OSV
n'emploient qu'un sous-ensemble minuscule du format (mesuré), tout le reste
est refusé.

- **Admis** : fin de fichier classique ou ZIP64 (enregistrement, localisateur
  et fin classique chaînés, chacun exactement à sa place, un seul disque),
  méthodes 0 (tailles égales) et 8, bits 1, 2 et 11 des drapeaux.
- **Refusé, dump entier** : répertoire central qui n'est pas contigu juste
  avant la fin, qui n'est pas consommé exactement ou dont le nombre d'entrées
  diffère du nombre déclaré ; chiffrement, données « patchées », ZIP64 par
  entrée, autre méthode ; descripteur de données (« descripteurs de données
  non pris en charge : format de l'export changé ? ») ; en-tête local
  différent du répertoire central ; enregistrements locaux qui se
  recouvrent ou passent sous le répertoire central ; CRC faux, longueur réelle
  différente de la déclarée, flux deflate corrompu ; tout dépassement
  d'offset ou de taille (`u64` vérifié).
- **Sauté et compté** : entrée de plus de 4 Mio déclarés (`too_large`, jamais
  décompressée), nom hors de `[A-Za-z0-9._-]{1,64}\.json` ou dossier
  (`bad_entry_name`).

**Rien n'est extrait sur le disque** : seul le dump compressé est écrit, dans
`<dossier de la base>/vulns-work/<source>/` (0700, fichier 0600 créé en
`create_new`, lien symbolique refusé), vidé au début et à la fin par le seul
détenteur du bail. Chaque entrée est décompressée en mémoire (taille
déclarée + 1 octet lus au plus), analysée par `from_osv`, puis poussée par
lots de 500 ; le nom d'une entrée n'est jamais un chemin. Un test
différentiel relit les zips de test avec `zipfile` de Python en CI.

### Requête conditionnelle et empreinte

`Accept-Encoding: identity` (toute autre `Content-Encoding` est refusée),
`If-None-Match` et `If-Modified-Since` depuis l'état de la source ; 304 et
SHA-256 du dump égale à celle de la génération active (calculée en flux, le
zip n'est alors pas ouvert) donnent « inchangé » : **aucune génération
écrite**, le bail rendu et le succès daté en une seule instruction
compare-and-swap (`finish_unchanged`), validateurs gardés (304) ou remplacés
par ceux de la réponse (même empreinte). Après un chargement, ETag (ASCII
imprimable, 256 caractères au plus) et `Last-Modified` (date HTTP valide)
sont écrits **dans la même instruction que la bascule**, jamais avant : un
ETag sans sa génération figerait la base sur un 304 perpétuel.

`LOADER_VERSION` (1 pour OSV) est enregistrée avec la génération ; si elle
diffère de celle du binaire, la requête part sans en-têtes conditionnels et
l'empreinte n'est pas comparée : une correction du lecteur s'applique au
passage suivant. À incrémenter à chaque changement du lecteur zip, de
`from_osv` ou des bornes F1 qui change ce qui est stocké.

### Seuil d'écart et garde contre le rétrécissement

- **Taux d'écart** : failles perdues (raisons `Reason::is_drop` : `too_large`,
  `bad_json`, `bad_id`, `bad_date`, `duplicate_id`, `no_affected`,
  `bad_entry_name`) sur les entrées lues du dump ; au-delà de 1 %, le dump est
  refusé (`failed`, compteurs par raison dans `last_error`). Les retraits
  (`withdrawn`), les failles d'un autre écosystème
  (`no_affected_out_of_scope`) et les simples notes (`bad_reference`,
  `bad_purl`…) ne comptent jamais.
- **Rétrécissement**, ensuite : un dump dont les failles retenues font moins
  de 80 % du maximum des 7 derniers chargements réussis (`recent_entries`,
  dès 100 failles) est refusé (`refused_shrink`, ancien jeu gardé, code 1).
  `vigie vulns sync --source <id> --accept-shrink` l'accepte une fois, le
  journalise, et ce chargement devient la seule référence.

### Bail, débit et échecs

Le bail de F1 est pris **avant** toute requête, pour le plafond de durée de
la source + 30 min : un second `vulns sync` sur la même source répond `busy`
sans rien télécharger (code 0) ; `vigie vulns sources` montre l'âge du bail en
cours. Puis le débit, en compare-and-swap : `last_request_at` (intervalle
minimal de la source, 0 pour OSV ; 30 min pour Wordfence en F3) et
`retry_after_until` (`Retry-After` borné à 24 h). Un refus de débit rend le
bail sans toucher `last_request_at`.

Toute erreur (réseau, statut, plafond, structure, CRC, échéance, bail perdu,
disque) rend le bail : la génération en cours reste vide ou partielle,
orpheline, purgée au chargement suivant ; la base précédente reste en
service ; `last_error` est assaini (500 caractères). Disque : espace libre
(`statvfs`, `f_bavail × f_frsize`) contrôlé avant d'écrire le dump (taille
annoncée ou plafond compressé, plus 1 Gio de réserve), puis après lecture du
répertoire central (somme des tailles déclarées, plus 1 Gio) ; sans contrôle
sous Windows.

### Constat `vulns-sync`

Évalué par `tick` à chaque passage, pas par la synchronisation : un timer
cassé ou jamais installé se voit. Pour chaque source déclarée, âge = maintenant
− dernière réussite (`loaded`, `unchanged`, `not_modified`), ou, jamais
réussie, depuis le premier passage qui l'a vue déclarée (`meta
vulns.declared.<source>`, supprimée quand elle ne l'est plus). Au-delà de
3 jours : avertissement `_veilleur/vulns-sync/<source>`, sur le pseudo-site
réservé `_veilleur` (hors de la grammaire des identifiants de site), déclaré
au registre des capacités (`Control::VulnsSync`, jamais surveillé pour un
site). Clos « rétabli » au premier passage après une réussite, « plus
surveillé » quand la source est retirée de `[vulns] sources`. Une lecture de
l'état en échec ne réconcilie rien. E-mails propres au veilleur (« [vigie]
veilleur : base de failles osv-npm non synchronisée »), avec la commande à
lancer. L'incident est lisible et acquittable par `/api/v1/incidents/{id}`,
absent des vues par site jusqu'à la vue « veilleur » de F7 (#21).

### Mise à jour incrémentale : évaluée, écartée

`modified_id.csv` n'est lu par personne. Le stockage de F1 remplace une
source par génération entière : appliquer des deltas exigerait de copier la
génération active ou d'écrire dans l'active, ce que le bail et le
compare-and-swap interdisent. Le CSV ne dit pas les suppressions et n'est pas
strictement trié (désordre ligne 765 sur npm, 2026-10-17). Mesure : 38
failles npm modifiées en 24 h, 247 en 7 jours, 1 784 en 30 jours ; le dump
complet coûte ≈ 218 Mo par jour (≈ 6,4 Gio par mois). À revoir si la durée
npm relevée sur le VPS dépasse 30 min.

### Licences et volumes

Licence et attribution par enregistrement, d'après le préfixe de son
identifiant ([Licences et attribution](#licences-et-attribution)) ;
`vuln_sources` porte « OSV.dev, licence de chaque enregistrement selon son
préfixe ». Volumes au 2026-10-17 : crates.io 2 940 entrées, Packagist 7 303,
npm 230 382 (dont 222 536 `MAL-`, 7 844 GHSA, 1 EEF, 1 GSD, ce dernier de
licence inconnue, gardé). Les zips des tests sont construits par le test
depuis les fixtures de F1 (`NOTICE`) et des failles fictives ; aucun zip
hostile n'est commité.

## Priorisation (F4)

Issue #18, plan `aidd_docs/tasks/2026_10/2026_10_17_priorisation-failles/`.
Code : `src/vulns/exploit.rs` (CVE, faits KEV et EPSS, `parse_ppm`, trait
`Exploitation`, `MemoryTables`), `src/vulns/severity.rs` (règle de gravité),
`src/vulns/enrich_store.rs` (stockage, `StoreTables`),
`src/vulns/sync/enrichment.rs` et `src/vulns/sources/{kev,epss}.rs`.

KEV et EPSS ne détectent rien : ce sont des tables jointes par CVE aux
alias des failles (identifiant s'il est un CVE, puis alias CVE normalisés
par F1, grammaire du schéma KEV ; un alias hors grammaire n'entre dans
aucune jointure ; une faille sans CVE n'a ni KEV ni EPSS).

- **Déclaration d'office** : dès qu'une source de failles est dans
  `[vulns] sources`, `kev` et `epss` sont déclarés d'office (les écrire est
  admis, sans doublon) ; `kev` ou `epss` sans source de failles : erreur de
  configuration (code 2). Retirés avec la dernière source de failles, leurs
  constats sont clos « plus surveillé ».
- **Ordre** : sources de failles, puis `kev`, puis `epss`
  (`registry::KNOWN`). Une issue `loaded` de KEV ou d'EPSS, comme celle
  d'une source de failles, demande le rapprochement de F7
  (`SyncReport::loaded`).
- **Même cadre que F2** : trait `EnrichmentSource`, voisin de `VulnSource`,
  même moteur, même bail (plafond de durée + 30 min, pris avant toute
  requête), même débit (`claim_request`, un seul par synchronisation même
  si KEV fait deux requêtes ; `min_interval` 0 ; `Retry-After` honoré),
  même `Download`, même état, mêmes issues, même constat
  `vulns-sync/<source>` à 3 jours.
- **Tables** (migration `0019.sql`) : `vuln_kev` et `vuln_epss` en
  `WITHOUT ROWID`, clé `(generation, cve)` (pas de second index) ;
  `vuln_dataset` garde une fois par génération la version et la date du
  jeu (KEV : `catalogVersion`, `dateReleased` complet en UTC ; EPSS :
  `model_version`, `score_date` à minuit UTC), écrite dans la transaction de
  la bascule. Écart à l'issue (`model_date` par ligne) : pas 300 000 copies
  de la même date.
- **Générations** : comme F1, sous bail, par lots IMMEDIATE de 5 000 lignes
  (bail revérifié dans chacun ; lot le plus lent ≈ 60 ms en debug pour
  400 000 lignes EPSS face à `serve` et `tick`), bascule en compare-and-swap,
  purge par lots selon la forme de la clé (`GenerationCve` : génération
  orpheline trouvée par la clé, sans parcourir l'active), puis
  `PRAGMA wal_checkpoint(PASSIVE)`. Un lecteur voit l'ancien jeu complet ou
  le nouveau. Table fantôme puis `RENAME` et `DELETE` + 300 000 `INSERT` en
  une transaction : rejetés.
- **`validator_url`** : URL demandée qui a servi l'ETag ou le
  `Last-Modified` gardés, écrite avec eux dans l'instruction unique de la
  bascule ou de `finish_unchanged` ; une requête n'est conditionnelle que si
  `LOADER_VERSION` concorde **et** si son URL est celle-là (un ETag du miroir
  n'a pas de sens pour cisa.gov). Une réponse servie par une autre URL
  remplace l'ETag et `validator_url`, ou les efface. La migration remplit
  `validator_url` avec l'URL de la source là où un validateur existait (OSV).
- **Ordre des contrôles avant la bascule** : (1) seuil d'écart de F2, 1 %
  (numérateur : `bad_cve`, `bad_date`, `bad_value`, `missing_field`,
  `duplicate` ; `unknown_ransomware` et `count_mismatch` comptés sans être
  des écarts ; dénominateur : entrées ou lignes lues) ; (2) KEV seulement :
  régression de `dateReleased` ; (3) garde de F2 contre le rétrécissement
  (80 % du maximum des 7 derniers chargements, dès 100 lignes, fonction
  `shrink_refused`) ; (4) bascule. KEV est contrôlé en mémoire avant toute
  poussée ; EPSS est poussé en flux, contrôlé à la fin, la génération
  abandonnée sur refus.
- **Secours KEV** : miroir, puis cisa.gov quand le miroir échoue (réseau,
  statut, 429 compris, plafond, format, seuil d'écart) ou est refusé
  (régression, rétrécissement : KEV appelle `shrink_refused` sur les mêmes
  valeurs que le moteur, seulement pour décider d'essayer l'autre hôte) ;
  le premier jeu accepté est poussé. Les deux refusés : l'issue la plus
  sévère, échec (dernière erreur ; deux 429 avec `Retry-After` donnent
  `rate_limited` et `retry_after_until`, comme pour OSV), puis
  `refused_shrink` (écrit une fois, `recent_entries` inchangé), puis
  « inchangé (périmé) ». Un 304 ou une même empreinte sur l'un des hôtes :
  inchangé.
- **Âge du catalogue KEV** : `vigie vulns sources` affiche `maintenant −
  dateReleased` et « avertissement : catalogue KEV de plus de 14 jours »
  au-delà (CISA publie les jours ouvrés), même quand chaque synchronisation
  réussit (304, miroir périmé). Affichage seulement : le constat reste
  `vulns-sync/kev` à 3 jours sans succès.
- **Lecture pour F7** : `StoreTables::open(&store)`, sur une connexion de
  lecture (`Store::open_read`, `query_only`) ou celle de l'écrivain ; KEV
  actif entier en mémoire (20 000 lignes au plus) et état des deux jeux lus
  dans une même transaction de lecture ; EPSS par CVE, joint sur la
  génération active (`EpssFact::generation` rempli), en cache le temps d'un
  passage. Une table jamais chargée ne lève aucune gravité ; l'état
  (`TablesState`) est porté par chaque évaluation.
- **Attribution** : KEV `CC0-1.0`, « CISA KEV » sans logo ; EPSS « FIRST
  EPSS Usage Agreement », « See EPSS at https://www.first.org/epss » ;
  imprimées par `vigie vulns sources` et `show`.

## Gravité

Règle codée dans un seul module, `src/vulns/severity.rs`, fonctions pures
utilisées telles quelles par F7 : `assess` (une faille), `assess_group`
(failles d'une même faille fusionnées par alias), `assess_unknown`
(« version inconnue » ou « plage inconnue »). Seuils en constantes, pas en
configuration : `CVSS_CRITICAL_TENTHS` = 90, `CVSS_WARNING_TENTHS` = 70,
`EPSS_WARNING_PPM` = 100 000 ; changer un seuil est une décision écrite dans
`decisions.md`.

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

Règles nommées, lues de haut en bas (`Rule`) : `kev` (un CVE dans KEV,
critique), `malicious` (`MAL-`, critique), `cvss_critical` (≥ 9,0,
critique), `cvss_high` (≥ 7,0, avertissement), `epss` (≥ 0,1,
avertissement), `unknown_severity` (aucun score, non `informational`,
avertissement), `informational` (aucun score, `informational`,
information), `default` (information). Plusieurs CVE : KEV si l'un y est
(`dateAdded` le plus ancien retenu, rançongiciel si l'un l'est), EPSS le plus
haut. **Groupe fusionné** (F7) : KEV et EPSS cherchés sur l'union
dédoublonnée des CVE du groupe ; chaque membre évalué avec ses propres
`malicious`, score et `informational` et ces faits communs ; gravité =
maximum ; règle, score et identifiant = ceux du premier membre reçu qui
l'atteint ; « aucun correctif » si aucun membre n'en a. Un avis Wordfence
sans CVE et la GHSA de la même faille, dont le CVE est dans KEV, sont la
même faille exploitée. **Inconnues** : avertissement sur une faille
critique, information sinon ; F7 prend le maximum par composant. Écart à
l'issue #18, qui proposait « CVSS ≥ 9 et correctif disponible →
avertissement » : la règle de F0 fait foi.

## Dérogations

- Par site, composant et faille, jamais globales ; motif obligatoire.
- Expiration à 90 jours au plus. Ce plafond vaut pour les failles des sites ;
  le contrôle des dépendances de Vigie (F8, CI) a sa propre règle de 92 jours.
- Liée à la version du composant : une autre version la rend caduque.
- Inscrite dans l'audit.
- Interdite pour une faille dont un CVE est dans KEV.
- **Mise en œuvre (#21)** : `vigie site vulns-ack <site> <purl> <faille>
  [--source agent|ci]… --reason <motif> --until <AAAA-MM-JJ>`, aperçu puis
  `--apply` ; retrait par `--revoke <id> --reason <motif>`. Une dérogation
  vaut pour **une source d'inventaire et la version qu'elle voit** (deux
  sources : deux dérogations, `--source` répété, obligatoire si le site en
  déclare deux) ; faille saisie par identifiant ou alias, normalisé ;
  `covered_ids` = tous les identifiants et alias du groupe à la saisie.
  Caduque (« groupe changé ») dès qu'un identifiant **ou un alias** hors de
  cet ensemble rejoint le groupe — un simple alias nouveau publié par une
  source suffit, la dérogation est à ressaisir —, quand la version de la
  source change, quand un CVE du groupe entre dans KEV, et à son échéance.
  Refusée pour une version inconnue (l'avertissement « version inconnue » sur
  une faille critique ne peut qu'être acquitté par `vigie ack`), une faille
  qui ne touche pas le composant, un composant absent du dernier inventaire
  de la source, sans `[commands]`. Échéance et motif contrôlés avant toute
  lecture de la base ; tout refus en code 2.
- **Effet** : le groupe sort du calcul de gravité, listé « sous dérogation
  jusqu'au … » ; s'il ne reste rien d'autre, l'incident reste **ouvert en
  information** (aucune clôture « rétabli ») ; à l'échéance, la gravité
  remonte et l'e-mail d'ouverture repart sur le même incident.
- **Audit par empreinte** : chaque saisie et chaque retrait sont inscrits,
  dans la même transaction, dans la chaîne d'audit signée du site
  (`vuln-waived`, `vuln-waiver-revoked`) ; `detail` = `{ purl, advisory,
  until, operator, reason_sha256 }`, jamais le texte du motif, qui ne vit que
  dans `vuln_waivers`, purgée par `site remove`.
- Distincte de la **correction de plage** : pour une plage libre de
  Friends-Of-Presta non reconnue, l'exploitant peut saisir sur le VPS la plage
  machine équivalente. Cette correction est auditée et vaut pour tous les
  sites, mais ne masque rien : elle remplace « plage inconnue » par une plage
  évaluée.

**Corrections de plage (#17).** `vigie vulns correct <id> <purl> --range
<expr> --reason <motif>` (ou `--clear`) ; `vigie vulns corrections
[--audit [--verify]]`.

- Table `vuln_range_corrections` (migration `0018.sql`) **en ajout seul**
  (déclencheurs) ; la ligne la plus récente d'une clé `(source, advisory_id,
  purl)` fait foi, `ranges` NULL vaut retrait ; motif de 1 à 500 caractères,
  assaini ; opérateur = nom du compte (`getpwuid(geteuid())`, jamais
  `$USER`) ; date.
- Source `friends-of-presta` seulement, ligne existante et `unevaluable` ;
  expression dans la grammaire fermée ci-dessus, **sans** remarque entre
  parenthèses ; refusée sans `[commands]` (pas de clé d'audit). Tout refus
  sort en code 2. Une correction orpheline peut être retirée.
- Chaque saisie et chaque retrait sont inscrits, dans la même transaction,
  dans la chaîne d'audit signée du pseudo-site réservé `_veilleur`
  (évènements `range-corrected`, `range-correction-cleared`) ; `tick` en
  envoie la tête par e-mail comme pour un site. `--verify` contrôle la
  chaîne et la correspondance dans les deux sens (chaque ligne a son entrée
  au contenu égal, chaque entrée `range-*` a sa ligne) : tout écart, code 1.
- Appliquée **à la lecture** (`candidates`) : seule une ligne `unevaluable`
  de Friends-Of-Presta prend la plage corrigée, sans attendre la
  synchronisation, et survit aux nouvelles générations ; `Candidate.corrected`
  le dit, `match` et `show` affichent « plage corrigée » et le motif. États :
  `active` ; `sans objet` (la source est devenue lisible : sa plage prime) ;
  `orpheline` (faille ou purl disparu : sans effet) ; `illisible` (`ranges`
  cassé en base : la ligne reste « plage inconnue ») ; `retirée`.
- `corrections::latest_range_correction_id()` rend le plus grand `id`
  (`None` si la table est vide), en lecture seule sur `Store::open_read` :
  l'« époque » des corrections pour F7 (#21).

## Contrôle `vulns`

- Déclaré dans le registre de capacités (#4) : `Control::Vulns`, nom
  `vulns`, dernier de `Control::ALL` (15), tous les CMS, condition
  `Needs::InventorySource`.
- Surveillé si le site déclare une source d'inventaire dans `[sites.inventory]`
  (`capability::inventory_sources` non vide) : `agent-php` (agent PHP avec
  inventaire, runtime `php`) ou `ci` (`vigie-inventory`, #20, tout runtime).
  Les sites `node` et `static` sont donc couverts par la source `ci`. La clé
  d'inventaire n'entre pas dans la condition : elle n'est admise que pour un
  site qui déclare `ci`. Section retirée : `close_unwatched` clôt les
  incidents `vulns` « plus surveillé ». **Écart à l'issue #21** (« surveillé
  si un inventaire reçu depuis moins de 7 jours ») : F0 fait foi, l'absence
  d'inventaire devient « inventaire périmé », jamais une perte de
  surveillance.
- Péremption **par source** (`inventory::stale_after`) : sans inventaire
  `agent` depuis plus de 7 jours, ou sans inventaire `ci` depuis plus de
  35 jours (le job planifié hebdomadaire de la CI le renvoie), constat
  d'avertissement « inventaire périmé ». Le contrôle reste surveillé : jamais
  de perte de surveillance en silence.
- **Règles pour F7 (#21)** : un inventaire `ci`, même complet, ne clôt jamais
  un constat vu sur l'inventaire `agent` : il décrit ce qui va être déployé,
  pas ce qui tourne (un déploiement raté laisse l'ancien code). L'absence d'un
  composant se juge par source : seul un inventaire `complete` d'une source
  vaut absence pour cette source. F7 dit d'où vient chaque composant.
- Dépendances hors registre (git, `file:`, archive, chemin, autre registre ;
  Composer sans `notification-url` hors WPackagist) : comptées dans `skipped`
  par l'agent comme par l'outil, donc inventaire incomplet.
- Sources consultées : Wordfence pour un site `wordpress`, Friends-Of-Presta
  pour un site `prestashop`, OSV pour tout composant `composer`, `npm` ou
  `cargo`, quel que soit le site.
- Conservation : dernier inventaire et 30 jours d'historique ; détail **et
  clé** des incidents `vulns` masqués 30 jours après leur clôture
  (`<site>/vulns/masque-<id>` : la clé nomme un composant du client), détail
  du dernier passage `vulns` d'un site masqué de même ; résultats d'un site
  retiré de la configuration ou sans source d'inventaire supprimés au passage
  suivant ; `site remove` purge inventaires, résultats, provenance,
  dérogations (motifs compris) et passages `vulns`, sans toucher aux
  incidents.

## Rapprochement (F7)

Issue #21 ; plan `aidd_docs/tasks/2026_10/2026_10_17_rapprochement-failles/`.
Code : `src/vulns/matching/` (`group`, `assess`, `waiver`, `finding` purs ;
`epoch`, `store`, `pass` pour `tick` ; `waiver_store`, `report` pour la CLI) ;
migration `0021.sql` (`SCHEMA_VULNS_MATCH`).

**Déclenchement par état comparé, dans `tick` seul.** « À la réception d'un
inventaire » et « après chaque synchronisation » s'entendent au passage de
`tick` qui suit (une minute au plus) ; `serve` et `vulns sync` ne
rapprochent jamais. Pour chaque (site, source d'inventaire), `tick` compare
l'état gardé (`vuln_match_state`) à l'état courant : dernier inventaire et
son `seen_at` ; `match_epoch` = SHA-256 des générations actives des sources
de failles **déclarées** et du dernier id des corrections de plage ;
`enrich_epoch` = générations de `kev` et `epss` ; `waiver_epoch` du site =
`(max(id), max(revoked_at), count(*), count(revoked_at))` ; sources
d'inventaire déclarées ; échéances gardées (péremption, fin de report, perte
de vue, dérogation). Ce qui est refait : inventaire ou `match_epoch` changés
→ rapprochement de la source, plages relues, dans un run neuf ;
`enrich_epoch` seule → **réévaluation** de la gravité sur les faits gardés,
dans un run neuf, sans relire une plage ; le reste → constats seuls. Dans
tous les cas les constats du site sont reconstruits en entier depuis les runs
de toutes ses sources, puis passés à **une** réconciliation.

**Budget.** Échéance `min(maintenant + 10 s, start + send_budget −
send_reserve)` (`vulns_budget` et `send_reserve` à 10 s), vérifiée entre deux
lots ; un lot obligatoire par passage, sauf après `start + send_budget −
send_reserve / 2` ; l'analyse de logs s'arrête elle aussi à `start +
send_budget − send_reserve`. Sites à tour de rôle, le plus anciennement dû
d'abord, ceux en erreur en dernier ; un run commencé reprend au `rowid`
suivant de l'inventaire. Mesure en release (`tests/vulns_match_budget.rs`,
200 sites × 2 000 composants, 20 000 failles fictives) : tout couvert en
13 passages, lot le plus long 0,61 s, bascule la plus longue 24 ms.

**Erreurs isolées.** Chaque site dans son propre `Result` : une erreur (ligne
illisible, JSON corrompu, faille candidate illisible) est journalisée,
comptée (`error_count`, `vigie status` : « rapprochement en échec depuis N
passages »), le passage continue et les e-mails partent ; l'époque des
failles du site est oubliée, le passage suivant reprend au début dans un run
neuf. L'étape ne propage jamais d'erreur à `tick`.

**Runs, comme les générations de F1.** Id dans une séquence globale
(`vuln_match_runs`), lots IMMEDIATE de 500 composants avec compare-and-swap
du curseur (deux `tick` concurrents n'écrivent jamais deux fois une
position) ; constats construits **hors transaction**, puis une transaction
IMMEDIATE revérifie ce qui a été lu (runs actifs et en cours, époques des
failles et des dérogations, incidents ouverts : tout écart, rien n'est écrit,
le site reste dû), bascule le run en compare-and-swap, clôt d'abord « plus
surveillé » ce qui ne tenait qu'à une source retirée ou à un report échu,
puis appelle `reconcile_in` ; l'ancien run est purgé ensuite par lots. Un
lecteur (API, CLI) ne lit que l'`active_run` de chaque source. Cache des
candidates d'un passage borné en poids (50 000 lignes et `versions[]`).

**Deux sources, une union.** Un composant a pour identité (source, purl
sans version, chemin) ; les composants d'un site sont l'union des derniers
inventaires de chaque source déclarée ; seuls les écosystèmes admis pour le
CMS du site (`inventory_ecosystems`) et les candidates des sources de failles
déclarées comptent. L'absence d'un composant ne se juge que dans un
inventaire **complet de la même source**. Un composant absent d'un relevé
**partiel** de sa source est reporté, rapproché sur sa dernière version
connue, « absent d'un relevé partiel », tant que sa dernière vue a moins de
`inventory::stale_after(source)` (7 jours `agent`, 35 jours `ci`).

**Fusion et verdict.** Les candidates d'un purl qui partagent un identifiant
ou un alias normalisé forment un groupe (union-find, fermeture transitive),
clé = plus petit CVE, sinon plus petit identifiant. Verdict : touché si un
membre l'est (correctif = le plus grand des plus petits correctifs s'ils se
comparent, sinon tous), sinon inconnu avec « plage inconnue » prioritaire sur
« version inconnue », sinon non touché. Gravité par la seule règle de F4
(`assess_group`, `assess_unknown`, [Gravité](#gravité)) ; niveau de
redistribution = le plus restrictif des sources du groupe (inconnue :
interne), affiché, jamais utilisé pour cacher une faille à l'exploitant.

**Un constat par (site, purl sans version)**, agrégé sur toutes les sources,
tous les chemins et toutes les failles : clé = purl canonique sans version
tel qu'indexé (jamais la version, le chemin ni un nom propre au site) ;
constats de péremption `inventaire-perime-agent`, `inventaire-perime-ci`.
**Seuils** : ouvert à l'avertissement ou au-dessus (une faille d'information
seule n'ouvre rien : elle reste visible dans `vigie site vulns --all`, l'API
et la console), ou tenu ouvert par une dérogation ; un incident ouvert reste
ouvert, en information s'il le faut, tant qu'un groupe touché ou inconnu
subsiste (pas de battement EPSS 0,09 → 0,11 → 0,09). Gravité = maximum hors
dérogation ; une faille entrée dans KEV fait monter le même incident, et
l'e-mail d'ouverture repart. **Détail** écrit par Vigie, assaini champ par
champ, 4 096 caractères au plus : première ligne de 200 caractères au plus
(objet de l'e-mail : purl, version vue par chaque source « agent : 1.2.3 ;
ci : 1.2.4 », nombre de failles et de critiques, « corriger : ≥ v » ou
« aucun correctif »), une ligne par groupe du plus grave au moins grave
(identifiants, état, gravité et règle, CVSS, KEV, EPSS, correctif, liens),
« + K autres : vigie site vulns <site> », mention « usage interne » d'un
groupe non libre, attributions dédoublonnées et jamais tronquées (les groupes
cèdent la place). Aucun résumé ni titre de source.

**Clôture : « rétabli » seulement sur preuve.** Un incident est clos
« rétabli » quand tous les groupes de toutes les vues qui voient le composant
sont non touchés (version corrigée), ou quand chaque **source requise** a
fourni, après sa dernière vue, un inventaire complet sans lui. Sources
requises = sources qui l'ont vu (provenance `vuln_match_seen`, gardée pour les
seuls purl à faille candidate) ∩ sources encore déclarées ∩ sources qui
peuvent porter l'écosystème (`source_carries` : `ci` ne porte jamais
`wordpress` ni `prestashop`, l'agent jamais `cargo`) ; provenance perdue
(`site remove`) : toutes les sources déclarées qui le peuvent, comptées
depuis `lost_view_at` (date du retrait). Sinon l'incident est gardé tel quel
(même clé, gravité, détail), puis clos « **plus surveillé** », jamais
« rétabli », quand une source requise manquante atteint
`inventory::stale_after` depuis sa dernière vue. Même règle pour une source
d'inventaire retirée de `[sites.inventory]` (état et run supprimés,
constats qu'elle seule voyait clos « plus surveillé ») et pour une source de
failles retirée de `[vulns]` (constat dont tous les groupes ne tenaient qu'à
elle).

**Inventaire périmé.** Sans inventaire d'une source depuis plus de
`stale_after(source)`, compté depuis le plus tardif du dernier inventaire et
de la déclaration de la source (méta `vulns.inventory.declared.<site>.<source>`
écrite au premier passage qui la voit) : avertissement
`inventaire-perime-<source>` ; les constats de composants restent, rapprochés
sur le dernier inventaire. Un renvoi inchangé le clôt.

**E-mails.** Objet d'un incident `vulns` = première ligne du détail ; corps
avec `vigie site vulns <site>`. Ce qui est **en attente pour un site** —
ouvertures (gravités montées et KEV comprises), rappels, clôtures — au-delà de
cinq part en **un seul e-mail** groupé (comptes par gravité, les dix plus
graves, rétablis et plus surveillés séparés), puis tous sont marqués dans une
transaction ; cinq ou moins, un e-mail par incident. Envoi raté : rien n'est
marqué, l'e-mail groupé repart. Marquage raté après un envoi réussi : il peut
partir une seconde fois (doublon accepté).

**Lectures.** CLI : `vigie site components`, `vigie site vulns [--all]`,
`vigie vulns report` (document interne), ligne « failles » de `vigie status`.
API : `/api/v1/sites/{id}/components`, `/sites/{id}/vulns`, `/vulns/sources`
([`api-console.md`](./api-console.md)). Console : écrans « Failles » et
« Sources de failles », sans action d'écriture.

### Limites connues (F7)

- Slug homonyme : une extension privée qui porte le slug d'une extension
  publique reçoit ses failles ; `wpackagist` sur un site `generic`
  (`Conventions purl`) ; une fusion par alias erronée dans une source affiche
  deux failles comme une (membres listés, gravité maximale). Parade : une
  dérogation par source et version.
- Rapprochement au passage de `tick` qui suit : jusqu'à une minute après un
  inventaire ou une synchronisation, plusieurs passages pour un premier
  rapprochement de nombreux sites.
- Vue `ci` en retard sur `agent` : un composant corrigé sur le serveur (vu par
  l'agent) reste signalé par la vue `ci` tant que la CI ne repousse pas
  d'inventaire, jusqu'à 35 jours ; le détail dit quelle source voit quelle
  version.
- E-mail groupé en double si son marquage échoue après l'envoi ; un groupe
  redescendu de six à cinq en attente donne cinq e-mails.
- Une dérogation vaut pour une source ; un nouvel alias publié la rend
  caduque (à ressaisir).
- `/components` sert à la console appairée **tous** les composants
  rapprochés d'un site, failles ou non, sans chemin ni nom brut.

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

1. Joignabilité de chaque hôte de la liste ci-dessus ; pour
   `osv-vulnerabilities.storage.googleapis.com`, cochée par le relevé de la
   première synchronisation réelle (`hebergement.md`, « Synchronisation des
   failles ») : **non fait au 2026-10-17**.
2. Wordfence : relire https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/
   et https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/ ;
   forme exacte de l'en-tête (`Bearer <jeton>` ?), conditions propres au jeton
   « Integrations », ETag ou Last-Modified, compression gzip, format v3
   identique au v2 sur un vrai téléchargement, texte réel de `copyrights`,
   affichage permis ou non aux clients d'un prestataire. Consigner le résultat,
   daté, dans la section Wordfence.
3. EPSS : URL finale après redirection, en-têtes (ETag, Last-Modified,
   **présence ou non de `Content-Encoding: gzip`** sur la réponse ; absent,
   `raw_content_encodings` d'EPSS est vidé et la décision consignée), poids
   du fichier, conditions sur https://www.first.org/epss/#Usage-Agreement.
   **À relever** (exploitant) : `vigie vulns sync --source epss` deux fois
   (le second : 304 ou empreinte inchangée), relevé masqué dans
   `hebergement.md`. Puis **grammaire EPSS à figer** : forme réelle des
   nombres, de `score_date` et des fins de ligne consignée ici, parseur et
   fixtures resserrés à ce qui est observé (tolérances gardées), plafonds
   ajustés si le poids réel les approche à moins d'un facteur 2.
4. cisa.gov : ETag et 304 sur l'URL canonique ; catalogue réel lu par
   `vigie vulns sync --source kev` deux fois (miroir puis 304). **À
   relever** (exploitant).
5. Friends-Of-Presta : archive `main.tar.gz` joignable, ETag, taille, nombre
   d'avis et date du dernier commit.
6. GitHub Advisory Database : texte d'attribution exact sur la page
   docs.github.com citée plus haut.
7. Packagist : état de l'issue google/osv.dev n° 230 (ordre des versions).
