# API de la console, version 1

La console (application Windows et Android) lit l'état du veilleur par
`/api/v1`. Chaque installation de la console est un **appareil** : elle reçoit
un jeton qui lui est propre, une seule fois, en échange d'un code d'appairage
créé sur le VPS. Le veilleur ne garde que l'empreinte SHA-256 des jetons et
des codes : ni l'un ni l'autre n'est écrit en clair, en base comme au journal.

Ce document est le contrat. `vigie/src/device.rs`, `vigie/src/api.rs`,
`vigie/tests/api_auth.rs`, `vigie/tests/api_read.rs`,
`vigie/tests/api_guards.rs` et `vigie/tests/cli.rs` en reprennent chaque règle.

## Configuration

```toml
[api]
public_url = "https://veilleur.example.org"
```

`public_url` est l'adresse publique du veilleur, telle que la console
l'appelle. Elle doit être en https ; http n'est admis que sur la boucle locale
(`127.0.0.1`, `::1`, `localhost`), pour les essais. Sans section `[api]`,
`vigie device pair` est refusé ; les routes `/api/v1` restent montées.

## Appairage

Sur le VPS, en SSH :

```console
$ vigie device pair --name téléphone
<QR code>

vigie://pair?u=https%3A%2F%2Fveilleur.example.org&c=<code>

appairage de « téléphone » : à scanner ou à coller dans la console avant 2026-10-16T14:10:00Z (10 min), une seule fois
```

- **Code** : 16 octets tirés par `getrandom`, en base64url sans remplissage
  (22 caractères). Valable 10 minutes, utilisable une seule fois.
- **Lien** : `vigie://pair?u=<public_url>&c=<code>`, paramètres encodés en
  `application/x-www-form-urlencoded`. Le QR code et la ligne de texte portent
  exactement le même lien : collé tel quel sous Windows, il donne à la fois
  l'adresse du veilleur et le code.
- **QR code** : caractères Unicode, deux modules par caractère (`▀ ▄ █` et
  espace), zone de silence comprise. Les modules clairs sont pleins : il est
  prévu pour un terminal à **fond sombre**. Sur un fond clair, il apparaît
  inversé et la plupart des lecteurs le refusent ; coller alors le lien.
- **Nom** : celui de `--name`, 64 caractères au plus, sans caractère de
  contrôle. La console n'en choisit pas : le code seul suffit.

La console envoie ensuite le code :

```http
POST /api/v1/pair HTTP/1.1
Content-Type: application/json

{"code":"<code>"}
```

Corps de 1 Ko au plus, reçu en entier en 10 s au plus. Réponse :

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"token":"<jeton>","device_id":1,"name":"téléphone"}
```

- **Jeton** : 32 octets tirés par `getrandom`, en base64url sans remplissage
  (43 caractères). Il n'est remis qu'ici : perdu, il faut appairer de nouveau.
- La consommation du code et la création de l'appareil se font dans une même
  transaction : deux requêtes simultanées avec le même code donnent un seul
  appareil.

## Authentification

Toute autre route de `/api/v1` exige :

```http
Authorization: Bearer <jeton>
```

Le veilleur hache le jeton présenté et cherche un appareil **actif** de même
empreinte (comparaison en temps constant). Un jeton de plus de 128 caractères
est refusé sans être haché. L'appareil trouvé passe ensuite la limite de débit
(voir [Limite de débit](#limite-de-débit)) ; sous la limite, sa date « vu le »
est mise à jour au plus une fois par minute ; son échec n'est que journalisé,
la requête passe.

Pas de certificat client (mTLS) : `serve` écoute sur `127.0.0.1:8080`, Caddy
l'expose en TLS, et le jeton d'appareil (32 octets aléatoires, gardé en
SHA-256, révocable un par un) authentifie chaque appel (`decisions.md`,
section #5).

## Révocation

```console
$ vigie device list
appareils : 1
  #1  téléphone  actif, vu il y a 2 min  (appairé le 2026-10-16T14:02:11Z)
$ vigie device revoke 1
appareil 1 révoqué : son jeton est refusé dès maintenant
```

La révocation prend effet à la requête suivante : aucun cache de jeton.
`device list` montre aussi les codes en attente, par nom et date d'expiration,
jamais le code lui-même. Un appareil révoqué reste listé, avec sa date de
révocation.

## Routes

| Route | Réponse | Écrans |
| ----- | ------- | ------ |
| `POST /api/v1/pair` | `{token, device_id, name}` (voir Appairage) | appairage |
| `GET /api/v1/overview` | sites triés par état, avec leur constat le plus grave | Main, ATraiter, Etats |
| `GET /api/v1/sites/{id}` | incidents ouverts, contrôles et dernier relevé de l'agent | ATraiter, Dispo, Controles, Parametres, Etats |
| `GET /api/v1/sites/{id}/incidents` | incidents fermés depuis 30 jours, par pages | Dispo |
| `GET /api/v1/sites/{id}/logs` | dernier instantané de l'analyse des logs : robots, règles, charge | — |
| `GET /api/v1/sites/{id}/logs/ips` | verdicts d'IP moyens et élevés, par pages | — |
| `GET /api/v1/sites/{id}/errors` | erreurs du site sur 14 jours, groupées par message normalisé (#52) | Erreurs |
| `GET /api/v1/sites/{id}/components` | composants rapprochés des derniers inventaires (#21), par pages | Failles |
| `GET /api/v1/sites/{id}/vulns` | failles des composants, une par (composant, faille fusionnée), par pages | Failles |
| `GET /api/v1/vulns/sources` | sources de failles déclarées : âge, issue, attribution, constat `vulns-sync` | SourcesFailles |
| `GET /api/v1/incidents/{id}` | un incident, ouvert ou fermé | Alerte |
| `GET /api/v1/incidents/{id}/mails` | les e-mails déjà envoyés pour l'incident, recomposés (#53) | Alerte |
| `POST /api/v1/incidents/{id}/ack` | l'incident acquitté | Alerte |
| `POST /api/v1/incidents/{id}/snooze/{duration}` | l'incident, rappels en sourdine (`24h` ou `7d`) | Alerte |
| `GET /api/v1/settings` | sites, fréquences, destinataire masqué, appareils | Parametres, Reglages |
| `DELETE /api/v1/devices/self` | 204, sans corps | Reglages |

Toutes, sauf `pair`, exigent le jeton. Les heures sont des secondes Unix (UTC) ;
un champ sans valeur connue vaut `null`, jamais zéro ni une valeur par défaut.
Les tableaux ne sont jamais `null` : vides, ils valent `[]`.

### Pagination

Toute liste qui croît se lit par pages, par clé (jamais par rang) :

- `limit` : de 1 à 100, 50 par défaut ; hors de ces bornes ou illisible,
  400 `bad_request`.
- `cursor` : opaque (base64url), 256 caractères au plus avant décodage ;
  illisible, trop long, vide ou émis par une autre liste, 400 `bad_request`.
  Un paramètre répété est aussi un 400. Les autres paramètres sont ignorés.
- La réponse porte la page (`items`, ou `incidents` pour les incidents, voir
  plus bas) et `next_cursor`, le curseur de la page suivante, `null` sur la
  dernière. La page suivante se demande avec ce curseur et le même `limit`.

Le curseur porte la clé du dernier élément servi : une page lue plus tard
reprend juste après lui, sans doublon ni trou dû aux éléments arrivés
entre-temps. Exception : les listes du rapprochement (`components`, `vulns`,
#21) sont figées sur les runs actifs de chaque source, qui ne changent jamais
en place ; leur curseur porte ces runs et un rang (une clé citerait un
chemin du site). Un run basculé entre deux pages (nouveau rapprochement ou
réévaluation KEV et EPSS) rend 409 `cursor_expired` : le client reprend au
début, sans curseur. Les listes bornées par la configuration ne se paginent pas :
sites (200 au plus, `config.toml` en refuse davantage) et contrôles d'un site.

### Incident

Forme commune à toutes les routes qui renvoient un incident :

```json
{
  "id": 12,
  "key": "site-a/exposed/.env",
  "site": "site-a",
  "check": "exposed",
  "severity": "critical",
  "detail": "fichier exposé : /.env",
  "opened_at": 1792000000,
  "closed_at": null,
  "acked_at": null,
  "open_notified_at": 1792000060,
  "close_notified_at": null,
  "last_reminder_at": null,
  "snoozed_until": null,
  "state": "open"
}
```

- `severity` : `info`, `warning` ou `critical`. Un `info` n'est jamais envoyé
  par e-mail et ne compte pas dans l'état du site.
- `state` : `closed` si `closed_at` est posé, sinon `acked` si `acked_at` est
  posé, sinon `open`.
- `snoozed_until` : date (secondes Unix) avant laquelle aucun rappel n'est
  envoyé, `null` hors sourdine. La sourdine ne change pas `state`.
- `open_notified_at`, `last_reminder_at` et `close_notified_at` sont les dates
  d'envoi des e-mails d'ouverture, de dernier rappel et de rétablissement :
  ATraiter et Alerte en tirent les e-mails envoyés.

### `GET /api/v1/overview`

```json
{
  "server_time": 1792000000,
  "last_tick": 1791999970,
  "sites": [
    {
      "id": "site-a",
      "url": "https://site-a.example.org/",
      "kind": "wordpress",
      "runtime": "php",
      "state": "non_compliant",
      "open_count": 2,
      "worst": { "...": "un incident" },
      "last_read": 1791999940
    }
  ]
}
```

- `last_tick` : `null` tant qu'aucun tick n'a tourné.
- `kind` : `generic`, `wordpress` ou `prestashop` (le CMS, qui filtre les contrôles).
- `runtime` : `php`, `node`, `static` ou `null` ; runtime effectif, déclaré dans `config.toml` ou impliqué par le CMS (`php` pour `wordpress` et `prestashop`). Il filtre les commandes (`protocole-commandes.md`). Présent aussi dans `sites/{id}` et `settings`.
- `open_count` : avertissements et critiques ouverts.
- `worst` : le plus grave d'entre eux, le plus ancien à gravité égale ; `null`
  s'il n'y en a aucun.
- `last_read` : dernier passage d'un contrôle encore surveillé ou dernier
  rapport d'agent accepté, le plus récent des deux ; `null` si aucun.
- Les sites sont triés par état (voir État d'un site), puis dans l'ordre du
  fichier de configuration.

### `GET /api/v1/sites/{id}`

```json
{
  "id": "site-a",
  "url": "https://site-a.example.org/",
  "kind": "wordpress",
  "runtime": "php",
  "interval": 300,
  "agent_silence": 900,
  "state": "to_check",
  "last_read": 1791999940,
  "agent": {
    "declared_at": 1791000000,
    "last_report_at": 1791999940,
    "agent": "vigie-agent 1.0.0",
    "facts": { "...": "relevé de l'agent, tel qu'envoyé" }
  },
  "open_incidents": [ { "...": "un incident" } ],
  "checks": [
    {
      "name": "tls",
      "interval": 3600,
      "last_run": 1791999000,
      "result": "ok",
      "severity": null,
      "detail": null,
      "duration_ms": 212,
      "observed": { "tls_not_after": 1798912000 }
    }
  ]
}
```

- `agent` : `null` si aucun agent n'est déclaré. `last_report_at`, `agent` et
  `facts` valent `null` avant le premier rapport accepté.
- `open_incidents` : tous les incidents ouverts du site, y compris `info`, du
  plus grave au moins grave, puis du plus ancien.
- `checks` : les contrôles que le registre des capacités (`capability.rs`,
  issue #4) surveille pour ce site, dans son ordre : d'abord les contrôles
  externes applicables au type du site (`content`, `installer` hors
  `generic`, `exposed`, `tls`, `headers`, puis `custom` si le site déclare au
  moins une règle `[[sites.custom_checks]]`), puis, si un agent est déclaré sur
  un site au runtime effectif `php`, `heartbeat` ; enfin, dès leur premier
  passage, `agent:integrity` (référence posée), les familles `agent:*` admises
  pour le site, `logs` (site avec une source) et `typology` (clé d'agent sur
  un site sans runtime `php`). Le passage d'un contrôle que le registre ne
  surveille plus n'est pas montré.
  - `interval` : secondes entre deux passages. `tls` et `headers` passent au
    plus une fois par heure. `heartbeat` porte le silence d'agent toléré ;
    les autres valent `null`, ils suivent les rapports ou `tick`.
  - `last_run` : `null` si le contrôle n'a jamais tourné. Tous les champs
    suivants sont alors `null` aussi.
  - `result` : `ok` (concluant, sans constat), `finding` (concluant, avec au
    moins un constat) ou `error` (non concluant) ; `null` pour un passage
    enregistré avant le schéma 6.
  - `severity` et `detail` : le constat le plus grave d'un `finding`, ou la
    raison d'un `error` (dans `detail`, `severity` restant `null`).
  - `duration_ms` : durée du passage ; `null` pour les contrôles d'agent.
  - `observed` : valeurs mesurées, `null` si aucune. `http_status` pour
    `content`, `tls_not_after` (secondes Unix) pour `tls`, présent même sans
    alerte. Un contrôle sauté parce que le site est injoignable n'a pas de
    passage : il ne reçoit aucune valeur.
- Identifiant absent de la configuration : 404.

### `GET /api/v1/sites/{id}/incidents`

```json
{ "site": "site-a", "since": 1789408000, "incidents": [ { "...": "un incident" } ], "next_cursor": "aTF8…" }
```

Incidents du site fermés depuis `since` (maintenant moins 30 jours), du plus
récemment fermé au plus ancien (`closed_at`, puis `id` décroissants), par
pages (voir [Pagination](#pagination)) : `incidents` est la page,
`next_cursor` le curseur de la suivante. Les incidents ouverts sont dans
`GET /api/v1/sites/{id}`. Identifiant absent de la configuration : 404.

- Un incident fermé pendant un parcours se place avant la première page : il
  n'est pas revu par les pages suivantes, et aucun autre n'y manque. Un
  nouveau parcours le voit en tête.
- **Changement depuis la console 0.1.1** : sans paramètre, la réponse ne porte
  plus tous les incidents des 30 jours, mais la première page (les 50 derniers
  fermés). Le nom `incidents` est gardé pour que la console 0.1.1 continue de
  lire la réponse ; elle ignore `next_cursor` (son client n'a pas de
  `deny_unknown_fields`) et ne voit donc que ces 50 incidents.

### `GET /api/v1/sites/{id}/logs`

```json
{
  "analysis": {
    "generated_at": 1792000000,
    "reference_ms": 1791999940000,
    "bots": [
      { "name": "GPTBot", "publisher": "OpenAI", "purpose": "…", "robots_only": false,
        "honours_robots": true, "class": "ai_training", "protected": false, "requests": 120 }
    ],
    "scored": 81,
    "unscored": 0,
    "rules": [
      { "rule": "spike-404", "scope": "site", "severity": "warning", "window_secs": 300,
        "min_count": 100, "min_ips": 1, "count": 140, "distinct_ips": 12, "keys_over": 0,
        "exceeded": true }
    ],
    "load": [
      { "hour": 497777, "requests": 5120, "refused": 30, "timed": 5000, "service_us": 900000000,
        "facets": 800, "facets_us": 300000000, "bots": 400, "bots_us": 20000000 }
    ],
    "load_threshold_us": 1800000000
  }
}
```

Dernier instantané de l'analyse des logs du site (#8), écrit par `tick` :

- `generated_at` : heure du veilleur à l'écriture, en secondes ;
  `reference_ms` : heure de référence des fenêtres, en ms (heure des données).
- `bots` : robots du catalogue vus sur 24 h, du plus actif au moins actif,
  avec leurs métadonnées (`class`, `protected` : jamais visé par les actions
  robots.txt et UA de #13).
- `rules` : chaque règle sur sa fenêtre finie à la référence ; `exceeded`
  dit si elle est dépassée. Aucune IP.
- `load` : charge des 24 heures, par tranche horaire (`timestamp_ms / 3 600
  000`), temps de service en µs.
- `scored` et `unscored` : IP notées, et IP sans score fiable.

Site qui a une source de logs mais aucune analyse encore : 200
`{"analysis": null}`. Site sans source (`[sites.logs] source`) ou absent de
la configuration : 404.

### `GET /api/v1/sites/{id}/logs/ips`

```json
{
  "site": "site-a",
  "generated_at": 1792000000,
  "items": [
    { "ip": "192.0.2.10", "score": 85, "level": "eleve", "reasons": ["facets", "tool_user_agent"], "class": "tool" }
  ],
  "next_cursor": "djF8…"
}
```

Verdicts d'IP d'un instantané de l'analyse, du plus haut score au plus bas
(puis par IP), par pages (voir [Pagination](#pagination)). Données
personnelles en liste blanche : l'IP, le score (0 à 100), le niveau
(`moyen` ou `eleve`, jamais les autres), les raisons en codes, la classe du
premier robot vu (`browser` sans robot). Ni user-agent, ni chemin, ni le
libellé des raisons, qui peut citer l'un ou l'autre.

- `reasons` : `fake_search_engine`, `search_engine`, `declared_bot`,
  `facets`, `no_static_resources`, `no_referer`, `tool_user_agent`,
  `user_agent_rotation`, `burst`, `hosting_network`, `consumer_isp`,
  `no_reverse_dns`, `shared_signature` ; `other` pour une raison inconnue de
  ce binaire.
- Rien au-delà de 48 heures : seul un instantané de `generated_at` ≥
  maintenant moins 48 h est servi, même avant la purge de `tick`. Sinon,
  `generated_at` vaut `null` et `items` `[]`.
- La première page lit le dernier instantané ; le curseur le fixe : une page
  suivante le relit même après un nouveau `tick` (l'instantané précédent est
  gardé 15 minutes). Instantané purgé depuis, ou de plus de 48 h : 409
  `cursor_expired`, le client reprend au début, sans curseur.
- Site sans source de logs ou absent de la configuration : 404.

### `GET /api/v1/sites/{id}/errors`

```json
{
  "site": "site-a",
  "days": 14,
  "groups": [
    { "message": "Undefined array key #", "count": 16,
      "first_seen": 1792000000, "last_seen": 1792150000, "days_seen": 3 }
  ]
}
```

Erreurs du site reçues de l'agent PHP (`POST /r/v1/errors`, voir
`docs/protocole-agent.md`), sur les 14 derniers jours UTC (aujourd'hui
compris), fusionnées par empreinte du message normalisé : `count` est la somme
des jours, `first_seen` le plus ancien et `last_seen` le plus récent, `days_seen`
le nombre de jours où le groupe a été vu. Triées par `count` décroissant, puis
`last_seen` décroissant ; 50 groupes au plus, sans pagination. Le message est
déjà normalisé par l'agent et renormalisé par le veilleur (nombres en `#`,
UUID en `<uuid>`) : le `#` y est un chiffre masqué. Le texte reçoit
l'assainissement de `LogText` (200 caractères au plus).

- Site connu sans lot reçu : `groups` vaut `[]` (la console ne distingue pas
  « aucune erreur » de « agent muet » ici ; le silence de l'agent a son propre
  incident `heartbeat`).
- Site absent de la configuration : 404.
- Aucune adresse IP, aucun chemin, aucune requête n'est servi : le veilleur
  refuse à la réception tout lot qui en porte.

### `GET /api/v1/sites/{id}/components`

```json
{
  "site": "site-a",
  "runs": { "agent": 12, "ci": null },
  "items": [
    { "source": "agent", "purl": "pkg:wordpress/plugin/exemple-plugin", "version": "1.2.3",
      "scope": "required", "vulns": 1, "severity": "critical" }
  ],
  "next_cursor": "YzF8…"
}
```

Composants des derniers inventaires du site, rapprochés des failles connues
(#21), une ligne par (source, composant, chemin), triés par gravité puis
purl. `runs` : run actif de chaque source d'inventaire (`null` : aucun).
`version` à `null` si inconnue, `severity` à `null` sans faille. Ni
`vigie:path`, ni `name` CycloneDX brut. **Limite de minimisation** : la
console appairée reçoit **tous** les composants rapprochés du site, failles
ou non.

### `GET /api/v1/sites/{id}/vulns`

```json
{
  "site": "site-a",
  "runs": { "agent": 12, "ci": 13 },
  "items": [
    { "group": "CVE-2099-0002", "ids": ["CVE-2099-0002", "WF-2099-0002"],
      "component": "pkg:wordpress/plugin/exemple-plugin",
      "versions": [{ "source": "agent", "version": "1.2.3" }, { "source": "ci", "version": "1.2.4" }],
      "verdict": "affected", "corrected": false, "divergence": false, "fixed": ["1.2.4"],
      "severity": "critical", "rule": "kev",
      "kev": { "cve": "CVE-2099-0002", "date_added": "2099-01-10", "ransomware": false },
      "epss": { "score": 123456, "percentile": 900000 }, "score": 98,
      "redistribution": "internal",
      "waiver": { "source": "agent", "until": 4073500800, "state": "valid" },
      "links": [{ "source": "wordfence", "url": "https://example.org/avis/WF-2099-0002" }],
      "attributions": ["Copyright 2099 Exemple Intelligence SARL"] }
  ],
  "next_cursor": null
}
```

Failles des composants du site, une par (purl sans version, faille fusionnée
par alias), triées par gravité, purl puis faille ; chaque faille **embarque**
son composant et la version vue par chaque source. `verdict` :
`affected`, `version_unknown` ou `range_unknown` (jamais « aucune faille ») ;
`fixed` vide : aucun correctif ; `rule` : règle de F4 (`kev`, `malicious`,
`cvss_critical`, `cvss_high`, `epss`, `unknown_severity`, `informational`,
`default`) ou `version_unknown`, `range_unknown` ; `score` : CVSS en
dixièmes ; `epss` en millionièmes ; `redistribution` : `internal`,
`facts_only` ou `free` ; `waiver` : source, échéance et état (`valid`,
`expired`, `version_changed`, `group_changed`, `kev`), **jamais le motif ni
l'opérateur** ; `attributions` : entières, relues depuis la source de chaque
membre. Aucun résumé ni texte d'avis. Tout texte d'une source passe par
`LogText`.

Ces deux routes répondent 404, le même corps, pour un site inconnu, un site
sans `[sites.inventory]` (contrôle `vulns` non surveillé), un site jamais
rapproché (aucun run actif) et une base antérieure au schéma du
rapprochement.

### `GET /api/v1/vulns/sources`

```json
{
  "sources": [
    { "id": "kev", "kind": "enrichment", "last_success_at": 1792000000,
      "last_outcome": "loaded", "entries": 1400, "license": "…", "attribution": "…",
      "redistribution": "free", "dataset": { "version": "2099.01.15", "released": 1791900000 },
      "incident": null }
  ]
}
```

Une entrée par source de `[vulns] sources` (KEV et EPSS d'office dès qu'une
source de failles est déclarée), dans l'ordre du registre ; liste vide sans
`[vulns]`. `kind` : `vulns` ou `enrichment` ; `dataset` : jeu actif de KEV ou
d'EPSS ; `incident` : constat `vulns-sync` ouvert de la source (`id`,
`severity`, `opened_at`). Non paginé. Jamais chargée : `last_success_at` et
`dataset` à `null`. Ni erreur brute, ni URL de validateur, ni résumé.

Le détail d'un incident `vulns` (dans `overview`, `sites/{id}`,
`incidents/{id}`) est assaini ligne à ligne par `LogText`, ses sauts de ligne
gardés, 4 096 caractères au plus. Un incident `vulns` critique rend le site
`non_compliant`, comme tout incident critique ; un incident d'information ne
compte pas.

### `GET /api/v1/incidents/{id}`

L'incident, ouvert ou fermé. Identifiant inconnu ou non entier : 404.

### `GET /api/v1/incidents/{id}/mails`

Aperçu des e-mails que le veilleur **a envoyés** pour cet incident (#53) : un
par date de notification posée (`open_notified_at`, `last_reminder_at`,
`close_notified_at`), jamais un modèle générique.

```json
{ "mails": [ { "kind": "open", "sent_at": 1792000000, "subject": "…", "body": "…" } ] }
```

- `kind` : `open`, `reminder` ou `close` ; `sent_at` en secondes Unix.
- Le texte est **recomposé** par les mêmes fonctions que l'envoi, à partir de
  l'état actuel de l'incident : il peut différer d'un message parti il y a
  longtemps (par exemple le détail d'une relance, ou l'adresse du site si la
  configuration a changé). Le veilleur ne conserve pas les messages.
- Liste vide si aucun e-mail n'est parti, et pour les incidents du contrôle
  `vulns` : leurs e-mails sont groupés, sans correspondance avec un incident.
- Le détail est assaini comme les textes issus des logs.
- 404 si l'identifiant est inconnu ou non entier.

### `POST /api/v1/incidents/{id}/ack`

Même effet que `vigie ack <id>` : les rappels s'arrêtent, la clôture
automatique et son e-mail restent. La console envoie la requête sans corps ni
`Content-Type` ; un corps JSON est ignoré, un corps annoncé d'un autre type
reçoit 415 (voir [En-têtes](#en-têtes)).

- 200 et l'incident, `state` à `acked`. Sur un incident déjà acquitté, la même
  réponse, `acked_at` inchangé.
- 409 si l'incident est fermé : la base n'est pas modifiée.
- 404 si l'identifiant est inconnu.
- Le journal du veilleur note l'id de l'appareil qui a acquitté.

### `POST /api/v1/incidents/{id}/snooze/{duration}`

Fait taire les **rappels** d'un incident ouvert pendant `24h` ou `7d`, les deux
seules durées admises (décision de #35, `decisions.md`). L'e-mail d'ouverture et
celui de clôture ne sont pas concernés, et la requête n'a aucun effet sur un
site. Pire cas d'un jeton volé : des rappels retardés de 7 jours au plus.
Même enveloppe que `ack` : aucun corps, un corps annoncé reçoit 415.

- 200 et l'incident, `snoozed_until` posé à `maintenant + durée` ; une nouvelle
  sourdine remplace la précédente.
- 409 si l'incident est fermé : la base n'est pas modifiée.
- 404 si l'identifiant est inconnu ou si la durée n'est ni `24h` ni `7d`.
- Le journal du veilleur note l'id de l'appareil et la durée.

« Jusqu'à la prochaine mise à jour » n'est pas une durée : pour cesser les
rappels jusqu'à la clôture, l'acquittement (`ack`) existe déjà.

### `GET /api/v1/settings`

```json
{
  "sites": [
    {
      "id": "site-a",
      "url": "https://site-a.example.org/",
      "kind": "wordpress",
      "runtime": "php",
      "interval": 300,
      "agent_silence": 900,
      "agent": true,
      "checks": { "content": 300, "exposed": 300, "headers": 3600, "installer": 300, "tls": 3600 }
    }
  ],
  "alerts": { "to": "a***@e***.org" },
  "reminder_period": 86400,
  "public_url": "https://veilleur.example.org",
  "devices": [
    { "id": 1, "name": "téléphone", "created_at": 1792000000, "seen_at": 1792000300, "revoked_at": null, "current": true }
  ]
}
```

- `alerts.to` : le destinataire, réduit à la première lettre de la partie
  locale, du nom de domaine, et à l'extension. Ni l'expéditeur, ni le relais
  SMTP, ni `password_file` ne sont exposés.
- `public_url` : `null` sans section `[api]`.
- `devices` : tous les appareils, révoqués compris ; `current` désigne celui
  qui fait la requête.

### `DELETE /api/v1/devices/self`

L'appareil appelant se révoque, comme `vigie device revoke <id>` : 204 sans
corps, puis 401 pour toute requête avec ce jeton. C'est la seule écriture sur
les appareils accessible par l'API ; `vigie device list` montre ensuite
l'appareil révoqué.

## Texte issu des logs

Tout champ dont le texte vient des logs d'un site est assaini avant d'être
servi (`LogText`, `vigie/src/api/log_text.rs`) : caractères de contrôle C0,
DEL et C1, U+2028, U+2029 et contrôles bidirectionnels (U+061C, U+200E,
U+200F, U+202A à U+202E, U+2066 à U+2069) deviennent U+FFFD. Aujourd'hui :
`key` et `detail` des incidents du contrôle `logs`, `detail` de son passage
(analyse de #8, déjà assainie à l'écriture ; la lecture ne s'y fie pas) ;
`ip` des verdicts de `logs/ips`, et les textes du résumé de `logs` (`name`,
`publisher`, `purpose` des robots, `rule`), tirés du catalogue et de la
configuration mais relus de la base. Un user-agent ou un chemin, s'il en est
servi un jour, suit la même règle : coupé à 512 caractères, chemin sans query
string, referer réduit à son origine. La console n'injecte jamais de HTML brut (`vue/no-v-html` en erreur
dans `vigie/app/eslint.config.js`).

## État d'un site

Calculé par le veilleur seul (`SiteState` dans `vigie/src/api.rs`) ; la
console l'affiche sans le recalculer. Le premier cas qui s'applique l'emporte :

| Ordre | `state` | Règle |
| ----- | ------- | ----- |
| 1 | `non_compliant` | Un incident critique ouvert, hors `heartbeat`. |
| 2 | `blind` | Un incident `heartbeat` ouvert (silence d'agent) : le veilleur ne voit plus le site de l'intérieur. |
| 3 | `to_check` | Un avertissement ouvert, ou le dernier passage d'un contrôle surveillé non concluant (`error`). |
| 4 | `first_read` | Aucun passage, aucun rapport, aucun incident : rien n'est encore connu. |
| 5 | `ok` | Tout le reste. |

L'ordre est aussi celui de l'écran Main. `first_read` n'est pas dans l'ordre
des maquettes (non conforme, aveugle, à vérifier, OK) : il est placé avant
`ok`, parce qu'un site jamais lu ne doit pas passer pour un site sain.

## Écrans

| Écran | Données |
| ----- | ------- |
| Main | `overview` : `state`, `worst`, `open_count`, `last_read` de chaque site. |
| ATraiter | `overview`, puis `sites/{id}` des sites concernés : incidents ouverts, e-mails envoyés tirés des dates de notification. |
| Alerte | `incidents/{id}`, `incidents/{id}/mails` (e-mails envoyés), actions Acquitter (`incidents/{id}/ack`) et Sourdine (`incidents/{id}/snooze/{duration}`). |
| Dispo | `sites/{id}` (contrôles externes, `duration_ms`, `last_run`, `tls_not_after`) et `sites/{id}/incidents`. |
| Controles | `sites/{id}` : `checks`, externes et d'agent. |
| Parametres | `settings` (site concerné) et `sites/{id}` (`interval`, `agent_silence`). |
| Reglages | `settings` : `alerts.to`, `devices`, `public_url` ; retrait par `devices/self`. |
| Etats | `state` à `blind` ou `first_read`, `server_time` et `last_read` pour la fraîcheur, échec réseau pour « hors ligne ». |
| Failles | `sites/{id}/vulns` (composants touchés, failles, versions par source, correctif, KEV, EPSS, dérogation, liens, attributions, mention « usage interne » ou « faits seulement ») et `sites/{id}/components`, par pages ; 404 : écran « non alimenté » ; aucune action d'écriture. |
| Erreurs | `sites/{id}/errors` : groupes de messages, compteur sur 14 jours, première et dernière vue, jours de présence ; liste vide : aucune erreur reçue ; aucune action d'écriture. |
| SourcesFailles | `vulns/sources` : âge, dernière issue, entrées, licence, attribution, jeu KEV et EPSS, constat `vulns-sync` ouvert. |

## Limite de débit

En mémoire de `serve`, perdue à son redémarrage ; deux tables de seaux à
jetons, sur une horloge monotone :

| Table | Règle | Appliquée à |
| ----- | ----- | ----------- |
| Par appareil | 120 appels par minute, rafale de 30 | Toute requête au jeton valide, après l'authentification et avant « vu le ». Bornée par le nombre d'appareils, jamais évincée. |
| Par IP cliente | 10 par minute | `POST /api/v1/pair`, avant tout traitement ; ailleurs, seulement un échec d'authentification (jeton absent, inconnu ou révoqué), qui reçoit alors 429 au lieu de 401. |

- Un seau d'IP vide ne bloque **jamais** une requête au jeton valide : un
  appareil derrière le même NAT qu'un attaquant reste servi.
- IP cliente : une IPv4 entière, une IPv6 sur son /64. Derrière Caddy, le pair
  est la boucle locale (`127.0.0.1` ou `::1`) et l'IP est la dernière valeur
  de `X-Forwarded-For`, que Caddy écrit lui-même ; venant d'un autre pair,
  l'en-tête est ignoré.
- La table des IP garde 4 096 clés au plus. Seul un seau plein, équivalent à
  une clé absente, en est évincé ; quand elle est pleine de seaux entamés, une
  IP nouvelle reçoit 429 (fermé) : arroser d'adresses ne libère personne.
- 429 au format commun, avec `Retry-After` en secondes.

## En-têtes

Toute réponse de `/api/v1`, corps d'erreur compris, porte
`X-Content-Type-Options: nosniff` et `Cache-Control: no-store`, et
`Content-Type: application/json` quand elle a un corps. Aucun en-tête CORS :
la console appelle depuis Rust, aucun navigateur n'est à autoriser. `OPTIONS`
reçoit le 404 commun.

Un `POST` qui annonce un corps (`Content-Length` non nul ou
`Transfer-Encoding`) d'un autre type que `application/json` (paramètres
admis : `application/json; charset=utf-8`) reçoit 415, d'après les seuls
en-têtes. Un `POST` sans corps ni `Content-Type` est accepté. Un JSON
illisible sur `pair` garde son 401.

## Journal des appels

Une ligne par appel de `/api/v1` sur la sortie de `serve` (journald) :

```text
[3f…] appel /api/v1 : appareil 1 GET /api/v1/sites/{id} 200 4 ms
```

Identifiant de requête, appareil (`-` sans authentification), méthode,
gabarit de route (jamais le chemin brut ni la query string ; `-` hors des
routes connues), statut, durée. Jamais de jeton, de code d'appairage ni
d'en-tête. Les 429 d'une même IP sont regroupés : la première ligne d'une
minute cite l'IP, les suivants sont comptés et le compte est écrit à la
minute suivante (`N autre(s) 429 regroupé(s) pour <ip> sur une minute`).

## Codes de réponse

Toute réponse du veilleur porte un en-tête `X-Request-Id` : 32 caractères hex
minuscules, tirés au hasard pour chaque requête. Le journal du veilleur cite le
même identifiant entre crochets ; un `X-Request-Id` envoyé par le client est
ignoré.

Toute erreur de `/api/v1` porte le même corps, avec les en-têtes stricts
(voir [En-têtes](#en-têtes)) :

```json
{"error": {"code": "unauthorized", "message": "authentification requise", "request_id": "3f…"}}
```

`code` est stable et seul à lire par la console ; `message` n'est
qu'indicatif et ne dit jamais la cause d'un refus ou d'une erreur interne.
`request_id` est celui de l'en-tête.

| Code | `error.code` | Cas |
| ---- | ------------ | --- |
| 200 | — | Succès, avec `Cache-Control: no-store`. |
| 204 | — | `DELETE /api/v1/devices/self` réussi, corps vide. |
| 400 | `bad_request` | `limit` hors de 1 à 100 ou illisible, curseur illisible, trop long ou d'une autre liste, paramètre de pagination répété (voir [Pagination](#pagination)). Vérifié après le 404 d'un site. |
| 401 | `unauthorized` | Code inconnu, expiré, déjà utilisé, corps illisible, trop gros ou trop lent ; jeton absent, mal formé, inconnu ou révoqué ; base absente ou antérieure au schéma 6. **Le même corps**, quelle qu'en soit la raison : le journal du veilleur seul dit laquelle. Toujours vérifié avant le 404 d'un site ou d'un incident : leur existence ne se devine pas sans jeton. |
| 404 | `not_found` | Site absent de la configuration, incident inconnu, méthode refusée sur une route de l'API. |
| 409 | `conflict` | Acquittement d'un incident fermé. |
| 409 | `cursor_expired` | Curseur de `logs/ips` dont l'instantané a été purgé ou a plus de 48 h : reprendre au début. |
| 415 | `unsupported_media_type` | `POST` dont le corps annoncé n'est pas `application/json`. |
| 429 | `too_many_requests` | Limite de débit dépassée (voir [Limite de débit](#limite-de-débit)), avec `Retry-After`. |
| 500 | `internal` | Erreur interne (base illisible, tirage aléatoire impossible). |

Hors de ces routes, une route inconnue, y compris sous `/api/v1`, reçoit le 404
sans corps du reste du veilleur, comme tout refus de `POST /r/v1/report` (sous
`/api/v1`, avec les en-têtes stricts et sa ligne de journal).

La console 0.1.1 ne connaît pas 400, 409 `cursor_expired`, 415 ni 429 : elle
les affiche comme « le veilleur a répondu N ». Aucune de ses requêtes ne les
reçoit sous la limite : elle n'envoie ni `limit` ni `cursor`, et ne lit pas
les routes `logs`.

## Base de données

L'API ne crée jamais la base et ne la migre pas : `vigie serve` applique les
migrations au démarrage, `vigie device pair` aussi. Tant que la base est
absente ou antérieure au schéma 6 (appareils au schéma 5, résultat des
passages au schéma 6), toute requête reçoit 401.

Avant le schéma 11 (instantanés de l'analyse des logs), `logs` répond
`{"analysis": null}` et `logs/ips` une liste vide. Avant le schéma du
rapprochement (fichier `0021.sql`, #21 : `vuln_match_runs`,
`vuln_match_state`, `vuln_match_components`, `vuln_match_items`,
`vuln_match_seen`, `vuln_match_keys`, `vuln_waivers`), `components` et
`vulns` répondent 404 ; `vulns/sources` lit les tables de failles (#15 à
#18) et vaut des champs à `null` sur une base antérieure. Le schéma 12 ajoute
l'index `(site, closed_at, id)` des incidents clos, lu par
`sites/{id}/incidents`.
