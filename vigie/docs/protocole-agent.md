# Protocole des rapports d'agent, version 1

Un agent installé sur un site envoie au veilleur, à intervalle régulier, un
rapport signé de ce qu'il voit de l'intérieur. Le veilleur ne garde que la clé
publique de chaque site : la clé privée ne quitte jamais le site.

Ce document est le contrat. `vigie/src/report.rs`, `vigie/src/ingest.rs`,
`vigie/src/facts.rs` et `vigie/tests/ingest.rs` en reprennent chaque règle.
L'agent PHP qui le respecte est décrit dans `agent-php.md`, et
`vigie/tests/interop.rs` vérifie un rapport qu'il a signé.

## Requête

```http
POST /r/v1/report HTTP/1.1
Host: <sous-domaine du veilleur>
Content-Type: application/json
X-Vigie-Site: site-a
X-Vigie-Signature: <base64 de la signature>

{"v":1,"site":"site-a","seq":42,"sent_at":1792079580,"agent":"agent-php/0.1.0","findings":[],"facts":{}}
```

- `X-Vigie-Site` : identifiant du site, tel que déclaré dans la configuration
  du veilleur (`[a-z0-9-]`, 64 caractères au plus).
- `X-Vigie-Signature` : signature Ed25519 détachée (RFC 8032, 64 octets),
  calculée sur **les octets bruts du corps**, exactement tels qu'envoyés, puis
  encodée en base64 standard avec remplissage (88 caractères). Le veilleur ne
  réencode jamais le JSON avant de vérifier : l'agent signe ce qu'il envoie.
- Côté PHP : `base64_encode(sodium_crypto_sign_detached($body, $secret))`.
- Corps : 64 Ko au plus, reçu en entier en 10 s au plus.

## Corps

Objet JSON, sans autre champ que ceux-ci (tout champ inconnu fait refuser le
rapport) :

| Champ | Type | Règle |
| ----- | ---- | ----- |
| `v` | entier | `1` |
| `site` | chaîne | égal à `X-Vigie-Site` |
| `seq` | entier | de 1 à 2⁶³−1, strictement supérieur au dernier `seq` accepté pour ce site |
| `sent_at` | entier | heure d'envoi, en secondes Unix, à ±300 s de l'horloge du veilleur |
| `agent` | chaîne | nom et version de l'agent, 1 à 64 caractères imprimables |
| `findings` | tableau | 100 constats au plus, voir ci-dessous |
| `facts` | objet | 50 entrées au plus ; clés `[a-z0-9_-]`, 1 à 64 caractères ; valeurs chaînes de 256 caractères au plus, nombres, booléens ou `null` |
| `files` | objet, facultatif | 100 entrées au plus ; clé : chemin d'un fichier critique relatif à la racine du site, 1 à 200 caractères imprimables ; valeur : son SHA-256 en 64 caractères hexadécimaux minuscules, ou `null` si le fichier est absent |

Chaque constat :

| Champ | Type | Règle |
| ----- | ---- | ----- |
| `check` | chaîne | famille du contrôle, `[a-z0-9-]`, 1 à 32 caractères, sauf `integrity`, réservé au veilleur |
| `severity` | chaîne | `info`, `warning` ou `critical` |
| `key` | chaîne | identifiant stable du constat, 1 à 200 caractères imprimables, jamais une heure ni une valeur mesurée |
| `detail` | chaîne | texte lisible, 1 à 300 caractères imprimables, montré dans l'e-mail |

« Imprimable » : aucun caractère de contrôle, retour à la ligne compris.

Un rapport décrit **l'état complet** vu par l'agent : un constat absent d'un
rapport accepté est considéré comme résolu. L'agent envoie donc tous ses
constats à chaque rapport, même ceux déjà signalés.

`facts` sert au relevé (versions de PHP, du CMS, des extensions…) : le dernier
relevé accepté est conservé, il n'ouvre aucun incident.

`files` sert à la comparaison d'intégrité (voir plus bas) : l'agent ne garde
aucun état, c'est le veilleur qui voit qu'un fichier a changé.

## Acceptation

Le veilleur vérifie, dans cet ordre, et s'arrête au premier échec :

1. **Taille** : corps de 64 Ko au plus, reçu en 10 s au plus ;
2. **Site connu** : `X-Vigie-Site` est déclaré dans la configuration et a une
   clé publique enregistrée par `vigie site add` ;
3. **Signature** : `X-Vigie-Signature` décode en 64 octets et vérifie, avec
   cette clé, les octets reçus (vérification stricte : signatures malléables et
   clés de petit ordre refusées, comme le fait libsodium) ;
4. **Schéma** : le corps respecte les tableaux ci-dessus et son `site` est égal
   à `X-Vigie-Site` ;
5. **Horodatage** : `sent_at` est à ±300 s de l'heure du veilleur ;
6. **Séquence** : `seq` est strictement supérieur au dernier `seq` accepté pour
   ce site, ce qui rend tout rejeu inutile ;
7. **Débit** : au plus un rapport accepté par site et par 60 s.

Réponses :

- **204** sans corps : rapport accepté ;
- **404** sans corps : tout refus, quelle qu'en soit la raison. Un site inconnu,
  une signature fausse ou un rapport rejoué reçoivent la même réponse, pour ne
  rien apprendre à qui sonde le point d'entrée. La raison n'est écrite que dans
  le journal du veilleur, avec le site et le `seq` quand ils sont lisibles,
  jamais avec le corps reçu.

Pour un agent, seules `POST /r/v1/report`, `POST /r/v1/commands`
(`protocole-commandes.md`) et `POST /r/v1/logs` (`logs.md`, « Transport
Alwaysdata ») existent, avec `GET /health` ; toute autre route
ou méthode hors de `/api/v1` reçoit le même 404.

Un agent qui reçoit un 404 ne réessaie pas le même rapport : il enverra le
suivant, avec un `seq` plus grand et un `sent_at` frais, à son prochain envoi.
Un refus répété se lit dans `journalctl -u vigie-serve` sur le veilleur.

## Effets d'un rapport accepté

- Le `seq`, l'heure de réception et `facts` sont enregistrés.
- Registre des capacités (`capability.rs`, issue #4) : seules les familles
  qu'émet l'agent PHP sont connues (`root`, `critical-file`, `must-contain`,
  `uploads-php`), `uploads-php` pour un site `wordpress` seulement, et aucune
  pour un site dont le runtime effectif n'est pas `php`. Un constat d'une
  famille bien formée mais inconnue, ou non admise pour le site, est
  **écarté et compté** : le rapport reste accepté, le nombre d'écartés du
  dernier rapport est enregistré (`reports.dropped`), journalisé par `serve`
  et montré par `vigie status`. `integrity`, lui, fait refuser tout le rapport
  (ci-dessus).
- Les constats admis passent dans le cycle des incidents des contrôles
  externes, sous le contrôle `agent:<check>` : un constat nouveau ouvre un
  incident, un constat disparu le clôt. Les constats `info` sont montrés dans
  `vigie status` et jamais envoyés par e-mail. Un incident d'une famille que
  le registre ne surveille plus pour ce site n'est ni clos ni noté « ok » par
  le rapport : `tick` le clôt « plus surveillé ».
- Les empreintes `files` sont comparées à la référence du site (ci-dessous).
- Un incident « agent silencieux » ouvert pour ce site est clos.
- `serve` n'envoie aucun e-mail : le passage suivant de `vigie tick`, dans la
  minute, envoie les ouvertures et les clôtures.

## Intégrité des fichiers critiques

Le premier rapport accepté qui porte des empreintes `files` pose la
**référence** du site. Ensuite, à chaque rapport :

- une empreinte différente de celle de la référence ouvre un incident
  d'avertissement `agent:integrity`, clé `modified:<chemin>`. La référence ne
  suit pas : l'incident reste ouvert tant que le fichier diffère, et se clôt
  s'il revient à son contenu de référence ;
- un chemin inconnu de la référence, ou absent quand elle a été posée, y entre
  avec son empreinte, sans incident ;
- un fichier absent (`null`) n'ouvre rien ici, l'agent le signale lui-même
  (`critical-file`), et la référence garde son ancienne empreinte : un fichier
  restauré avec un autre contenu est signalé ;
- un chemin que l'agent ne rapporte plus reste dans la référence.

Après une modification voulue (mise à jour de WordPress, règle `.htaccess`
ajoutée), prendre les empreintes du dernier rapport comme nouvelle référence :

```console
$ ~/vigie/bin/vigie site accept site-a
```

Les incidents d'intégrité du site sont clos aussitôt. `site remove` efface la
référence avec la clé ; `site rotate-key` la garde.

## Silence

`vigie tick` ouvre un incident critique `heartbeat` pour tout site dont la
clé est enregistrée et dont le dernier rapport accepté (ou, à défaut, la date
d'enregistrement de la clé) date de plus de `agent_silence` secondes (900 par
défaut, réglable par site dans la configuration). Le rapport accepté suivant le
clôt.

## Inventaire des composants (issue #19)

`POST /r/v1/inventory` reçoit l'inventaire des composants d'un site, en
CycloneDX, relevé par l'agent PHP 0.5.0 (`agent-php.md`, « Inventaire »,
source `agent`) ou lu dans les lockfiles du projet par `vigie-inventory` au
déploiement (`inventaire.md`, issue #20, source `ci`).
Code : `vigie/src/inventory/` ; tests : `vigie/tests/inventory_receive.rs`,
`interop.rs`, `inventory_vectors.rs`, `agent_e2e.rs`.

- Mêmes en-têtes que le rapport. `X-Vigie-Signature` signe
  `vigie-inventory-v1\n` suivi des octets bruts du corps, avec la clé de
  rapport pour l'agent (`sodium_crypto_sign_detached(DOMAIN_INVENTORY . $body,
  $secret)`), avec la clé d'inventaire du site pour `vigie-inventory`.
- **La clé qui vérifie fixe la source** : le veilleur essaie la clé d'agent
  (si `agent-php` est déclaré), puis la clé d'inventaire (si `ci` est
  déclaré) ; aucun en-tête ni champ non signé ne choisit la clé. Une signature
  valide pour les deux est impossible : une clé publique n'est enregistrée
  qu'une fois.
- Corps de 512 Kio au plus, reçu en 10 s, sans gzip.
- Ouvert seulement pour un site qui déclare `[sites.inventory]` dans
  `config.toml` : `sources = ["agent-php", "ci"]` (1 ou 2 valeurs distinctes),
  ou la forme `source = "agent-php"` de F5, lue comme une liste d'un élément ;
  les deux clés ensemble sont refusées au chargement. `agent-php` exige le
  runtime effectif `php` ; `ci` est admis quel que soit le runtime, même
  absent. C'est la configuration du veilleur qui dit « surveillé », jamais ce
  qu'un agent envoie.

### Enveloppe et liste blanche

```json
{"v":1,"type":"inventory","site":"site-a","seq":1792079580123,"sent_at":1792079580,
 "agent":"vigie-agent-php/0.5.0","complete":true,"skipped":0,
 "bom":{"bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":"urn:uuid:…",
        "metadata":{"timestamp":"2026-10-15T15:53:00Z","component":{"type":"application","name":"site-a"}},
        "components":[{"type":"library","name":"exemple-formulaire","version":"5.9.3",
                       "purl":"pkg:wordpress/plugin/exemple-formulaire@5.9.3","scope":"required",
                       "properties":[{"name":"vigie:path","value":"wp-content/plugins/exemple-formulaire"},
                                     {"name":"vigie:scope","value":"required"}]}]}}
```

| Champ | Règle |
| --- | --- |
| `v`, `type` | `1`, `inventory` |
| `site` | égal à `X-Vigie-Site` |
| `source` | facultatif : `agent` ou `ci`, absent = `agent` (agents 0.5.0) ; doit égaler la source fixée par la clé, sinon refus (« schéma : source ») |
| `seq` | ≥ 1, strictement croissant, propre aux inventaires et à la source (`site_keys.last_inventory_seq` pour `agent`, `site_inventory_keys.last_seq` pour `ci`) |
| `sent_at` | ±300 s de l'heure du veilleur |
| `agent` | 1 à 64 caractères imprimables (`vigie-agent-php/0.5.0`, `vigie-inventory/0.1.0`) |
| `complete`, `skipped` | booléen ; 0 à 100 000 composants et sources écartés par l'agent. `complete = false` dès que `skipped > 0` ou qu'une borne a tronqué le relevé. **Seul un inventaire complet vaut absence d'un composant** (règle de F7) |
| `bom.bomFormat`, `specVersion` | `CycloneDX` ; `1.6` ou `1.7` (l'agent émet `1.7`) |
| `bom.serialNumber` | `urn:uuid:` et UUID en minuscules |
| `bom.metadata` | `{timestamp, component}` : RFC 3339 en UTC à 30 jours au plus de `sent_at` ; `{"type":"application","name":<site>}` |
| `bom.components` | 0 à 2 000 objets `{type, name, version, purl, scope, properties}`, rien d'autre |
| `type` | `application` pour un noyau (`pkg:wordpress/core/core`, `pkg:prestashop/core/prestashop`), `library` sinon |
| `version` | vide, ou la version du purl (grammaire `[0-9A-Za-z.+_-]{1,128}`) |
| `purl` | forme canonique de la grammaire commune (`failles.md`, « Conventions purl ») |
| `scope` | `required`, ou `excluded` pour une dépendance de développement |
| `properties` | `vigie:path` (obligatoire, relatif, 200 octets, segments de `[A-Za-z0-9._@+-]`), `vigie:scope` (obligatoire : `required`, `dev` ou `mu`), `vigie:parent` (thème parent d'un thème enfant), `vigie:config-version` (module PrestaShop dont `config.xml` diffère) |

`deny_unknown_fields` partout : **un champ hors liste** (`authors`,
`supplier`, `licenses`, `hashes`, `bom-ref`…) **ou une propriété hors de ces
quatre, ou en double, fait refuser le document entier**. Le scope CycloneDX
n'admet que `required`, `optional` et `excluded` : le scope Vigie de l'issue
(`required`, `dev`, `mu`) part dans `vigie:scope`.

Un défaut propre à un composant l'écarte et le compte (`dropped`), le reste
étant accepté : purl hors grammaire ou non canonique (le veilleur recalcule la
forme canonique, Composer en minuscules), écosystème non admis pour le CMS du
site (`wordpress` sur un site `wordpress`, `prestashop` sur un site
`prestashop`, `composer`, `npm` et `cargo` partout), version différente de
celle du purl, incohérence (`excluded` si et seulement si `dev`, `mu` hors
extension WordPress, `vigie:parent` hors thème, `vigie:config-version` hors
module, `application` hors noyau), doublon `(purl, vigie:path)`. L'agent
applique la même grammaire : il n'émet rien que le veilleur écarterait.

### Vérifications

Dans l'ordre, arrêt au premier échec, 404 sans corps :

1. **Avant de lire le corps** : `X-Vigie-Site` bien formé, site connu,
   `[sites.inventory]` déclarée, au moins une source déclarée dont la clé est
   enregistrée (clé d'agent pour `agent-php`, clé d'inventaire pour `ci`),
   signature présente. Un corps annoncé de 10 Mio d'un site fermé n'est
   jamais lu.
2. Taille et délai du corps.
3. Hors du writer de `serve` : signature (domaine `vigie-inventory-v1\n`)
   avec la clé d'agent puis la clé d'inventaire, la première qui vérifie
   fixant la source ; liste blanche, `source` de l'enveloppe égale, purl,
   liste canonique et digest, horloge (±300 s : une machine de CI dont
   l'horloge dérive de plus de 5 min voit ses envois refusés).
4. Dans le writer, transaction IMMEDIATE, **par (site, source)** : clé de la
   source inchangée, `seq` strictement croissant ; débit de 240 s sur le
   `seen_at` du dernier inventaire de la source, pour **tout envoi** de la
   source `agent` et pour le seul **renvoi inchangé** de la source `ci` (un
   inventaire `ci` nouveau n'a pas de délai : deux déploiements rapprochés
   décrivent deux états réels) ; **24 inventaires nouveaux par (site, source)
   et par jour UTC** (au-delà, raison `plafond quotidien des inventaires`) ;
   écriture.

Le journal ne porte que des raisons fixes (« schéma : champ hors liste
blanche », « schéma : JSON illisible »…) et des nombres : jamais le texte
d'erreur de serde, ni un nom, une version ou un purl reçu. Un rapport, un
retrait ou un lot de logs rejoués sur `/r/v1/inventory` échouent à la
signature, et un inventaire envoyé à `/r/v1/report` ou `/r/v1/logs` aussi.

### Effets

- Digest SHA-256 de la liste canonique (composants triés par `(purl, path)`,
  sérialisés par le veilleur, sans `serialNumber`, `timestamp` ni `seq`). Même
  digest et même `complete` que le dernier inventaire du site : seuls
  `seen_at` et `seq` avancent (renvoi des 24 h). Sinon, nouvel inventaire et
  ses composants en une transaction.
- Le corps reçu n'est jamais stocké : `site_inventory` (tête) et
  `site_inventory_components` (`ecosystem`, `base` = purl sans version,
  `purl`, `name`, `version`, scope Vigie, `type`, `path`, `parent`,
  `config_version`), migration 16.
- Conservation : le dernier inventaire de chaque (site, source), colonne
  `site_inventory.source` (migration du fichier `0020.sql`) ; les précédents
  purgés par `tick` 30 jours après leur `seen_at`. Une source retirée de
  `[sites.inventory]` (ou un site retiré de la configuration) perd aussi son
  dernier inventaire 30 jours après son dernier `seen_at`.
- **Pas une preuve de vie** : un inventaire ne touche ni au dernier rapport,
  ni au silence, ni aux incidents, et n'ouvre aucun constat. « Inventaire
  périmé » et le rapprochement sont des règles du contrôle `vulns` (F7) ; la
  péremption se juge par source : **7 jours pour `agent`, 35 jours pour
  `ci`** (`inventory::stale_after`).
- **Un inventaire de CI décrit ce qui va être déployé, pas ce qui tourne** :
  l'agent PHP reste la vérité du serveur ; F7 dit d'où vient chaque
  composant.
- `site rotate-key` (et la rotation par commande) remet le `seq` de la source
  `agent` à zéro, `site inventory-key <site> rotate` celui de la source `ci` ;
  l'inventaire reste. `site remove` purge les deux clés et tous les
  inventaires du site.

### Limites V1

Aucune lecture de l'inventaire par l'API, la console ou la CLI (F7) ; aucun
gzip ; les limites de relevé de l'agent sont dans `agent-php.md`.

## Clés

```console
$ ~/vigie/bin/vigie site add site-a --pubkey <base64 de la clé publique>
$ ~/vigie/bin/vigie site list
$ ~/vigie/bin/vigie site rotate-key site-a --pubkey <base64 de la nouvelle clé>
$ ~/vigie/bin/vigie site accept site-a
$ ~/vigie/bin/vigie site remove site-a
```

- La clé publique fait 32 octets (44 caractères en base64). Côté PHP :
  `$pair = sodium_crypto_sign_keypair()`, puis
  `base64_encode(sodium_crypto_sign_publickey($pair))`.
- `site add` refuse un site absent de la configuration ou qui a déjà une clé,
  et, comme `site rotate-key`, un site dont le runtime effectif n'est pas
  `php` (issue #4) : déclarer `runtime = "php"` pour un site `generic` en PHP.
  Une clé déjà en base sur un tel site ouvre l'avertissement `typology`.
- `site rotate-key` remplace la clé : un rapport signé avec l'ancienne est
  refusé dès la rotation. La séquence repart de zéro (celles des lots de logs
  et des inventaires aussi), puisque l'ancienne clé ne
  peut plus rien faire accepter ; le silence reste mesuré depuis le dernier
  rapport accepté.
- `site remove` retire la clé, l'état des rapports, la référence
  d'empreintes, les logs et les inventaires reçus du site, après confirmation (taper
  l'identifiant du site) ou avec `--yes`. Les incidents de l'agent sont clos au
  passage suivant de `tick`.

### Une clé par usage

Règle du socle (issue #9) : une paire Ed25519 sert un seul usage, et une clé
ne vérifie jamais ce qu'une autre a signé.

| Usage | Signe | Vérifie | Clé privée |
| --- | --- | --- | --- |
| Rapports | l'agent | le veilleur, avec la clé publique de `site add` | sur le site, hors webroot, 0600 vérifié par l'agent |
| Retraits de commandes | l'agent, préfixe `vigie-pull-v1\n` | le veilleur, même clé que les rapports | idem rapports ; le préfixe sépare les deux usages |
| Lots de logs (`/r/v1/logs`) | l'agent, préfixe `vigie-logs-v1\n` | le veilleur, même clé que les rapports | idem rapports ; le préfixe sépare les usages |
| Inventaires (`/r/v1/inventory`) | l'agent, préfixe `vigie-inventory-v1\n` | le veilleur, même clé que les rapports | idem rapports ; le préfixe sépare les usages |
| Inventaires de CI (`/r/v1/inventory`, #20) | `vigie-inventory`, clé d'inventaire, préfixe `vigie-inventory-v1\n` | le veilleur, clé de `vigie site inventory-key` (`site_inventory_keys`), jamais consultée par `/r/v1/report`, `/r/v1/logs` ni `/r/v1/commands` | secret d'environnement de déploiement de la CI (`docs/inventaire.md`) |
| Commandes | le veilleur (`[commands] key_file`) | l'agent, avec la clé publique épinglée | sur le VPS, lue par `serve` seul (`protocole-commandes.md`) |
| Audit des commandes | le veilleur (`[commands] audit_key_file`) | `vigie site audit --verify` | sur le VPS, lue par `serve`, `tick` et la CLI |

- **Une clé publique n'est enregistrée qu'une fois**, toutes tables et tous
  sites confondus : `site add`, `site rotate-key`, `site inventory-key add`,
  `site inventory-key rotate` et la commande `rotate-key` refusent une clé
  déjà enregistrée comme clé d'agent ou d'inventaire (code 2, « clé déjà
  enregistrée »), dans leur transaction (`store::pubkey_in_use`).
- L'agent **épingle** la clé publique des commandes : il la reçoit une fois,
  à `--init`, et refuse ensuite toute commande signée par une autre. Elle ne
  se change que par une nouvelle installation de l'agent, jamais par une
  commande.
- La rotation d'une clé de rapport reste celle de `agent-php.md` et de
  `site rotate-key` ci-dessus. Changer la clé des commandes demande de
  réinstaller chaque agent : `protocole-commandes.md`, « Changer la clé de
  commandes ».
- Un webhook entrant éventuel aurait son propre secret, distinct de toutes les
  clés Ed25519 (`decisions.md`, sonde UptimeRobot).
- Les signatures restent en base64 standard avec remplissage (`decisions.md`).

