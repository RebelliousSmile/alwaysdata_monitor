# Protocole des commandes, version 1

Le veilleur peut demander à l'agent d'un site d'agir. C'est la seule voie
d'écriture de Vigie vers un site, et elle est fermée par défaut. Ce document est
le contrat ; il fixe dès l'issue #2 ce que le canal de l'issue #10 transportera,
pour que les agents déployés n'aient jamais à changer de contrat.

Décision du 2026-10-16 (`decisions.md`) : agir suit toujours trois temps.
Vigie propose, l'exploitant valide, puis l'application se fait par une commande
explicite (`--apply`). Rien n'est automatique.

## Liste fermée

La liste est codée en dur (`src/capability.rs`). Ajouter une commande est un
changement de code relu, jamais une valeur de configuration.

| Commande | Effet | Runtimes admis |
| --- | --- | --- |
| `ping` | aller-retour sans effet : prouve que le canal fonctionne | `php` |
| `rotate-key` | l'agent crée une nouvelle paire de clés de rapport et rend la clé publique | `php` |
| `htaccess-apply` | remplace le bloc `# BEGIN vigie` … `# END vigie` du `.htaccess` (#13) | `php` |
| `htaccess-rollback` | remet le `.htaccess` précédent (#13) | `php` |

Aucune commande n'admet `node` tant qu'aucun agent Node n'existe, ni `static`,
qui n'a pas d'agent.

## Typologie : deux axes

| Axe | Clé de `config.toml` | Valeurs | Filtre |
| --- | --- | --- | --- |
| CMS | `kind` | `generic` (défaut), `wordpress`, `prestashop` | les contrôles (`CheckKind::cms`) |
| Runtime | `runtime` | `php`, `node`, `static` | les commandes (`CommandKind::runtimes`) |

- `wordpress` et `prestashop` impliquent `php` ; un autre runtime pour eux est
  une erreur de configuration.
- Un site `generic` sans `runtime` n'en a aucun et n'admet **aucune**
  commande. Un site PHP déclaré `generic` doit poser `runtime = "php"`.
- Le runtime vient **seulement** de `config.toml` sur le veilleur : jamais d'un
  rapport de l'agent, jamais d'une détection du contenu du site. Un site ne
  peut pas se déclarer lui-même `php`.
- Une valeur inconnue (`runtime = "python"`) fait refuser la configuration.

Dans le contrat des commandes, le champ s'appelle `runtime`, et non `kind`
comme dans le texte de l'issue #2 : `kind` désigne déjà le CMS.

## Enveloppe d'une commande

Le champ `command` d'une réponse du veilleur (voir Réponse) contient cet objet :

```json
{
  "v": 1,
  "site": "site-a",
  "id": "0192f5a8-7c3e-7d41-9b2a-5c1e8f0a4b6d",
  "seq": 3,
  "name": "ping",
  "runtime": "php",
  "params": {},
  "issued_at": 1792108800,
  "expires_at": 1792195200
}
```

| Champ | Règle |
| --- | --- |
| `v` | `1` ; l'agent refuse toute autre version |
| `site` | identifiant du site destinataire ; l'agent refuse un site qui n'est pas le sien. La clé de commandes est commune à tous les sites : sans ce champ, une commande pour le site A vaudrait pour le site B |
| `id` | UUIDv7 tiré par le veilleur |
| `seq` | entier strictement croissant par site ; l'agent refuse un `seq` déjà vu ou plus petit |
| `name` | une commande de la liste fermée ; l'agent refuse un nom absent de **sa propre** liste codée en dur |
| `runtime` | obligatoire ; l'agent refuse un runtime qui n'est pas le sien |
| `params` | objet propre à la commande, schéma strict (#10) |
| `issued_at`, `expires_at` | secondes Unix ; l'agent refuse une commande expirée |

- Le schéma est strict : tout champ inconnu fait refuser la commande.
- La signature (#10) porte sur **les octets exacts du corps**, tels que reçus,
  sans réencodage du JSON, comme pour les rapports (`protocole-agent.md`). Elle
  est faite par la clé de commandes du veilleur, distincte de toute clé
  d'agent. L'agent l'a épinglée à son installation.
- Le veilleur vérifie que la commande est admise (`permit`) à sa création, **et
  de nouveau à sa délivrance** : la configuration a pu changer entre-temps.

## Clés

Trois clés Ed25519, chacune pour un seul usage :

| Clé | Signe | Où |
| --- | --- | --- |
| Clé de rapport de l'agent | ses rapports, et ses retraits avec le préfixe `vigie-pull-v1\n` | sur le site, hors webroot (`agent-php.md`) |
| Clé de commandes du veilleur | les réponses de `/r/v1/commands`, préfixe `vigie-commands-v1\n` | `[commands] key_file`, lue par `serve` seul |
| Clé d'audit du veilleur | le journal d'audit, préfixe `vigie-audit-v1\n` | `[commands] audit_key_file`, lue par `serve`, `tick` et la CLI |

La clé de l'agent signe deux types de requête, mais jamais la même chose :
un rapport est signé sans préfixe (format en service), un retrait avec
`vigie-pull-v1\n`. Les deux clés du veilleur sont créées par
`vigie commands init-keys` : fichiers 0600 dans un dossier 0700, au
propriétaire du veilleur, jamais écrasés, lus sans suivre de lien. L'agent
épingle la clé publique de commandes à son installation
(`vigie commands pubkey`).

## Retrait

```http
POST /r/v1/commands HTTP/1.1
Content-Type: application/json
X-Vigie-Site: site-a
X-Vigie-Signature: <base64 de la signature de "vigie-pull-v1\n" + corps, par la clé de rapport>

{"v":1,"type":"pull","site":"site-a","seq":7,"sent_at":1800000000,"nonce":"Tm9uY2VEZVRlc3RBMTIzNDU2","agent":"agent-php/0.2.0","result":{"command_id":"…","status":"ok","detail":"pong"}}
```

| Champ | Règle |
| --- | --- |
| `v`, `type` | `1`, `pull` |
| `site` | égal à `X-Vigie-Site` |
| `seq` | strictement croissant par site, distinct du `seq` des rapports |
| `sent_at` | à ±300 s de l'heure du veilleur |
| `nonce` | 22 à 64 caractères base64url, tiré au hasard à chaque retrait |
| `agent` | 1 à 64 caractères imprimables |
| `result` | facultatif : `command_id`, `status` (`ok`, `failed`, `refused`), `detail` (imprimable, 1000 caractères au plus), `data` propre à la commande |

Le veilleur vérifie, dans l'ordre, et répond le 404 commun au premier échec
(comme `/r/v1/report`, la raison ne va qu'au journal) : taille (64 Ko, 10 s),
site présent dans la configuration **relue à ce retrait** et doté d'une clé,
signature, schéma strict, horloge, `seq`, débit (un retrait accepté par site et
par 30 s). Sans `[commands]` dans la configuration, ou sans clé de commandes
ou d'audit lisible, tout retrait reçoit le 404 : rien n'est servi ni accusé.

Un retrait refusé ne coûte rien à l'agent : il garde son résultat et
réessaiera au passage suivant.

## Réponse

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Vigie-Timestamp: 1800000000
X-Vigie-Signature: <base64 de la signature de "vigie-commands-v1\n" + horodatage + "\n" + corps>

{"v":1,"site":"site-a","nonce":"Tm9uY2VEZVRlc3RBMTIzNDU2","server_time":1800000000,"acked":"…","accepted":true,"command":null}
```

L'agent vérifie, dans l'ordre, et rejette la réponse au premier échec :

1. la signature, avec la clé de commandes épinglée, sur le préfixe,
   l'horodatage de l'en-tête et les octets exacts du corps ;
2. `server_time` égal à `X-Vigie-Timestamp` ;
3. l'horodatage à ±300 s de son horloge ;
4. `site` (de la réponse et de la commande) égal au sien ;
5. `nonce` égal à celui de son retrait ;
6. la commande : `v`, runtime, nom dans sa propre liste, `expires_at` dans le
   futur, `seq` jamais exécuté (voir l'enveloppe ci-dessus).

`tests/fixtures/commands-vectors.json` donne des vecteurs pour chaque cas, avec
le verdict attendu, et des retraits et une preuve de rotation signés.

## Résultat et accusé

- L'agent persiste `{id, seq, état, résultat}` avant et après l'exécution, et
  renvoie le résultat à chaque retrait tant qu'il n'a pas reçu `acked` égal à
  l'id de la commande.
- Le veilleur **accuse toujours** un résultat reçu (`acked`) et dit s'il l'a
  pris (`accepted`) : un résultat identique à celui déjà enregistré est sans
  effet ; un résultat sur une commande annulée, expirée, inconnue ou d'un
  autre site est refusé (`accepted: false`), tracé, mais accusé, pour que
  l'agent cesse de le renvoyer.
- `acked` ne part qu'une fois le résultat et son entrée d'audit écrits.
- Une commande servie et non close est re-servie identique (même `id`, même
  `seq`) : un agent qui l'a déjà exécutée ne la rejoue pas, il renvoie son
  résultat.
- Les `seq` vus par l'agent peuvent avoir des trous (commandes annulées ou
  expirées) : l'agent n'exige que leur croissance.

## États

```text
pending → served → done | failed | refused
pending → expired | refused (refusée à la délivrance : la configuration ne l'admet plus)
pending | served → cancelled (exploitant, kill-switch, site remove, site rotate-key)
served → unknown (sans résultat en 24 h : elle a pu s'exécuter) → done | failed (résultat tardif)
```

- Une seule commande non close par site (index unique en base).
- Une commande non retirée 24 h après sa création passe `expired` ; une
  commande servie sans résultat en 24 h passe `unknown`. `serve` ne sert jamais
  une commande échue, même avant le passage de `tick`.
- Remettre en file une commande non idempotente (`rotate-key`, `htaccess-*`)
  après une issue `unknown` exige `--force`.

## `rotate-key`

1. L'agent crée une nouvelle paire et **garde l'ancienne**.
2. Son résultat porte `data.new_pubkey` (base64) et `data.proof` : signature
   par la nouvelle clé de `vigie-rotate-v1\n` + site + `\n` + id de la
   commande + `\n` + nouvelle clé publique en base64.
3. Le retrait qui le porte est signé par l'**ancienne** clé.
4. Le veilleur vérifie la preuve, refuse une clé égale à l'ancienne ou à celle
   d'un autre site, et ne bascule que si la commande est encore `served` ; il
   remplace alors la clé et remet à zéro les `seq` de rapport et de retrait,
   dans la même transaction, et accuse avec `accepted: true`.
5. L'agent ne bascule que sur `acked` égal à l'id **et** `accepted: true`. Sur
   `accepted: false`, il détruit la nouvelle paire et garde l'ancienne. Tant
   qu'il n'a pas d'accusé, pour ses retraits et ses rapports, il essaie la
   nouvelle clé quand l'ancienne est refusée.
6. Un résultat tardif de `rotate-key` sur une commande `unknown` est refusé et
   la commande passe `failed` : la clé ne change pas.

`rotate-key` n'est **pas** un remède à une compromission du site : qui tient la
clé de l'agent peut répondre avec sa propre clé. Le remède reste la
réinstallation de l'agent et `vigie site rotate-key` hors canal, qui annule
toute commande en vol : une preuve arrivée après ne remplace jamais cette clé.

## Journal d'audit

- Une chaîne par site, en ajout seul (la base refuse `UPDATE` et `DELETE`).
  Chaque entrée stocke ses octets JSON tels qu'écrits ; `hash = SHA-256(hash
  précédent ‖ octets)`, signé par la clé d'audit.
- Évènements : `enabled`, `disabled`, `created`, `served`, `refused`,
  `result`, `result-late`, `result-rejected`, `expired`, `unknown`,
  `cancelled`.
- Ancre externe : `tick` envoie par e-mail la tête de chaque chaîne qui a
  changé, environ une minute après. Garder ces e-mails : une fin de chaîne
  coupée ne se voit que contre une tête connue d'ailleurs.
- `vigie site audit site-a` exporte en JSONL ;
  `vigie site audit site-a --verify --head <hash reçu par e-mail>` vérifie
  chaîne, signatures et tête (code 1 sinon).

## CLI

```console
$ vigie commands init-keys                     # une fois, après avoir posé [commands]
$ vigie commands pubkey                         # à épingler par chaque agent
$ vigie site commands site-a enable            # kill-switch : enable | disable
$ vigie site command site-a ping               # aperçu, rien n'est écrit
$ vigie site command site-a ping --apply       # en file, servie au prochain retrait
$ vigie site command-cancel site-a
$ vigie site audit site-a --verify --head <hash>
```

`site remove` et `site rotate-key` coupent le canal du site et annulent la
commande en vol : un site réinstallé n'hérite d'aucune activation.

## Changer la clé de commandes

1. Créer une nouvelle clé (renommer l'ancienne, puis `vigie commands
   init-keys` ne crée que ce qui manque : déplacer aussi la clé d'audit si
   elle doit changer).
2. Réinstaller chaque agent avec la nouvelle clé publique épinglée.
3. Détruire l'ancienne clé. Entre-temps, les agents qui épinglent l'ancienne
   refusent les réponses : aucune commande ne s'exécute.

## Ce que le canal ne protège pas

- Un attaquant installé sur le site, qui tient la clé de l'agent, peut retirer
  la commande en vol et déclarer `ok` sans l'exécuter : le journal enregistre
  des **déclarations** de l'agent, pas des preuves d'exécution.
- Le même attaquant peut forger un `seq` de retrait à 2⁶³−1 et bloquer les
  retraits de l'agent légitime : remède, `vigie site rotate-key` hors canal.
- Il ne peut ni créer de commande, ni en lire une destinée à un autre site, ni
  rejouer une réponse : la clé de commandes, l'enveloppe signée avec `site` et
  le `nonce` l'en empêchent.
