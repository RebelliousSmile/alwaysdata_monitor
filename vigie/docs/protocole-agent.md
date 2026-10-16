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

Pour un agent, seules `POST /r/v1/report` et `POST /r/v1/commands`
(`protocole-commandes.md`) existent, avec `GET /health` ; toute autre route
ou méthode hors de `/api/v1` reçoit le même 404.

Un agent qui reçoit un 404 ne réessaie pas le même rapport : il enverra le
suivant, avec un `seq` plus grand et un `sent_at` frais, à son prochain envoi.
Un refus répété se lit dans `journalctl -u vigie-serve` sur le veilleur.

## Effets d'un rapport accepté

- Le `seq`, l'heure de réception et `facts` sont enregistrés.
- Les constats passent dans le cycle des incidents des contrôles externes, sous
  le contrôle `agent:<check>` : un constat nouveau ouvre un incident, un constat
  disparu le clôt. Les constats `info` sont montrés dans `vigie status` et
  jamais envoyés par e-mail.
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
- `site add` refuse un site absent de la configuration ou qui a déjà une clé.
- `site rotate-key` remplace la clé : un rapport signé avec l'ancienne est
  refusé dès la rotation. La séquence repart de zéro, puisque l'ancienne clé ne
  peut plus rien faire accepter ; le silence reste mesuré depuis le dernier
  rapport accepté.
- `site remove` retire la clé, l'état des rapports et la référence
  d'empreintes, après confirmation (taper
  l'identifiant du site) ou avec `--yes`. Les incidents de l'agent sont clos au
  passage suivant de `tick`.

### Une clé par usage

Règle du socle (issue #9) : une paire Ed25519 sert un seul usage, et une clé
ne vérifie jamais ce qu'une autre a signé.

| Usage | Signe | Vérifie | Clé privée |
| --- | --- | --- | --- |
| Rapports | l'agent | le veilleur, avec la clé publique de `site add` | sur le site, hors webroot, 0600 vérifié par l'agent |
| Retraits de commandes | l'agent, préfixe `vigie-pull-v1\n` | le veilleur, même clé que les rapports | idem rapports ; le préfixe sépare les deux usages |
| Commandes | le veilleur (`[commands] key_file`) | l'agent, avec la clé publique épinglée | sur le VPS, lue par `serve` seul (`protocole-commandes.md`) |
| Audit des commandes | le veilleur (`[commands] audit_key_file`) | `vigie site audit --verify` | sur le VPS, lue par `serve`, `tick` et la CLI |

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

