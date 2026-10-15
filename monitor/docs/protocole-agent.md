# Protocole des rapports d'agent, version 1

Un agent installé sur un site envoie au veilleur, à intervalle régulier, un
rapport signé de ce qu'il voit de l'intérieur. Le veilleur ne garde que la clé
publique de chaque site : la clé privée ne quitte jamais le site.

Ce document est le contrat. `monitor/src/report.rs`, `monitor/src/ingest.rs`
et `monitor/tests/ingest.rs` en reprennent chaque règle.

## Requête

```http
POST /r/v1/report HTTP/1.1
Host: <sous-domaine du veilleur>
Content-Type: application/json
X-Monitor-Site: site-a
X-Monitor-Signature: <base64 de la signature>

{"v":1,"site":"site-a","seq":42,"sent_at":1792079580,"agent":"agent-php/0.1.0","findings":[],"facts":{}}
```

- `X-Monitor-Site` : identifiant du site, tel que déclaré dans la configuration
  du veilleur (`[a-z0-9-]`, 64 caractères au plus).
- `X-Monitor-Signature` : signature Ed25519 détachée (RFC 8032, 64 octets),
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
| `site` | chaîne | égal à `X-Monitor-Site` |
| `seq` | entier | de 1 à 2⁶³−1, strictement supérieur au dernier `seq` accepté pour ce site |
| `sent_at` | entier | heure d'envoi, en secondes Unix, à ±300 s de l'horloge du veilleur |
| `agent` | chaîne | nom et version de l'agent, 1 à 64 caractères imprimables |
| `findings` | tableau | 100 constats au plus, voir ci-dessous |
| `facts` | objet | 50 entrées au plus ; clés `[a-z0-9_-]`, 1 à 64 caractères ; valeurs chaînes de 256 caractères au plus, nombres, booléens ou `null` |

Chaque constat :

| Champ | Type | Règle |
| ----- | ---- | ----- |
| `check` | chaîne | famille du contrôle, `[a-z0-9-]`, 1 à 32 caractères |
| `severity` | chaîne | `info`, `warning` ou `critical` |
| `key` | chaîne | identifiant stable du constat, 1 à 200 caractères imprimables, jamais une heure ni une valeur mesurée |
| `detail` | chaîne | texte lisible, 1 à 300 caractères imprimables, montré dans l'e-mail |

« Imprimable » : aucun caractère de contrôle, retour à la ligne compris.

Un rapport décrit **l'état complet** vu par l'agent : un constat absent d'un
rapport accepté est considéré comme résolu. L'agent envoie donc tous ses
constats à chaque rapport, même ceux déjà signalés.

`facts` sert au relevé (versions de PHP, du CMS, des extensions…) : le dernier
relevé accepté est conservé, il n'ouvre aucun incident.

## Acceptation

Le veilleur vérifie, dans cet ordre, et s'arrête au premier échec :

1. **Taille** : corps de 64 Ko au plus, reçu en 10 s au plus ;
2. **Site connu** : `X-Monitor-Site` est déclaré dans la configuration et a une
   clé publique enregistrée par `monitor site add` ;
3. **Signature** : `X-Monitor-Signature` décode en 64 octets et vérifie, avec
   cette clé, les octets reçus (vérification stricte : signatures malléables et
   clés de petit ordre refusées, comme le fait libsodium) ;
4. **Schéma** : le corps respecte les tableaux ci-dessus et son `site` est égal
   à `X-Monitor-Site` ;
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

Seules `GET /health` et `POST /r/v1/report` existent ; toute autre route ou
méthode reçoit le même 404.

Un agent qui reçoit un 404 ne réessaie pas le même rapport : il enverra le
suivant, avec un `seq` plus grand et un `sent_at` frais, à son prochain envoi.
Un refus répété se lit dans `journalctl -u monitor-serve` sur le veilleur.

## Effets d'un rapport accepté

- Le `seq`, l'heure de réception et `facts` sont enregistrés.
- Les constats passent dans le cycle des incidents des contrôles externes, sous
  le contrôle `agent:<check>` : un constat nouveau ouvre un incident, un constat
  disparu le clôt. Les constats `info` sont montrés dans `monitor status` et
  jamais envoyés par e-mail.
- Un incident « agent silencieux » ouvert pour ce site est clos.
- `serve` n'envoie aucun e-mail : le passage suivant de `monitor tick`, dans la
  minute, envoie les ouvertures et les clôtures.

## Silence

`monitor tick` ouvre un incident critique `heartbeat` pour tout site dont la
clé est enregistrée et dont le dernier rapport accepté (ou, à défaut, la date
d'enregistrement de la clé) date de plus de `agent_silence` secondes (900 par
défaut, réglable par site dans la configuration). Le rapport accepté suivant le
clôt.

## Clés

```console
$ ~/monitor/bin/monitor site add site-a --pubkey <base64 de la clé publique>
$ ~/monitor/bin/monitor site list
$ ~/monitor/bin/monitor site rotate-key site-a --pubkey <base64 de la nouvelle clé>
$ ~/monitor/bin/monitor site remove site-a
```

- La clé publique fait 32 octets (44 caractères en base64). Côté PHP :
  `$pair = sodium_crypto_sign_keypair()`, puis
  `base64_encode(sodium_crypto_sign_publickey($pair))`.
- `site add` refuse un site absent de la configuration ou qui a déjà une clé.
- `site rotate-key` remplace la clé : un rapport signé avec l'ancienne est
  refusé dès la rotation. La séquence repart de zéro, puisque l'ancienne clé ne
  peut plus rien faire accepter ; le silence reste mesuré depuis le dernier
  rapport accepté.
- `site remove` retire la clé et l'état des rapports, après confirmation (taper
  l'identifiant du site) ou avec `--yes`. Les incidents de l'agent sont clos au
  passage suivant de `tick`.
