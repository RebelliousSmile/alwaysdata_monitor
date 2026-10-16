# API de la console, version 1

La console (application Windows et Android) lit l'état du veilleur par
`/api/v1`. Chaque installation de la console est un **appareil** : elle reçoit
un jeton qui lui est propre, une seule fois, en échange d'un code d'appairage
créé sur le VPS. Le veilleur ne garde que l'empreinte SHA-256 des jetons et
des codes : ni l'un ni l'autre n'est écrit en clair, en base comme au journal.

Ce document est le contrat. `vigie/src/device.rs`, `vigie/src/api.rs`,
`vigie/tests/api_auth.rs` et `vigie/tests/cli.rs` en reprennent chaque règle.

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
est refusé sans être haché. La date « vu le » de l'appareil est mise à jour au
plus une fois par minute ; son échec n'est que journalisé, la requête passe.

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

| Route | Authentification | Réponse |
| ----- | ---------------- | ------- |
| `POST /api/v1/pair` | code dans le corps | `{token, device_id, name}` |
| `GET /api/v1/overview` | Bearer | `{server_time, last_tick}` (secondes Unix ; `last_tick` vaut `null` sans aucun tick) |

## Codes de réponse

| Code | Cas |
| ---- | --- |
| 200 | Succès, avec `Cache-Control: no-store`. |
| 401 | Code inconnu, expiré, déjà utilisé, corps illisible, trop gros ou trop lent ; jeton absent, mal formé, inconnu ou révoqué ; base absente ou pas encore migrée. **Corps vide**, quelle qu'en soit la raison : le journal du veilleur seul dit laquelle. |
| 404 | Route ou méthode inconnue, corps vide (le même 404 que le reste du veilleur). |
| 500 | Erreur interne (base illisible, tirage aléatoire impossible), corps vide. |

## Base de données

L'API ne crée jamais la base et ne la migre pas : `vigie serve` applique les
migrations au démarrage, `vigie device pair` aussi. Tant que la base est
absente ou antérieure au schéma 5, toute requête reçoit 401.
