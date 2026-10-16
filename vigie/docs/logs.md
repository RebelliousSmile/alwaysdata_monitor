# Contrat de l'analyse de logs

Ce document fixe ce qui sépare l'**acquisition** des logs, propre à chaque
serveur, de leur **analyse**, invariante (issue #7). Ajouter un type de serveur,
c'est écrire un adaptateur et une fixture, sans toucher une ligne de
l'analyseur (#8). Le code : `src/logs/`. Les tests : `src/logs/tests.rs`,
`tests/logs_contract.rs`, `tests/fixtures/logs/`.

## Modèle

Le veilleur ne va jamais chercher les logs chez un hébergeur : aucun accès FTP
ou API n'est stocké (`decisions.md`). Seul l'agent du site peut lire ses logs.
Il les pousse au veilleur dans des requêtes signées (transport décrit par #1).

```text
agent (site)                        veilleur
fichier de l'hébergeur ──lignes──▶  lots reçus et stockés
  position d'octet : côté agent      │
                                     ▼
                       adaptateur : LogSource (curseur du veilleur)
                         découpeur → RawFields → normalize → Entry
                                     ▼
                       analyseur (#8) : ne voit que des Entry
```

- **Règle de coupe de l'agent** : chaque ligne est coupée à 16 Kio, en gardant
  le début, avant envoi. Le statut tombe avant la coupe dans tous les cas
  réalistes (`LimitRequestLine` d'Apache vaut 8190 octets) ; sinon la ligne
  est rejetée `malformed` et comptée.
- **Côté veilleur**, `MAX_LINE` (4 Mio) n'est qu'une borne défensive.

## `Entry`

| Champ | Type | Règle |
| --- | --- | --- |
| `timestamp_ms` | `i64` | millisecondes UTC |
| `host` | `Option<String>` | hôte demandé, minuscules, sans port ni point final, 253 octets au plus |
| `ip` | `Option<IpAddr>` | client tel que le serveur l'a vu ; `-` ou illisible → `None` ; jamais tiré d'un en-tête (`X-Forwarded-For`) |
| `method` | `Option<String>` | majuscules ASCII, 1 à 16 ; sinon `None`, la cible étant gardée (`get /.env` est un signal) |
| `path` | `String` | cible sans query string, **ni décodée ni normalisée** (`%2e`, `//`, `..` restent tels quels), 2048 octets au plus |
| `query_keys` | `Vec<String>` | clés de la query string, dans l'ordre, sans doublon, 16 au plus ; **jamais les valeurs** |
| `status` | `u16` | 100 à 599, sinon la ligne est rejetée |
| `size` | `Option<u64>` | `-` → `None` |
| `referer_present` | `bool` | referer ni vide ni `-` |
| `referer_host` | `Option<String>` | hôte du referer seulement, normalisé comme `host`, identifiants retirés |
| `user_agent` | `String` | 512 octets au plus |
| `duration_us` | `Option<u64>` | durée de service (format « Advanced » d'Alwaysdata), en µs |

Tout texte est de l'UTF-8 valide : les octets invalides deviennent U+FFFD, et
une troncature coupe au dernier caractère entier.

### RGPD

Décision du 2026-10-16 : les query strings sont masquées dès l'analyse. Seules
leurs clés passent, et seulement une clé de 1 à 32 caractères parmi
`[A-Za-z0-9_.-]` et `[]`, suivie de `=`. Tout autre paramètre (sans `=`, clé
longue ou exotique, qui peut être un jeton) est remplacé une fois par la
marque `?`. Le referer est réduit à son hôte. La conservation est de 30 jours
(#1).

## Horodatage et fuseau

- Un décalage écrit dans la ligne (`+0200`) l'emporte.
- Sans décalage, le fuseau IANA déclaré pour la source (base tz embarquée par
  `jiff`). Changements d'heure : au recul, la plus tôt des deux heures ; dans le
  trou d'une avance, l'heure décalée d'autant après le trou.
- Sans décalage ni fuseau : rejet `timestamp`. Années hors 1970 à 9999 : rejet
  `timestamp`.
- Une entrée datée de plus d'un jour après l'heure du veilleur (horloge
  injectée, `clock.rs`) est rejetée `future`. Aucun ordre n'est garanti entre
  entrées : un recul est normal (rotation, requêtes longues).

## Rejets

Une ligne rejetée ne bloque jamais le lot : elle est comptée par motif
(`too_long`, `malformed`, `timestamp`, `future`, `status`).

## Découpeur Apache combined

`logs::combined::split` lit `[hôte] ip ident user [date] "requête" statut
taille "referer" "user-agent" [queue…]` :

- l'hôte en tête est repéré par la forme des jetons : si le premier est une IP
  ou `-`, pas d'hôte ; sinon, si le deuxième l'est, le premier est l'hôte ;
- l'utilisateur prend tout jusqu'au `[` de la date (il peut contenir une
  espace) et n'est jamais rendu ;
- `\"` et `\\` ne ferment pas un champ entre guillemets ; les échappements
  restent dans les octets rendus ;
- une ligne coupée après le statut reste valide : un guillemet non fermé se
  clôt en fin de ligne ;
- en queue, un dernier jeton décimal est la durée en secondes.

## `LogSource`

```rust
pub trait LogSource: Send + Sync {
    fn id(&self) -> &str;
    fn fetch<'a>(&'a self, from: &'a Cursor, max_entries: usize)
        -> BoxFuture<'a, Result<Fetched, SourceError>>;
}
```

- Dyn-compatible : un registre est un `Vec<Box<dyn LogSource>>`.
- `Fetched { entries, rejected, next, more }` : `max_entries` entrées
  possédées au plus, rejets par motif, curseur suivant, et `more` s'il en
  reste.
- `Cursor` est opaque, propre à l'adaptateur ; le veilleur le persiste sans
  l'interpréter.
- `SourceError::CursorInvalid { restart }` : la position ne vaut plus rien
  (rotation, fichier remplacé), reprendre à `restart`. Les autres erreurs
  sont `Unavailable`, `Corrupt` et `Internal`.
- L'appelant persiste les entrées d'un lot et le curseur suivant dans une même
  transaction `IMMEDIATE`. Chaque entrée est ainsi vue une fois par curseur,
  **côté veilleur**. Un lot renvoyé par l'agent après une réponse perdue arrive
  deux fois : #1 le déduplique par son identité (fichier, offset de début).
  Un hash de ligne ne convient pas : il fusionnerait deux requêtes identiques
  dans la même seconde.
- `MemorySource` sert des entrées en mémoire aux tests de #8 et #13.

## Ajouter un type de serveur

1. Un adaptateur qui découpe sa ligne en `RawFields` (ou réutilise
   `combined::split`) et implémente `LogSource`.
2. Une fixture synthétique dans `tests/fixtures/logs/`, avec des IP des plages
   de documentation et des hôtes `example.org`.
3. Son entrée dans `expected.json` (fuseau, lignes, acceptées, rejets par
   motif), que `tests/logs_contract.rs` vérifie.
