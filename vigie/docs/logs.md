# Contrat de l'analyse de logs

Ce document fixe ce qui sépare l'**acquisition** des logs, propre à chaque
serveur, de leur **analyse**, invariante (issue #7). Ajouter un type de serveur,
c'est écrire un adaptateur et une fixture, sans toucher une ligne de
l'analyseur (#8). Le code : `src/logs/`. Les tests : `src/logs/tests.rs`,
`tests/logs_contract.rs`, `tests/logs_receive.rs`, `tests/fixtures/logs/`.
Le premier adaptateur, Alwaysdata (#1), est décrit plus bas :
[Transport Alwaysdata](#transport-alwaysdata-issue-1).

## Modèle

Le veilleur ne va jamais chercher les logs chez un hébergeur : aucun accès FTP
ou API n'est stocké (`decisions.md`). Seul l'agent du site peut lire ses logs.
Il les pousse au veilleur dans des requêtes signées (`POST /r/v1/logs`,
ci-dessous).

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
(#1) : voir [Conservation](#conservation).

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
  deux fois : #1 le déduplique par son identité (fichier, génération, plage
  lue), voir [Idempotence](#idempotence). Un hash de ligne ne convient pas :
  il fusionnerait deux requêtes identiques dans la même seconde.
- `MemorySource` sert des entrées en mémoire aux tests de #8 et #13.

## Ajouter un type de serveur

1. Un adaptateur qui découpe sa ligne en `RawFields` (ou réutilise
   `combined::split`) et implémente `LogSource`.
2. Une fixture synthétique dans `tests/fixtures/logs/`, avec des IP des plages
   de documentation et des hôtes `example.org`.
3. Son entrée dans `expected.json` (fuseau, lignes, acceptées, rejets par
   motif), que `tests/logs_contract.rs` vérifie.

## Transport Alwaysdata (issue #1)

Code : agent `agent/php/vigie-agent.php` (section `logs`), veilleur
`src/logs/receive.rs`, `src/logs/alwaysdata.rs`. Configuration de l'agent :
`agent-php.md`, « Logs HTTP ».

### Ce que lit l'agent

Alwaysdata écrit le log HTTP de tout le compte dans
`admin/logs/http/<année>/http-<AAAA-MM-JJ>.log`, puis le compresse en
`.log.gz`. L'agent (`logs.dir` = ce dossier `http`) :

- liste `<année courante>/` et `<année précédente>/`, ignore les fichiers
  datés (par leur nom) de plus de 30 jours, et lit par ordre de nom à partir
  du fichier de sa position : ni calcul de jour, ni fuseau, ni `mtime` ;
- garde sa position dans `logs.json` (dossier de l'agent, 0700, fichier
  0600 vérifié, écriture par fichier temporaire et `rename`), sous `flock`
  non bloquant de `logs.lock` ; il lit les logs **après** le rapport et le
  retrait ;
- ne garde que les lignes dont l'hôte (premier jeton, minuscules, sans port)
  figure dans `logs.hosts` ; une ligne sans hôte lisible est écartée ;
- lit par `fgets` de 16 Kio : une ligne plus longue part coupée (son début
  suivi de `\n`), la suite est jetée jusqu'au `\n` ;
- ferme un lot à 44 Kio gardés, ou quand la plage lue atteint 4 Mio (moins une
  ligne), ou si le corps signé dépasserait 64 Kio ; 20 lots et 20 s au plus
  par passage.

Fichier **ouvert** : seules les lignes entières partent. Un fichier est
**clos** s'il n'existe plus qu'en `.gz`, ou une heure après que l'agent a vu
pour la première fois un fichier plus récent (`next_seen_at`, heure de
l'agent : PHP n'a pas de date de création). Dans un fichier clos, une
dernière ligne sans fin de ligne part telle quelle, puis l'agent passe au
suivant. Une ligne qu'Alwaysdata écrirait encore dans un fichier clos est
perdue.

Le fichier de la position introuvable (purgé, trop ancien) ou un `.gz` plus
court que la position (archive tronquée) : fichier suivant, compté dans
`skipped_files` du lot suivant et journalisé par le veilleur. Un `.gz` est
ouvert une fois par passage ; l'avance jusqu'à la position compte dans les
20 s.

### Identité d'un lot

| Champ | Règle |
| --- | --- |
| `v`, `type` | `1`, `"logs"` |
| `site`, `seq`, `sent_at`, `agent` | comme un rapport ; `seq` propre aux logs, `max(seq + 1, heure en ms)`, persisté par l'agent |
| `file` | `http-AAAA-MM-JJ.log`, sans chemin ni `.gz` |
| `gen` | génération du fichier, entier ≥ 0 |
| `start`, `end` | positions du fichier **non compressé** lues : `start < end`, `end − start ≤ 4 Mio` |
| `skipped_files` | fichiers sautés depuis le dernier lot, 0 à 1000, hors de l'identité |
| `chunk` | base64 standard des lignes **gardées** (filtrées, coupées), `≤ end − start` octets ; vide si la plage ne contient que d'autres hôtes |

Base64 parce que `json_encode` échoue sur l'UTF-8 invalide d'une ligne
hostile. Signature : clé de rapport de l'agent, sur `vigie-logs-v1\n` +
octets du corps ; un rapport envoyé sur `/r/v1/logs`, ou un lot sur
`/r/v1/report`, échoue à la signature.

**Génération.** `logs.json` garde, pour le fichier de la position, sa forme
(`.log` ou `.gz`), son inode et l'empreinte SHA-256 de ses `head_len`
premiers octets (256 au plus, décompressés pour un `.gz`, élargis dès que le
fichier grandit). Empreinte différente, inode différent entre deux lectures
de même forme, ou `.log` plus court que la position : fichier remplacé,
`gen + 1`, position 0, lot en attente abandonné. Le passage `.log` → `.gz`
garde la génération et la position si l'empreinte concorde : la compression
ne fait rien relire. Sans `logs.json` (premier passage, état perdu), l'agent
part du début du fichier le plus récent avec `gen` = son heure en ms : au pire
ce fichier est relu une fois, jamais absorbé par une ancienne limite haute.
Un nouveau fichier commence en génération 0.

### Acceptation

`POST /r/v1/logs`, mêmes limites que `/r/v1/report` (64 Ko, 10 s), 404 muet
sur tout refus, raison au journal avec le `request_id`. Dans l'ordre : site
de la configuration (lue au démarrage de `serve`) avec `[sites.logs] source`
et une clé ; signature ; schéma strict ; horloge ±300 s ; puis, en une
transaction `IMMEDIATE` : clé inchangée, `seq` strictement supérieur à
`last_logs_seq`, limite haute, plafond quotidien.

### Idempotence

Le veilleur tient, par `(site, file, gen)`, la limite haute : la fin du
dernier lot accepté (`log_marks.high`, et `received_at`).

- `end ≤ limite` : déjà reçu, **204** sans rien écrire que le `seq` ;
- `start ≥ limite` : accepté ; un trou (`start > limite`) est admis et
  compté (`log_batches.gap`) ;
- sinon (à cheval) : refus.

Côté agent, un lot est écrit `pending {file, gen, start, end}` dans
`logs.json` **avant** l'envoi ; la position n'avance qu'après un 204. Au
passage suivant, la plage en attente est relue et renvoyée à l'identique (le
fichier ne fait que grandir) ; si elle ne se relit plus à l'identique, le
fichier a été remplacé (`gen + 1`). Un agent qui a perdu la réponse renvoie
donc le même lot, compté une fois, et ne peut pas se bloquer sur un lot « à
cheval ».

### Stockage

Le veilleur découpe (`combined::split`) et normalise (`normalize`, fuseau
`[sites.logs] tz` facultatif) chaque ligne à la réception et n'écrit que des
`Entry` dans `log_entries` : les octets reçus, les valeurs de query string,
l'utilisateur et le referer complet n'existent jamais en base. Rejets
comptés par lot (`log_batches.rejected`) : ceux de `normalize`, plus
`too_old` (entrée de plus de 30 jours) et `host` (sans hôte, ou hôte hors
`[sites.logs] hosts` : défense en profondeur après le filtre de l'agent).

- Plafond : 50 Mo de `chunk` par site et par jour UTC de réception ; au-delà,
  refus. L'agent prend alors du retard, rattrapé les jours suivants.
- Un lot accepté ne vaut ni rapport ni preuve de vie (`reports` inchangé).
- `site rotate-key` (et la commande `rotate-key`) remet `last_logs_seq` à 0.

### `AlwaysdataSource`

`LogSource` sur `log_entries` d'un site : `WHERE site = ? AND id > ? ORDER BY
id LIMIT max + 1` (`more` s'il y en a une de plus). Curseur : dernier id
servi, en décimal ; illisible → `CursorInvalid { restart: start }`.
`rejected` est vide (les rejets restent dans `log_batches`). L'ordre des id
est l'ordre d'arrivée, **pas celui du temps** : un retard rattrapé arrive
après des entrées plus récentes. `id` est en `AUTOINCREMENT` : après une
purge totale, aucun id n'est redonné sous un curseur déjà rendu.

### Conservation

Chaque `tick` purge les entrées dont l'heure est antérieure à `now − 30 j`, et
les lots et limites hautes reçus avant (`received_at`). `site remove` purge
les entrées, lots et limites du site. Une limite haute purgée ne gêne pas :
l'agent ignore les fichiers de plus de 30 jours.
