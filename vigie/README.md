# vigie — veilleur multi-sites

Veilleur hébergé sur un VPS. Il surveille les sites de
l'extérieur, reçoit les rapports signés d'un agent PHP posé sur chaque site
(protocole : [`docs/protocole-agent.md`](./docs/protocole-agent.md), pose :
[`docs/agent-php.md`](./docs/agent-php.md)) et alerte par e-mail.
Les décisions de produit sont consignées dans
[`docs/decisions.md`](./docs/decisions.md).

Ce dossier est indépendant du module PrestaShop `sc_alwaysdata` à la racine du
dépôt : il n'entre ni dans son déploiement (`scripts/deploy.mjs`), ni dans une
archive du module (`.gitattributes`, `export-ignore`).

## Commandes

Sur le veilleur, toujours appeler le binaire par son chemin complet.

| Commande | Rôle |
| -------- | ---- |
| `~/vigie/bin/vigie serve` | Service `vigie-serve` derrière Caddy : écoute sur `$IP:$PORT` (ou `--ip`, `--port`), `127.0.0.1:8080` dans l'unité. Routes : `GET /health`, `POST /r/v1/report` et l'API de la console `/api/v1` ; tout le reste renvoie 404 sans corps. Migre la base au démarrage |
| `~/vigie/bin/vigie tick` | Lancé chaque minute par `vigie-tick.timer` : lance les contrôles dus, ouvre ou clôt les incidents, envoie les e-mails |
| `~/vigie/bin/vigie check <site> --once` | Lance tous les contrôles d'un site et affiche les constats, sans écrire dans la base ni envoyer d'e-mail ; code 1 si un constat est à traiter |
| `~/vigie/bin/vigie status` | Dernier passage, sites et dernier contrôle, incidents ouverts avec leur âge, état de l'agent de chaque site, informations (en-têtes manquants), notifications en attente ; code 1 si `tick` est en retard |
| `~/vigie/bin/vigie site list` | Sites de la configuration, état de leur agent (sans agent, clé sans rapport, âge du dernier rapport accepté) et, en dernière colonne, leur runtime effectif (`-` sans runtime) |
| `~/vigie/bin/vigie commands init-keys` | Crée la clé de commandes et la clé d'audit de `[commands]` (jamais écrasées) et affiche la clé publique à épingler par les agents (`docs/protocole-commandes.md`) |
| `~/vigie/bin/vigie site commands <site> enable\|disable` | Kill-switch du canal de commandes d'un site, coupé par défaut |
| `~/vigie/bin/vigie site command <site> <commande> [--apply] [--force]` | Aperçu d'une commande, puis mise en file avec `--apply` |
| `~/vigie/bin/vigie site audit <site> [--verify --head <hash>]` | Journal d'audit des commandes, en JSONL, ou vérification de sa chaîne contre la tête reçue par e-mail |
| `~/vigie/bin/vigie site add <site> --pubkey <base64>` | Enregistre la clé publique Ed25519 (32 octets) de l'agent d'un site de la configuration ; refusé si le site a déjà une clé ou n'a pas le runtime effectif `php` |
| `~/vigie/bin/vigie site rotate-key <site> --pubkey <base64>` | Remplace la clé : un rapport signé par l'ancienne est refusé dès maintenant |
| `~/vigie/bin/vigie site accept <site>` | Prend les empreintes du dernier rapport comme référence et clôt les incidents d'intégrité : à lancer après une modification voulue d'un fichier critique |
| `~/vigie/bin/vigie site remove <site> [--yes]` | Retire la clé, l'état des rapports et la référence des empreintes ; sans `--yes`, demande de retaper l'identifiant |
| `~/vigie/bin/vigie ack <id>` | Acquitte un incident : plus de rappel, la clôture automatique reste active |
| `~/vigie/bin/vigie device pair --name <nom>` | Crée un code d'appairage de la console, valable 10 min et une seule fois : l'affiche en QR code (terminal à fond sombre) et en lien `vigie://pair` ; exige la section `[api]` |
| `~/vigie/bin/vigie device list` | Appareils (actif, vu il y a…, révoqué) et codes en attente, sans aucun secret |
| `~/vigie/bin/vigie device revoke <id>` | Révoque un appareil : son jeton est refusé dès la requête suivante |
| `~/vigie/bin/vigie test-alert` | Envoie un e-mail de test par le relais SMTP configuré |

`/health` répond 200 si le dernier `tick` date de moins de 3 minutes, sinon 503.
Routes de l'API de la console, toutes sauf `pair` derrière `Authorization: Bearer <jeton>` :

| Route | Rôle |
| ----- | ---- |
| `POST /api/v1/pair` | Échange un code d'appairage contre le jeton de l'appareil |
| `GET /api/v1/overview` | Sites triés par état (non conforme, aveugle, à vérifier, première lecture, OK), constat le plus grave, dernière lecture |
| `GET /api/v1/sites/{id}` | Incidents ouverts, contrôles avec leur dernier résultat, relevé de l'agent |
| `GET /api/v1/sites/{id}/incidents` | Incidents fermés depuis 30 jours |
| `GET /api/v1/incidents/{id}` | Détail d'un incident, avec les dates d'envoi des e-mails |
| `POST /api/v1/incidents/{id}/ack` | Comme `vigie ack` ; 409 si l'incident est fermé |
| `GET /api/v1/settings` | Sites et fréquences, destinataire masqué, appareils |
| `DELETE /api/v1/devices/self` | L'appareil appelant se révoque (204) |

Schémas JSON, état d'un site et codes de réponse : [`docs/api-console.md`](./docs/api-console.md).

## Rapports des agents

`POST /r/v1/report` accepte au plus 64 Ko de corps, lu en 10 s au plus. Les
vérifications suivent l'ordre taille, site connu, signature, schéma,
horodatage (±300 s), `seq` strictement croissant, un rapport par minute et par
site. Un rapport accepté reçoit 204 ; tout refus reçoit le même 404 sans corps,
et la raison n'est écrite que dans le journal de `serve` (site, `seq`, raison,
jamais le corps).

Les constats d'un rapport accepté passent dans le cycle des incidents sous des
contrôles préfixés `agent:`. `serve` n'envoie aucun e-mail : c'est le `tick`
suivant qui notifie. Un site dont l'agent a une clé et ne fait accepter aucun
rapport pendant `agent_silence` secondes (900 par défaut) ouvre un incident
critique `heartbeat`, clos par le rapport accepté suivant.

L'agent ne garde aucun état : c'est le veilleur qui voit une dérive. Le premier
rapport qui porte des empreintes (`files`) pose la référence du site ; ensuite,
un fichier critique dont l'empreinte diffère ouvre un avertissement
`agent:integrity`, maintenu tant que le fichier diffère et jusqu'à
`site accept`. Un chemin nouveau entre dans la référence sans constat. Le
contrôle `integrity` est réservé au veilleur : un rapport qui l'envoie est
refusé.

## Contrôles

Vus de l'extérieur, par un agent HTTP unique : 10 s par requête, 2 Mo de corps
au plus, User-Agent `vigie/<version>`, redirections limitées à l'hôte du site.

| Contrôle | Constat |
| -------- | ------- |
| `content` | Critique si `keyword_url` (sinon `url`) ne répond pas 200 ou ne contient pas `keyword` |
| `installer` | Critique si `wp-admin/install.php` ou `wp-admin/setup-config.php` (WordPress), ou `/install/` (PrestaShop), sert un formulaire d'installation |
| `exposed` | Critique si `.env`, `.git/HEAD`, une sauvegarde de `wp-config.php` ou un dump SQL courant est servi. Une URL témoin aléatoire est interrogée d'abord : une réponse identique au témoin, ou sans la signature attendue, n'est pas un constat |
| `tls` | Avertissement à moins de 14 jours de l'expiration, critique à moins de 3 jours ou si le nom n'est pas couvert |
| `headers` | Information : HSTS, `X-Content-Type-Options`, `X-Frame-Options` ou `frame-ancestors`. Montré dans `status`, jamais envoyé par e-mail |

Un site injoignable donne un seul constat `unreachable` : les autres contrôles
du passage ne sont pas lancés, pour ne pas produire de constats fantômes.
Chaque contrôle attend son intervalle (`interval`, 300 s par défaut, `tls` et
`headers` une fois par heure). Les contrôles s'arrêtent après 40 s et les
envois après 50 s : le reste passe au tick suivant.

Un constat stable (`site/contrôle/clé`) ouvre un incident et déclenche un seul
e-mail ; sa disparition clôt l'incident et envoie un e-mail de retour à la
normale. Un incident ouvert et non acquitté est rappelé une fois par jour. Un
envoi qui échoue reste en attente et repart au passage suivant.

## Configuration

`~/vigie/config.toml`, sur le veilleur seulement : voir
[`config.example.toml`](./config.example.toml). Le fichier est pris dans
`--config`, sinon dans `$VIGIE_CONFIG`, sinon dans `~/vigie/config.toml`.
Une clé inconnue, un chemin relatif ou un identifiant invalide sont refusés avec
le code de retour 2.

Le mot de passe SMTP n'est pas dans `config.toml` : il est lu au moment de
l'envoi dans le fichier `password_file`. L'envoi est refusé, avant toute
connexion, si ce fichier est lisible par le groupe ou par les autres, ou s'il
appartient à un autre utilisateur. Le mot de passe n'apparaît dans aucun log ni
dans aucune erreur.

La section `[api]`, facultative, donne `public_url`, l'adresse publique du
veilleur telle que la console l'appelle : en https, http n'étant admis que sur
la boucle locale. Elle entre dans le lien d'appairage ; sans elle,
`device pair` est refusé.

## Développement

```powershell
cd vigie
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

`tests/external_checks.rs` sert les fixtures de `tests/fixtures/` en HTTPS
local, avec une autorité de certification de test, et remplace l'envoi SMTP
par un notifier en mémoire : aucun site réel n'est contacté, aucun e-mail
n'est envoyé. `tests/ingest.rs` signe des rapports avec une clé de test et
vérifie les vecteurs Ed25519 de la RFC 8032 (`tests/fixtures/rfc8032.json`).
`tests/interop.rs` vérifie qu'un rapport signé par l'agent PHP (sodium) est
accepté tel quel par ed25519-dalek et par l'ingestion.

L'agent PHP a ses propres tests, sans Composer, sur les arborescences de
`agent/php/tests/fixtures/` (sodium requis, PHP 8.1 au moins) :

```powershell
php -d extension=sodium vigie/agent/php/tests/run.php
# Après une modification du format du rapport : régénérer la fixture d'interopérabilité
php -d extension=sodium vigie/agent/php/tests/make-interop-fixture.php
```

La reprise de l'incident du 2026-09-07 (promesse : alerte sous 10 min) se
rejoue en heure logique par `tests/replay_2026_09_07.rs`, et en processus réels
(`vigie serve`, agent PHP, `tick` chaque minute) par
`node vigie/scripts/replay-incident.mjs`, en 12 à 15 min. Procédure et
résultats datés : [`docs/reception.md`](./docs/reception.md).

Sous Windows, l'antivirus peut mettre en quarantaine un fichier de test qui
ressemble à un webshell (« Failed to open stream: Invalid argument ») : les
fixtures ne contiennent que du PHP anodin.

La version de Rust est épinglée à trois endroits, à garder identiques :
`rust-toolchain.toml`, `rust-version` dans `Cargo.toml` et
`.github/workflows/vigie.yml`.

## Déploiement

Prérequis dans WSL : rustup avec la cible `x86_64-unknown-linux-musl`, zig et
`cargo-zigbuild` (voir [`docs/hebergement.md`](./docs/hebergement.md)). Sur le
VPS : une fois, `deploy/provision.sh` en root (utilisateur `vigie`, unités
systemd, Caddy, pare-feu).

```powershell
copy vigie\deploy\targets.example.json vigie\deploy\targets.json   # ignoré par git
node vigie/scripts/deploy.mjs veilleur --check    # build et validations locales
node vigie/scripts/deploy.mjs veilleur            # prévisualisation, aucune écriture
node vigie/scripts/deploy.mjs veilleur --apply    # envoi, bascule atomique, redémarrage de serve
```

Garde-fous : seul le contenu du commit est compilé, branche `main` exigée (sauf
`--any-branch`), clé SSH dédiée en `BatchMode`, verrou `~/vigie/deploy.lock`,
binaire vérifié (sha256 et `--version`) avant la bascule, ancien binaire conservé
en `vigie.prev`. Le script affiche la commande de retour arrière.

Après la bascule, le script redémarre `serve` par la seule règle sudo de
l'utilisateur `vigie` ; `tick` prend le nouveau binaire au passage suivant du
timer.

L'agent PHP se déploie de la même façon sur le compte SSH de chaque site, dans
`~/vigie-agent/` (jamais sous `~/www`, refusé avant et après résolution des
liens) :

```powershell
node vigie/scripts/deploy-agent.mjs site-a-agent --check    # php -l local si PHP est disponible
node vigie/scripts/deploy-agent.mjs site-a-agent            # prévisualisation, compare les sha256
node vigie/scripts/deploy-agent.mjs site-a-agent --apply    # envoi, php -l distant, bascule atomique
```

Le script ne touche ni à la configuration ni à la clé de l'agent : la pose
complète est décrite dans [`docs/agent-php.md`](./docs/agent-php.md).
