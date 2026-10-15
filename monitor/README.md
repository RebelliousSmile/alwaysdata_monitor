# monitor — veilleur multi-sites

Veilleur hébergé sur un VPS (nom provisoire). Il surveille les sites de
l'extérieur et, à partir de la phase 3, reçoit les rapports signés d'un agent
PHP posé sur chaque site. Il alerte par e-mail.

Ce dossier est indépendant du module PrestaShop `sc_alwaysdata` à la racine du
dépôt : il n'entre ni dans son déploiement (`scripts/deploy.mjs`), ni dans une
archive du module (`.gitattributes`, `export-ignore`).

## Commandes

Sur le veilleur, toujours appeler le binaire par son chemin complet.

| Commande | Rôle |
| -------- | ---- |
| `~/monitor/bin/monitor serve` | Service `monitor-serve` derrière Caddy : écoute sur `$IP:$PORT` (ou `--ip`, `--port`), `127.0.0.1:8080` dans l'unité. Seule la route `/health` répond ; tout le reste renvoie 404 sans corps |
| `~/monitor/bin/monitor tick` | Lancé chaque minute par `monitor-tick.timer` : lance les contrôles dus, ouvre ou clôt les incidents, envoie les e-mails |
| `~/monitor/bin/monitor check <site> --once` | Lance tous les contrôles d'un site et affiche les constats, sans écrire dans la base ni envoyer d'e-mail ; code 1 si un constat est à traiter |
| `~/monitor/bin/monitor status` | Dernier passage, sites et dernier contrôle, incidents ouverts avec leur âge, en-têtes manquants, notifications en attente ; code 1 si `tick` est en retard |
| `~/monitor/bin/monitor site list` | Sites de la configuration |
| `~/monitor/bin/monitor ack <id>` | Acquitte un incident : plus de rappel, la clôture automatique reste active |
| `~/monitor/bin/monitor test-alert` | Envoie un e-mail de test par le relais SMTP configuré |

`/health` répond 200 si le dernier `tick` date de moins de 3 minutes, sinon 503.

## Contrôles

Vus de l'extérieur, par un agent HTTP unique : 10 s par requête, 2 Mo de corps
au plus, User-Agent `monitor/<version>`, redirections limitées à l'hôte du site.

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

`~/monitor/config.toml`, sur le veilleur seulement : voir
[`config.example.toml`](./config.example.toml). Le fichier est pris dans
`--config`, sinon dans `$MONITOR_CONFIG`, sinon dans `~/monitor/config.toml`.
Une clé inconnue, un chemin relatif ou un identifiant invalide sont refusés avec
le code de retour 2.

Le mot de passe SMTP n'est pas dans `config.toml` : il est lu au moment de
l'envoi dans le fichier `password_file`. L'envoi est refusé, avant toute
connexion, si ce fichier est lisible par le groupe ou par les autres, ou s'il
appartient à un autre utilisateur. Le mot de passe n'apparaît dans aucun log ni
dans aucune erreur.

## Développement

```powershell
cd monitor
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

`tests/external_checks.rs` sert les fixtures de `tests/fixtures/` en HTTPS
local, avec une autorité de certification de test, et remplace l'envoi SMTP
par un notifier en mémoire : aucun site réel n'est contacté, aucun e-mail
n'est envoyé.

La version de Rust est épinglée à trois endroits, à garder identiques :
`rust-toolchain.toml`, `rust-version` dans `Cargo.toml` et
`.github/workflows/monitor.yml`.

## Déploiement

Prérequis dans WSL : rustup avec la cible `x86_64-unknown-linux-musl`, zig et
`cargo-zigbuild` (voir [`docs/hebergement.md`](./docs/hebergement.md)). Sur le
VPS : une fois, `deploy/provision.sh` en root (utilisateur `monitor`, unités
systemd, Caddy, pare-feu).

```powershell
copy monitor\deploy\targets.example.json monitor\deploy\targets.json   # ignoré par git
node monitor/scripts/deploy.mjs veilleur --check    # build et validations locales
node monitor/scripts/deploy.mjs veilleur            # prévisualisation, aucune écriture
node monitor/scripts/deploy.mjs veilleur --apply    # envoi, bascule atomique, redémarrage de serve
```

Garde-fous : seul le contenu du commit est compilé, branche `main` exigée (sauf
`--any-branch`), clé SSH dédiée en `BatchMode`, verrou `~/monitor/deploy.lock`,
binaire vérifié (sha256 et `--version`) avant la bascule, ancien binaire conservé
en `monitor.prev`. Le script affiche la commande de retour arrière.

Après la bascule, le script redémarre `serve` par la seule règle sudo de
l'utilisateur `monitor` ; `tick` prend le nouveau binaire au passage suivant du
timer.
