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
| `~/monitor/bin/monitor tick` | Lancé chaque minute par `monitor-tick.timer` : enregistre le passage (contrôles en phase 2) |
| `~/monitor/bin/monitor status` | Dernier passage et version du schéma ; code 1 si `tick` est en retard |
| `~/monitor/bin/monitor site list` | Sites de la configuration |
| `~/monitor/bin/monitor ack <id>` | Acquitte un incident (incidents en phase 2) |

`/health` répond 200 si le dernier `tick` date de moins de 3 minutes, sinon 503.

## Configuration

`~/monitor/config.toml`, sur le veilleur seulement : voir
[`config.example.toml`](./config.example.toml). Le fichier est pris dans
`--config`, sinon dans `$MONITOR_CONFIG`, sinon dans `~/monitor/config.toml`.
Une clé inconnue, un chemin relatif ou un identifiant invalide sont refusés avec
le code de retour 2.

## Développement

```powershell
cd monitor
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

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
