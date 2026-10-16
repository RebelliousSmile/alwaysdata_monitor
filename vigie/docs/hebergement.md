# Hébergement du veilleur sur un VPS

Constats de la reconnaissance (phase 1). Chaque ligne cite la commande et sa
sortie. Les noms d'hôtes, de comptes et le sous-domaine sont masqués : le dépôt
est public.

## Statut

| Point | État |
| ----- | ---- |
| VPS du veilleur | Hetzner CX23, Ubuntu 26.04.1 LTS, x86_64, Helsinki : **créé** le 2026-10-15, pare-feu Hetzner (22, 80, 443, ICMP) attaché |
| Installation | `deploy/provision.sh` **lancé** le 2026-10-15 : sshd par clé seulement (`sshd -T`), mot de passe refusé (`Permission denied (publickey)`), `ufw` actif sur 22, 80 et 443, `monitor` en 0700 hors sudo sauf `systemctl restart monitor-serve.service` (`stop caddy` refusé), certificat Let's Encrypt obtenu par Caddy, `serve` ignoré faute de binaire (`/health` en 502) |
| Relevé système du VPS | **Fait** le 2026-10-16 en `vigie` (voir [VPS du veilleur](#vps-du-veilleur)) : `x86_64`, glibc 2.43, `/home/vigie` en `ext4` sur disque local, seuls 22, 80 et 443 en écoute publique, `serve` sur `127.0.0.1:8080`. `ufw status` et les processus de `ss -ltnp` demandent root : à relever |
| SMTP authentifié sur 587 vers le relais Alwaysdata | **Fait** le 2026-10-15 depuis le VPS : STARTTLS exigé (`--ssl-reqd`), authentification par la boîte d'alerte, code SMTP 250, message reçu par le destinataire ; les relais `smtp-<compte>.alwaysdata.net` de deux comptes résolvent vers la même adresse (relais communs, l'authentification se fait par la boîte et non par le compte) |
| Premier déploiement | **Fait** le 2026-10-15 : `monitor 0.1.0`, `/health` en 200 avec un tick postérieur à la bascule, route inconnue en 404 sans corps, HTTP redirigé en 308 vers HTTPS, `serve` sur `127.0.0.1:8080` seulement (8080 injoignable de l'extérieur), timer à la minute, base en 0600 dans `data/` |
| Contrôles externes et alertes (phase 2) | **Fait** le 2026-10-15 : `monitor 0.2.0` déployé (commit 2b55edd), `/health` en 200 ; `status` en code 0, schéma v2, dernier tick à 26 s, site A contrôlé, aucun incident, trois en-têtes manquants (HSTS, `nosniff`, `frame-ancestors`) en information ; `test-alert` reçu par le destinataire (envoyé à 16:35:26 UTC) ; `config.toml`, `smtp-password` et la base en 0600 au propriétaire `monitor` |
| Renommage en Vigie | **Fait** le 2026-10-15 : utilisateur `vigie` créé par `provision.sh`, `config.toml` (chemins réécrits), `smtp-password` et la base copiés vers `~vigie/vigie/` (base par `sqlite3 .backup`, `integrity_check` à `ok`, fichiers en 0600 au propriétaire `vigie`) ; `vigie 0.3.0` déployé (commit 208a73d), bascule à 20:23:38 UTC, base migrée en v4 au premier tick, `/health` en 200 avec un tick postérieur. Ancien `monitor` supprimé vers 20:47 UTC (unités, règle sudo, `10-monitor.conf` après `diff` identique à `10-vigie.conf`, utilisateur et dossier personnel) ; son dossier est archivé en 0600 dans `/root` |
| Arrêt de `deploy.mjs` pendant la preuve HTTP | **Contourné, cause non établie** : au déploiement de la 0.3.0, le processus a pris fin moins d'une seconde après « Preuve HTTP », pendant le premier `fetch`, sans message ni sur stdout ni sur stderr, et le `finally` du verrou n'a pas tourné (`deploy.lock` rendu à la main). Le déploiement lui-même avait abouti. Non reproduit le 2026-10-16 : la même suite (`wsl` synchrones, puis `fetch` de `/health` sortie en pipe) se termine en code 0. Depuis, le verrou est rendu avant la preuve HTTP, qui n'écrit rien, et un arrêt avant la fin affiche l'étape et le code. Au prochain `--apply` : sans pipe, et relever le code de sortie |
| Relance de `serve` après kill | **Fait** : `kill -9` du PID 3259, relancé en PID 3336 en moins de 8 s |
| Relance après reboot | **Fait** le 2026-10-15 (extinction puis rallumage depuis la console Hetzner) : démarrage à 15:52:12 UTC, `serve` actif à 15:52:11 en PID 1048, `caddy`, `ufw`, `ssh.socket` et le timer actifs, premier tick à 15:53:00, `/health` en 200, `status` en code 0, 8080 toujours injoignable de l'extérieur |
| Cloisonnement | **Fait côté `vigie`** le 2026-10-16 (voir [Cloisonnement](#cloisonnement)) : dossiers en 0700, secrets et base en 0600, une seule règle sudo, unités à 3.1 sur `systemd-analyze security`. Le test d'un autre utilisateur est sans objet tant que Hermes n'est pas installé ; il reste à le refaire en root avec `nobody` |
| sodium sur le site A | **Fait** le 2026-10-15 : PHP 8.3.35 en ligne de commande (`php -r 'echo PHP_VERSION;'`), `sodium` dans `php -m` ; le CLI affiche aussi `Warning: Module "intl" is already loaded` à chaque lancement |
| Sortie IPv4 et IPv6 du site A | **Fait** le 2026-10-15 : `curl -4` et `curl -6` vers un site externe en 200 depuis le compte du site A |
| `/health` en IPv4 et IPv6 depuis le poste | **Fait** le 2026-10-15 : `curl -4` et `curl -6` en 200 |

## Installation

Sur un VPS neuf, avec la clé root déposée à la commande :

```console
$ git archive -o vigie-deploy.tar --prefix=vigie-deploy/ HEAD:vigie/deploy
$ scp vigie-deploy.tar root@<vps>:/root/
$ ssh root@<vps> 'tar -xf /root/vigie-deploy.tar -C /root && sh /root/vigie-deploy/provision.sh "<clé publique ed25519 de déploiement>" <sous-domaine>'
```

`git archive` plutôt que `scp -r` : seul le contenu du commit part, pas le
`targets.json` local, ignoré par git. Avec `HEAD:vigie/deploy`, les chemins
perdent le préfixe `vigie/` et la règle `eol=lf` de la racine ne s'applique
plus : sous Windows, `core.autocrlf` passerait le script en CRLF
(`set: Illegal option -` sur le VPS). `vigie/deploy/.gitattributes` reprend
la règle à la racine de cet arbre ; il n'agit qu'une fois commité, `git
archive` lisant les règles du commit.

Le script est idempotent. Il installe `unattended-upgrades`, `ufw` (22, 80 et
443 seulement), Caddy, l'authentification SSH par clé seulement, l'utilisateur
`vigie` (sans mot de passe ni sudo général, dossier personnel en 0700), les
unités `vigie-serve.service`, `vigie-tick.service` et `vigie-tick.timer`,
et une règle sudo unique :

```text
vigie ALL=(root) NOPASSWD: /usr/bin/systemctl restart vigie-serve.service
```

Avant le premier déploiement, les conditions des unités (`bin/vigie`
exécutable, `config.toml` présent) les font ignorer au lieu d'échouer.

## VPS du veilleur

Relevé du 2026-10-16, en `vigie` :

```console
$ uname -m
x86_64
$ ldd --version | head -1
ldd (Ubuntu GLIBC 2.43-2ubuntu2.3) 2.43
$ grep -E '^PRETTY_NAME=' /etc/os-release
PRETTY_NAME="Ubuntu 26.04.1 LTS"
$ findmnt -no FSTYPE,SOURCE -T /home/vigie
ext4 /dev/sda1
$ df -h /home/vigie | tail -1      # 38G, 1.8G utilisés, 5 %
$ ss -ltn                          # en écoute
0.0.0.0:22, [::]:22, *:80, *:443   publics
127.0.0.1:8080                     serve
127.0.0.1:2019                     API d'administration de Caddy
127.0.0.53:53, 127.0.0.54:53       résolveur local
$ systemctl is-active vigie-serve.service vigie-tick.timer caddy ufw ssh.socket unattended-upgrades
active (×6)
$ ~/vigie/bin/vigie --version
vigie 0.3.0
```

`ufw status` et `ss -ltnp`, qui nomme les processus, demandent root.

Premier relevé, avant installation (2026-10-15) : `x86_64`, Ubuntu 26.04.1 LTS,
racine en `ext4`, `sudo-rs 0.2.13` (son `visudo` accepte `-c` et `-f`),
`ssh.socket` et `ssh.service` actifs, `ufw`, `curl` et `unattended-upgrades`
déjà présents.

Attendus : `x86_64`, `/home` sur un disque local (`ext4`), seuls
22, 80 et 443 en écoute publique, `serve` sur `127.0.0.1:8080` seulement.

Le disque est local : SQLite en WAL y est sûr, `serve` et `tick` partageant
le même hôte et la même base `~/vigie/data/vigie.db`.

## SMTP

Hetzner bloque par défaut les ports 25 et 465 en sortie ; le 587 reste ouvert.
Les alertes passent par le relais d'une boîte Alwaysdata existante
(`smtp-<compte>.alwaysdata.net`, port 587, STARTTLS, authentification). Une
boîte dédiée aux alertes est préférable : son mot de passe ne donne accès qu'à
elle.

Le mot de passe vit dans `~vigie/vigie/smtp-password` (0600, propriétaire
`vigie`), jamais dans `config.toml` ni dans le dépôt. `config.toml` le
désigne :

```toml
[alerts]
to = "<destinataire>"
from = "<adresse de la boîte d'alerte>"   # aussi l'identifiant SMTP
smtp_host = "smtp-<compte>.alwaysdata.net"
password_file = "/home/vigie/vigie/smtp-password"
```

`vigie` relit ce fichier à chaque envoi. Il refuse d'envoyer, sans ouvrir de
connexion, si le fichier est lisible par le groupe ou par les autres, ou s'il
n'appartient pas à `vigie`. STARTTLS est obligatoire : un relais qui ne le
propose pas fait échouer l'envoi. Les unités systemd montent `~/vigie` en
lecture seule, ce qui suffit puisque le fichier n'est que lu.

Après un changement de mot de passe ou de relais :

```console
$ ssh vigie@<vps> ~/vigie/bin/vigie test-alert
```

Envoi de test depuis le VPS (2026-10-15, code SMTP 250), sans mot de passe sur
la ligne de commande : le `netrc` est généré en 0600 dans un dossier temporaire
de `~/vigie`, à partir de `smtp-password`, puis supprimé ; pas de `-v`, qui
afficherait l'échange `AUTH` :

```console
$ curl --url smtp://smtp-<compte>.alwaysdata.net:587 --ssl-reqd \
    --netrc-file ~/vigie/smtp-netrc \
    --mail-from <expéditeur> --mail-rcpt <destinataire> --upload-file test.eml
```

## Cloisonnement

Le VPS peut aussi héberger Hermes Agent (voir `plan.md`, Décisions), à ces
conditions :

- Hermes tourne sous son propre utilisateur, sans sudo et hors du groupe
  `docker` ; ses commandes shell passent par un bac à sable ; son unité porte
  un `MemoryMax`.
- `vigie` a un dossier personnel en 0700 : Hermes ne lit ni la
  configuration, ni la base, ni le mot de passe SMTP.
- Les unités du veilleur sont durcies (`ProtectSystem=strict`,
  `ProtectHome=read-only`, seul `~/vigie/data` en écriture,
  `NoNewPrivileges`), et `serve` comme `tick` ont `OOMScoreAdjust=-500`.
- Si Hermes redevient inutilisé : le désinstaller et révoquer ses jetons.

Mesuré le 2026-10-16, en `vigie` :

- `/home/vigie`, `~/vigie` et `~/vigie/data` en 0700 ; `config.toml`,
  `smtp-password` et `vigie.db` en 0600, tous à `vigie:vigie` (`namei -l`
  confirme la chaîne depuis `/`).
- `id` : `vigie` dans les groupes `vigie` et `users` seulement. `sudo -n -l`
  ne liste que `(root) NOPASSWD: /usr/bin/systemctl restart vigie-serve.service`.
- Comptes avec un shell : `root`, `sync`, `vigie`. Pas de groupe `docker`,
  groupe `sudo` vide, pas d'utilisateur `hermes`.
- `systemd-analyze security` : `vigie-serve.service` et `vigie-tick.service`
  à 3.1 (`OK`).

La relance de `serve` après `kill` et après un reboot est consignée dans le
[Statut](#statut). Reste, en root : `sudo -u nobody cat
/home/vigie/vigie/config.toml` doit être refusé. Le même test avec `hermes`
attendra son installation.

## Plateforme du site A (Alwaysdata, 2026-10-15)

Relevé en lecture seule sur le compte SSH d'un site déjà hébergé sur
Alwaysdata. Il sert à l'agent PHP (phase 4) : les comptes d'une même plateforme
partagent l'image système, mais le relevé est à refaire sur le compte du site A.

```console
$ uname -m
x86_64
$ ldd --version | head -1
ldd (Debian GLIBC 2.36-9+deb12u14) 2.36
$ grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
VERSION_ID="12"
$ df -h ~ | tail -1
<serveur-http>:/<compte>  1.7T  798G  891G  48% /home/<compte>
$ hostname; stat -f -c %T ~
ssh1
nfs
$ php -v | head -1; php -m | grep -i sodium
PHP 8.1.34 (cli) (built: Apr 14 2026 07:36:24) (NTS)
sodium
$ curl -4 -s -o /dev/null -w "ipv4 %{http_code}\n" https://www.google.com; curl -6 -s -m 10 -o /dev/null -w "ipv6 %{http_code}\n" https://www.google.com || echo ipv6 echec
ipv4 200
ipv6 200
```

Conséquences :

- **Agent PHP** : PHP 8.1 avec sodium, de quoi signer les rapports en Ed25519
  sans dépendance.
- **NFS** : le dossier personnel y est monté en NFS. Cela ne concerne plus le
  veilleur, qui tourne sur le disque local du VPS ; l'agent PHP, lui, n'écrit
  pas de base SQLite.

## Build

WSL n'a pas `musl-gcc` (paquet `musl-tools`, droits administrateur requis). Le
repli prévu est retenu : `cargo-zigbuild` 0.20.1 avec zig 0.13.0, installés dans
`~/.local` et `~/.cargo` sans droits administrateur. Le binaire musl statique
(`x86_64-unknown-linux-musl`) ne dépend pas de la glibc de l'hôte.

```console
$ file vigie
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
$ ./vigie --version
vigie 0.1.0
```
