# Hébergement du veilleur sur un VPS

Constats de la reconnaissance (phase 1). Chaque ligne cite la commande et sa
sortie. Les noms d'hôtes, de comptes et le sous-domaine sont masqués : le dépôt
est public.

## Statut

| Point | État |
| ----- | ---- |
| VPS du veilleur | Hetzner CX23, Ubuntu 26.04.1 LTS, x86_64, Helsinki : **créé** le 2026-10-15, pare-feu Hetzner (22, 80, 443, ICMP) attaché |
| Installation | `deploy/provision.sh` **lancé** le 2026-10-15 : sshd par clé seulement (`sshd -T`), mot de passe refusé (`Permission denied (publickey)`), `ufw` actif sur 22, 80 et 443, `monitor` en 0700 hors sudo sauf `systemctl restart monitor-serve.service` (`stop caddy` refusé), certificat Let's Encrypt obtenu par Caddy, `serve` ignoré faute de binaire (`/health` en 502) |
| Relevé système du VPS | **À mesurer** après l'installation |
| SMTP authentifié sur 587 vers le relais Alwaysdata | **Fait** le 2026-10-15 depuis le VPS : STARTTLS exigé (`--ssl-reqd`), authentification par la boîte d'alerte, code SMTP 250, message reçu par le destinataire ; les relais `smtp-<compte>.alwaysdata.net` de deux comptes résolvent vers la même adresse (relais communs, l'authentification se fait par la boîte et non par le compte) |
| Premier déploiement | **Fait** le 2026-10-15 : `monitor 0.1.0`, `/health` en 200 avec un tick postérieur à la bascule, route inconnue en 404 sans corps, HTTP redirigé en 308 vers HTTPS, `serve` sur `127.0.0.1:8080` seulement (8080 injoignable de l'extérieur), timer à la minute, base en 0600 dans `data/` |
| Relance de `serve` après kill | **Fait** : `kill -9` du PID 3259, relancé en PID 3336 en moins de 8 s |
| Relance après reboot | **Fait** le 2026-10-15 (extinction puis rallumage depuis la console Hetzner) : démarrage à 15:52:12 UTC, `serve` actif à 15:52:11 en PID 1048, `caddy`, `ufw`, `ssh.socket` et le timer actifs, premier tick à 15:53:00, `/health` en 200, `status` en code 0, 8080 toujours injoignable de l'extérieur |
| Cloisonnement | **À mesurer** (tâche 5, une fois Hermes installé) |
| sodium sur le site A | **À mesurer** (pas d'accès SSH au compte du site A depuis le poste) |
| Sortie IPv4 et IPv6 du site A | **À mesurer** |

## Installation

Sur un VPS neuf, avec la clé root déposée à la commande :

```console
$ scp -r monitor/deploy root@<vps>:/root/monitor-deploy
$ ssh root@<vps> sh /root/monitor-deploy/provision.sh "<clé publique ed25519 de déploiement>" <sous-domaine>
```

Le script est idempotent. Il installe `unattended-upgrades`, `ufw` (22, 80 et
443 seulement), Caddy, l'authentification SSH par clé seulement, l'utilisateur
`monitor` (sans mot de passe ni sudo général, dossier personnel en 0700), les
unités `monitor-serve.service`, `monitor-tick.service` et `monitor-tick.timer`,
et une règle sudo unique :

```text
monitor ALL=(root) NOPASSWD: /usr/bin/systemctl restart monitor-serve.service
```

Avant le premier déploiement, les conditions des unités (`bin/monitor`
exécutable, `config.toml` présent) les font ignorer au lieu d'échouer.

## VPS du veilleur

À compléter après l'installation :

```console
$ uname -m
$ ldd --version | head -1
$ grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
$ findmnt -no FSTYPE,SOURCE /home
$ df -h /home | tail -1
$ ufw status
$ ss -ltnp
$ systemctl is-active monitor-serve.service monitor-tick.timer caddy
$ ~monitor/monitor/bin/monitor --version
```

Premier relevé, avant installation (2026-10-15) : `x86_64`, Ubuntu 26.04.1 LTS,
racine en `ext4`, `sudo-rs 0.2.13` (son `visudo` accepte `-c` et `-f`),
`ssh.socket` et `ssh.service` actifs, `ufw`, `curl` et `unattended-upgrades`
déjà présents.

Attendus : `x86_64`, `/home` sur un disque local (`ext4`), seuls
22, 80 et 443 en écoute publique, `serve` sur `127.0.0.1:8080` seulement.

Le disque est local : SQLite en WAL y est sûr, `serve` et `tick` partageant
le même hôte et la même base `~/monitor/data/monitor.db`.

## SMTP

Hetzner bloque par défaut les ports 25 et 465 en sortie ; le 587 reste ouvert.
Les alertes passent par le relais d'une boîte Alwaysdata existante
(`smtp-<compte>.alwaysdata.net`, port 587, STARTTLS, authentification). Une
boîte dédiée aux alertes est préférable : son mot de passe ne donne accès qu'à
elle.

Le mot de passe vit dans `~monitor/monitor/smtp-password` (0600, propriétaire
`monitor`), référencé par `password_file` (phase 2), jamais dans `config.toml`
ni dans le dépôt.

Envoi de test depuis le VPS (2026-10-15, code SMTP 250), sans mot de passe sur
la ligne de commande : le `netrc` est généré en 0600 dans un dossier temporaire
de `~/monitor`, à partir de `smtp-password`, puis supprimé ; pas de `-v`, qui
afficherait l'échange `AUTH` :

```console
$ curl --url smtp://smtp-<compte>.alwaysdata.net:587 --ssl-reqd \
    --netrc-file ~/monitor/smtp-netrc \
    --mail-from <expéditeur> --mail-rcpt <destinataire> --upload-file test.eml
```

## Cloisonnement

Le VPS peut aussi héberger Hermes Agent (voir `plan.md`, Décisions), à ces
conditions :

- Hermes tourne sous son propre utilisateur, sans sudo et hors du groupe
  `docker` ; ses commandes shell passent par un bac à sable ; son unité porte
  un `MemoryMax`.
- `monitor` a un dossier personnel en 0700 : Hermes ne lit ni la
  configuration, ni la base, ni le mot de passe SMTP.
- Les unités du veilleur sont durcies (`ProtectSystem=strict`,
  `ProtectHome=read-only`, seul `~/monitor/data` en écriture,
  `NoNewPrivileges`), et `serve` a un `OOMScoreAdjust=-500`.
- Si Hermes redevient inutilisé : le désinstaller et révoquer ses jetons.

À compléter (tâche 5) : PID de `serve` avant et après `kill`, puis après un
reboot ; `sudo -u hermes cat ~monitor/monitor/config.toml` refusé.

## Plateforme du site A (Alwaysdata, 2026-10-15)

Relevé en lecture seule sur le compte SSH d'un site déjà hébergé sur
Alwaysdata. Il sert à l'agent PHP (phase 3) : les comptes d'une même plateforme
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

## Site A

À compléter : `php -v`, `php -m | grep -i sodium`, puis la même paire de
commandes `curl -4 -s -m 10 -o /dev/null -w "ipv4 %{http_code}\n" https://www.google.com`
et `curl -6 -s -m 10 -o /dev/null -w "ipv6 %{http_code}\n" https://www.google.com || echo ipv6 echec`.

## Build

WSL n'a pas `musl-gcc` (paquet `musl-tools`, droits administrateur requis). Le
repli prévu est retenu : `cargo-zigbuild` 0.20.1 avec zig 0.13.0, installés dans
`~/.local` et `~/.cargo` sans droits administrateur. Le binaire musl statique
(`x86_64-unknown-linux-musl`) ne dépend pas de la glibc de l'hôte.

```console
$ file monitor
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
$ ./monitor --version
monitor 0.1.0
```
