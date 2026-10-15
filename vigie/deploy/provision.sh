#!/bin/sh
# Installation du VPS du veilleur (Ubuntu 24.04 ou 26.04, Debian 12 ou 13), en root. Idempotente : la relancer
# ne change que ce qui diffère.
#
#   git archive -o vigie-deploy.tar --prefix=vigie-deploy/ HEAD:vigie/deploy
#   scp vigie-deploy.tar root@<vps>:/root/
#   ssh root@<vps> 'tar -xf /root/vigie-deploy.tar -C /root && sh /root/vigie-deploy/provision.sh "<clé publique ed25519 de déploiement>" [<sous-domaine>]'
#
# git archive plutôt que scp -r : seul le contenu du commit part, pas le
# targets.json local (ignoré par git). Fins de ligne LF même sous core.autocrlf :
# voir le .gitattributes de ce dossier.
#
# Sans sous-domaine, Caddy est installé mais /etc/caddy/Caddyfile n'est pas
# touché. Hermes Agent n'est pas installé ici (voir plan.md, Décisions).

set -eu

DEPLOY_KEY=${1:-}
DOMAIN=${2:-}
HERE=$(cd "$(dirname "$0")" && pwd)
HOME_DIR=/home/vigie
ROOT_DIR=$HOME_DIR/vigie

fail() { echo "✖ $*" >&2; exit 1; }
step() { echo "== $*"; }

[ "$(id -u)" = 0 ] || fail "à lancer en root"
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
  *) fail "Ubuntu 24.04 ou 26.04, Debian 12 ou 13 attendu (reçu : ${PRETTY_NAME:-inconnu})" ;;
esac
[ "$(uname -m)" = x86_64 ] || fail "x86_64 attendu : le binaire est construit pour x86_64-unknown-linux-musl"
case $DEPLOY_KEY in
  "ssh-ed25519 "*) ;;
  *) fail "premier argument : la clé publique ed25519 de déploiement (ssh-ed25519 AAAA… commentaire)" ;;
esac
if [ -n "$DOMAIN" ]; then
  printf '%s\n' "$DOMAIN" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' \
    || fail "sous-domaine invalide : $DOMAIN"
fi
# Sans clé pour root, couper l'authentification par mot de passe fermerait la porte.
[ -s /root/.ssh/authorized_keys ] || fail "/root/.ssh/authorized_keys vide : ajouter une clé avant de couper les mots de passe"

step "Paquets"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
# Caddy vient des dépôts de la distribution (universe sur Ubuntu), pas d'un dépôt tiers.
apt-cache show caddy >/dev/null 2>&1 || fail "paquet caddy introuvable : activer le composant universe (Ubuntu) puis relancer"
apt-get install -y -q unattended-upgrades ufw caddy sudo curl sqlite3

step "Mises à jour de sécurité automatiques"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

step "SSH par clé seulement"
# sshd_config inclut sshd_config.d/ en tête et la première valeur l'emporte :
# 10- passe avant le 50-cloud-init.conf des images cloud.
cat > /etc/ssh/sshd_config.d/10-vigie.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
sshd -t
# Ubuntu active ssh par socket : sans service lancé, la config vaut au prochain démarrage.
systemctl try-reload-or-restart ssh.service

step "Pare-feu : 22, 80 et 443 seulement"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

step "Utilisateur vigie"
id vigie >/dev/null 2>&1 || adduser --disabled-password --gecos "" vigie
install -d -m 700 -o vigie -g vigie "$HOME_DIR" "$ROOT_DIR" "$ROOT_DIR/bin" "$ROOT_DIR/data" "$HOME_DIR/.ssh"
touch "$HOME_DIR/.ssh/authorized_keys"
grep -qxF "$DEPLOY_KEY" "$HOME_DIR/.ssh/authorized_keys" || printf '%s\n' "$DEPLOY_KEY" >> "$HOME_DIR/.ssh/authorized_keys"
chown vigie:vigie "$HOME_DIR/.ssh/authorized_keys"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"

step "Règle sudo : redémarrage de serve, rien d'autre"
SUDOERS=$(mktemp)
echo 'vigie ALL=(root) NOPASSWD: /usr/bin/systemctl restart vigie-serve.service' > "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null
install -m 440 -o root -g root "$SUDOERS" /etc/sudoers.d/vigie
rm -f "$SUDOERS"

step "Unités systemd"
install -m 644 "$HERE/systemd/vigie-serve.service" "$HERE/systemd/vigie-tick.service" "$HERE/systemd/vigie-tick.timer" /etc/systemd/system/
systemctl daemon-reload
# Avant le premier déploiement, les conditions des unités les font ignorer.
systemctl enable --now vigie-serve.service vigie-tick.timer

step "Caddy"
if [ -n "$DOMAIN" ]; then
  sed "s/<sous-domaine>/$DOMAIN/" "$HERE/Caddyfile.example" > /etc/caddy/Caddyfile
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
  systemctl reload caddy
else
  echo "Sous-domaine absent : /etc/caddy/Caddyfile non modifié"
fi

step "Fait"
echo "Reste à faire : ~vigie/vigie/config.toml (0600), ~vigie/vigie/smtp-password (0600, phase 2), puis le premier déploiement."
stat -c '%a %U %n' "$HOME_DIR" "$ROOT_DIR"
ufw status
cat /etc/sudoers.d/vigie
