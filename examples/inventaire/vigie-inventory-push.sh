#!/bin/sh
# Enveloppe de `vigie-inventory push` pour la CI (issue #20,
# vigie/docs/inventaire.md) : un veilleur injoignable ou un refus (code 1)
# laisse un avertissement visible sans bloquer le déploiement ; une
# configuration fausse (code 2 : usage, clé, lockfile, projet) arrête le job.
# Aucune option de CI qui laisse passer un job en échec : elle masquerait le
# code 2.
# Shell POSIX : ne marche pas tel quel sous Windows.
#
# Usage : sh vigie-inventory-push.sh --site site-a --endpoint https://vigie.example.org [options de push]
set -u
rc=0
vigie-inventory push "$@" || rc=$?
if [ "$rc" -eq 1 ]; then
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::warning::inventaire non envoyé au veilleur (code 1) : déploiement poursuivi"
  else
    echo "avertissement : inventaire non envoyé au veilleur (code 1) : déploiement poursuivi" >&2
  fi
  exit 0
fi
exit "$rc"
