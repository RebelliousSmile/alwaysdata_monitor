#!/bin/sh
# Échoue si un Cargo.lock tire une pile TLS autre que rustls + ring : aws-lc
# casse le build musl par zigbuild, openssl et native-tls lient une
# bibliothèque système (issue #9). Usage : check-tls-deps.sh <Cargo.lock>...
set -eu
[ "$#" -gt 0 ] || { echo "usage : $0 <Cargo.lock>..." >&2; exit 2; }
status=0
for lock in "$@"; do
    [ -f "$lock" ] || { echo "$lock : fichier absent" >&2; exit 2; }
    found=$(grep -E '^name = "(aws-lc-sys|aws-lc-rs|openssl-sys|native-tls)"$' "$lock" | sed 's/^name = //' || true)
    if [ -n "$found" ]; then
        echo "$lock : dépendance TLS interdite :" $found >&2
        status=1
    fi
done
exit $status
