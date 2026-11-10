#!/usr/bin/env python3
"""Vérifie les exceptions des osv-scanner.toml (issue #22).

Chaque entrée [[IgnoredVulns]] doit porter un `id` non vide, une `reason`
non vide et un `ignoreUntil` en date TOML, au plus tard 92 jours après la
date UTC du jour. Toute autre clé de premier niveau est refusée, dont
PackageOverrides, qui ignore un paquet entier sans échéance.

Une échéance déjà passée n'est pas une erreur ici : osv-scanner rend alors
la faille et le scan échoue.

Usage : python3 -I check-osv-exceptions.py [osv-scanner.toml...]
Sortie 0 si tout est conforme (ou sans fichier), 1 sinon, après avoir
listé chaque erreur (fichier, entrée, motif).
"""

import datetime
import sys
import tomllib

MAX_DAYS = 92


def check_entry(index, entry, limit):
    """Retourne (nom de l'entrée, liste des motifs d'erreur)."""
    if not isinstance(entry, dict):
        return f"entrée {index}", ["n'est pas une table"]
    vuln_id = entry.get("id")
    if isinstance(vuln_id, str) and vuln_id.strip():
        name = vuln_id
    else:
        name = f"entrée {index}"
    errors = []
    if not (isinstance(vuln_id, str) and vuln_id.strip()):
        errors.append("id absent ou vide")
    reason = entry.get("reason")
    if not (isinstance(reason, str) and reason.strip()):
        errors.append("reason absente ou vide")
    if "ignoreUntil" not in entry:
        errors.append("ignoreUntil absent")
    else:
        until = entry["ignoreUntil"]
        if isinstance(until, datetime.datetime):
            until = until.date()
        if not isinstance(until, datetime.date):
            errors.append(f"ignoreUntil n'est pas une date TOML ({until!r})")
        elif until > limit:
            errors.append(
                f"ignoreUntil {until.isoformat()} au-delà de {MAX_DAYS} jours "
                f"(limite {limit.isoformat()})"
            )
    return name, errors


def check_file(path, limit):
    """Retourne la liste des messages d'erreur du fichier."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [f"{path} : illisible ({e})"]
    errors = []
    for key in data:
        if key != "IgnoredVulns":
            errors.append(f"{path} : clé {key!r} refusée (seule IgnoredVulns est admise)")
    entries = data.get("IgnoredVulns", [])
    if not isinstance(entries, list):
        return errors + [f"{path} : IgnoredVulns doit être une liste de tables ([[IgnoredVulns]])"]
    for index, entry in enumerate(entries, start=1):
        name, reasons = check_entry(index, entry, limit)
        errors.extend(f"{path} : {name} : {reason}" for reason in reasons)
    return errors


def main(paths):
    today = datetime.datetime.now(datetime.timezone.utc).date()
    limit = today + datetime.timedelta(days=MAX_DAYS)
    errors = []
    for path in paths:
        errors.extend(check_file(path, limit))
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"{len(errors)} erreur(s) dans les exceptions osv-scanner", file=sys.stderr)
        return 1
    print(f"{len(paths)} fichier(s) d'exceptions conforme(s) (échéance au plus tard {limit.isoformat()})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
