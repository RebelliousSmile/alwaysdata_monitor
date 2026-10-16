---
objective: "Le contrat de l'analyse de logs est figé : une Entry aux types fixés, une normalisation commune qui tient les entrées hostiles, un trait LogSource dyn-compatible, et un jeu de fixtures que les adaptateurs (#1) et l'analyseur (#8) partagent."
status: in-progress
issue_number: 7
---

# Plan: Contrat LogSource et format Entry

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Séparer l'acquisition des logs, propre à chaque serveur, de leur analyse, invariante. Un nouveau type de serveur = un adaptateur et une fixture, zéro ligne dans l'analyseur |
| **Source** | Issue GitHub #7 ; `vigie/docs/decisions.md` (RGPD, aucun accès FTP stocké) ; format HTTP d'Alwaysdata (documentation « Formatting HTTP Logs ») |

## Phases

| #   | Phase                                   | File                         |
| --- | --------------------------------------- | ---------------------------- |
| 1   | Entry et normalisation                  | [`phase-1.md`](./phase-1.md) |
| 2   | Trait LogSource, fixtures et contrat écrit | [`phase-2.md`](./phase-2.md) |

## Resources

| Source | Verified |
| ------ | -------- |
| https://help.alwaysdata.com/en/docs/web-hosting/sites/customizing/formatting-http-logs/ | Format « Standard » : combined Apache précédé de `{request_hostname}`. Format « Advanced », par défaut : ajoute `{protocol}` et `{duration}` (secondes) en fin de ligne. Un même fichier `admin/logs/http/<année>/http-<date>.log` couvre tous les sites du compte |
| `src/Service/HttpLogParserService.php` | Forme réelle d'une ligne lue par le module : `<hôte> <ip> - - [12/Apr/2026:14:32:10 +0200] "GET /p HTTP/2.0" 200 12345 "-" "<ua>"` |
| https://httpd.apache.org/docs/2.4/mod/mod_log_config.html | `%t` : `[day/month/year:hour:minute:second zone]` ; `%b` : `-` pour zéro octet ; `%r` peut être une requête HTTP/0.9 sans protocole |

## Decisions

| Decision | Why |
| -------- | --- |
| Le veilleur ne va jamais chercher les logs : seul l'agent du site peut les lire (aucun accès FTP stocké, `decisions.md`). Le contrat porte donc sur la transformation d'octets bruts reçus en `Entry`, et sur un `LogSource` qui sert des entrées depuis une position. L'acquisition différentielle (offset, rotations gz) relève de #1 | Le contrat reste vrai quel que soit le transport ; l'analyseur (#8) ne voit que des `Entry` |
| `Entry` ajoute aux champs de l'issue `host: Option<String>`, `query_keys: Vec<String>`, `referer_present: bool`, `referer_host: Option<String>` et `duration_us: Option<u64>` | Un fichier Alwaysdata couvre tous les sites du compte : sans l'hôte, impossible d'attribuer une ligne. Le module se sert des clés de requête (`?q=` des scrapers) et de l'absence de referer (score de suspicion, `IpSuspicionScorer.php`) ; la durée sert le « temps de réponse serveur » du brainstorm |
| Les valeurs de la query string ne sortent jamais du contrat : `normalize` ne garde que ses clés (16 au plus, 64 octets chacune). Le referer est réduit à son hôte | RGPD, « query strings masquées dès l'analyse » (`decisions.md`) : jetons de réinitialisation et paniers ne passent même pas par l'analyseur |
| La normalisation (`RawFields` → `Entry`) et le découpeur Apache combined (hôte en tête facultatif, champs en queue facultatifs, guillemets échappés) vivent dans le contrat. Un adaptateur choisit son découpeur et fournit ses octets ; #1 n'écrit que le transport, la position et les rotations | Ce sont les parties exposées aux entrées hostiles : les écrire une fois, les fuzzer une fois. Cela rend `expected.json` vérifiable dès #7. Le découpeur était listé dans #1 : il y est livré par avance |
| Une ligne n'est jamais rejetée pour sa longueur tant qu'elle reste sous `MAX_LINE` (4 Mio) : chaque champ est tronqué à sa limite. Au-delà, `TooLong` | Un UA de 1 Mo doit donner une `Entry` tronquée, sinon un robot se cache en gonflant sa ligne ; 4 Mio borne la mémoire |
| `fetch(from, max_entries)` et `Fetched.more` sont dans la signature dès maintenant ; les entrées d'un lot et le curseur suivant se persistent dans une même transaction `IMMEDIATE` par l'appelant : chaque entrée est vue exactement une fois par curseur côté veilleur ; un lot renvoyé par l'agent après une réponse perdue est dédupliqué par #1, par son identité (fichier, offset de début) | Ajouter plus tard une borne casserait chaque adaptateur ; un hash de ligne fusionnerait à tort deux requêtes identiques dans la même seconde |
| Aucun ordre garanti entre entrées ; une entrée datée de plus d'un jour dans le futur par rapport à l'horloge injectée (#9) est rejetée (`Future`) ; détecter une rotation est l'affaire de l'adaptateur, qui rend `SourceError::CursorInvalid` quand une position ne vaut plus rien | Une ligne future fausserait toutes les fenêtres de #8 ; le passé est laissé à la purge de 30 jours |
| L'hôte est mis en minuscules, sans port ni point final. Le chemin n'est ni décodé ni normalisé (`%2e`, `//`, `..` restent tels quels). Une méthode invalide (`get`) n'efface pas la cible : `method` vaut `None`, `path` garde la cible | `{request_hostname}` vient du client ; #8 sait ainsi ce que voient ses globs ; `get /.env` est un signal |
| Fixtures synthétiques au format réel au lieu des « logs réels » de l'issue : IP des plages RFC 5737 et `2001:db8::/32`, hôtes en `example.org` ; les UA de robots sont des chaînes publiques. Écart consigné dans `decisions.md` | Dépôt public (`.claude/rules/07-quality/7-public-repo-data.md`) ; aucune ligne de production |
| `jiff` avec `tzdb-bundle-always`, `flate2` (`rust_backend`, en dev seulement) : `jiff-tzdb`, `flate2` et `miniz_oxide` sont du Rust pur, vérifiés par le contrôle des lockfiles et le build musl | Base tz embarquée, sans dépendre de `/usr/share/zoneinfo` du VPS |
