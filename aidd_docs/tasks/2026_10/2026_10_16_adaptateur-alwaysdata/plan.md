---
objective: "L'agent PHP d'un site Alwaysdata pousse au veilleur, par lots signés et idempotents, les lignes nouvelles du log HTTP de ses hôtes, depuis une position d'octet persistée qui survit aux rotations gz ; le veilleur les normalise à la réception, n'en garde que des Entry sans valeur de query string, 30 jours, et les sert à l'analyse par un LogSource."
status: pending
issue_number: 1
---

# Plan: Adaptateur Alwaysdata (fetch différentiel des logs)

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Premier client du contrat `LogSource` (#7) : amener les logs d'accès d'un site Alwaysdata jusqu'à l'analyseur (#8), sans accès stocké et sans garder de données personnelles inutiles |
| **Source** | Issue GitHub #1 ; `vigie/docs/logs.md` ; `vigie/docs/decisions.md` (RGPD 30 jours, query strings masquées, aucun accès FTP stocké) ; `src/Service/LogReaderService.php` (chemins des logs Alwaysdata) |

## Phases

| #   | Phase                                     | File                         |
| --- | ----------------------------------------- | ---------------------------- |
| 1   | Point d'entrée /r/v1/logs et stockage     | [`phase-1.md`](./phase-1.md) |
| 2   | Lecture différentielle par l'agent PHP    | [`phase-2.md`](./phase-2.md) |
| 3   | LogSource Alwaysdata, rétention et contrat écrit | [`phase-3.md`](./phase-3.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Transport : l'agent pousse (`POST /r/v1/logs`), signé par sa clé de rapport, sur le modèle de `/r/v1/report` (taille, délai, site, signature, schéma strict avec `"type":"logs"`, horloge ±300 s, `seq` de lots strictement croissant et distinct de celui des rapports, 404 muet sur tout refus). Le veilleur ne lit jamais l'hébergeur | Aucun accès FTP ou API stocké (`decisions.md`) ; l'agent n'expose aucune URL |
| Un lot porte l'identité de ce qu'il couvre : `file` (nom du fichier, sans chemin), `start` et `end` (octets du fichier non compressé), et `chunk` en base64 des octets bruts, lignes entières. Base64 parce que `json_encode` échoue sur l'UTF-8 invalide d'une ligne hostile | Les octets arrivent intacts ; l'identité (site, fichier, début) sert la déduplication |
| Idempotence côté veilleur : un lot dont (site, file, start, end) est déjà accepté reçoit 204 sans rien réécrire ; un lot qui chevauche autrement un lot accepté est refusé ; les entrées d'un lot et sa ligne d'identité sont écrites dans une même transaction IMMEDIATE | Un agent qui a perdu la réponse renvoie le même lot : il doit être compté une fois |
| Position d'octet côté agent, dans son état hors webroot (0700, fichier 0600 vérifié, écriture atomique sous `flock`), avancée seulement après un 204 ; jamais de `mtime` | Reprise après crash : l'agent renvoie depuis sa dernière position acceptée, le veilleur déduplique |
| Rotation : Alwaysdata écrit `admin/logs/http/<année>/http-<date>.log` puis le compresse en `.log.gz`. L'agent suit le fichier du jour par sa date ; s'il reste une position sur un fichier de la veille, il le finit d'abord, lu en `.log` ou décompressé depuis `.log.gz`, en sautant `start` octets décompressés. Un fichier plus court que la position (remplacé) repart de zéro et le dit dans le lot (`restarted: true`) | Les lignes de la fin de journée ne se perdent pas à la rotation |
| Filtre d'hôtes côté agent : seules les lignes dont l'hôte figure dans `logs.hosts` de sa configuration partent. Un compte qui loge plusieurs sites ne fait pas partir les logs d'un autre client | Minimisation RGPD ; un fichier Alwaysdata couvre tout le compte |
| Coupe de chaque ligne à 16 Kio côté agent (règle de `logs.md`) ; lot de 48 Kio de données au plus (le corps reste sous 64 Ko après base64 et JSON) ; 20 lots au plus et 20 s au plus par passage ; plafond de 50 Mo de logs par site et par jour côté veilleur, au-delà refus | Bornes mémoire et CPU des deux côtés ; un site très chargé rattrape sur plusieurs passages |
| Le veilleur normalise à la réception (`combined::split`, `normalize`, fuseau facultatif de la source) et ne stocke que des `Entry` dans `log_entries` ; les octets bruts ne sont jamais écrits. Les rejets sont comptés par lot | RGPD : les valeurs de query string n'existent jamais en base ; rien n'est à masquer après coup |
| Conservation : `tick` purge les entrées et les identités de lots de plus de 30 jours (heure de l'entrée) | Décision RGPD du 2026-10-16 |
| `[sites.logs]` de `config.toml` active la réception pour un site (`source = "alwaysdata"`, `tz` facultatif) ; sans elle, `/r/v1/logs` refuse le site | Fail-closed, comme les commandes |
