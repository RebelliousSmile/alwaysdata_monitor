---
objective: "Un veilleur Rust hébergé sur Alwaysdata surveille le site A de l'extérieur et via un agent PHP signé, et une reprise de l'incident du 2026-09-07 déclenche un e-mail d'alerte en moins de 10 minutes, sans que le module PrestaShop actuel change. Le poste de pilotage Windows s'installe et se met à jour comme email-to-markdown."
status: pending
---

<!-- Fill or omit these sections; never add, rename, or reorder one. -->

# Plan: Veilleur multi-sites, plus petite version utile

## Overview

| Field      | Value                   |
| ---------- | ----------------------- |
| **Goal**   | Veilleur Rust sur Alwaysdata (contrôles externes, rapports signés de l'agent PHP, alertes par e-mail), placé dans `monitor/` et validé par la reprise de l'incident du site A |
| **Source** | [`brainstorm.md`](./brainstorm.md) (synthèse approuvée le 2026-10-15), plus deux consignes de l'utilisateur : « tout dans `monitor/`, sans casser le code actuel » et « pour windows, on installera le programme comme pour email to markdown ou lyremember » |

## Phases

| #   | Phase                                                             | File                         |
| --- | ----------------------------------------------------------------- | ---------------------------- |
| 1   | Reconnaissance Alwaysdata et squelette déployé                    | [`phase-1.md`](./phase-1.md) |
| 2   | Contrôles externes et alertes par e-mail                          | [`phase-2.md`](./phase-2.md) |
| 3   | Point d'entrée des rapports signés et silence des agents          | [`phase-3.md`](./phase-3.md) |
| 4   | Agent PHP et pose sur le site A                                   | [`phase-4.md`](./phase-4.md) |
| 5   | Test de réception : reprise de l'incident du 2026-09-07           | [`phase-5.md`](./phase-5.md) |
| 6   | Distribution Windows du poste de pilotage (possible dès la fin de la phase 3) | [`phase-6.md`](./phase-6.md) |

## Resources

| Source | Verified          |
| ------ | ----------------- |
| https://help.alwaysdata.com/en/docs/web-hosting/services/ | Les services sont des programmes au premier plan, redémarrés automatiquement, avec une commande de surveillance facultative, et désactivés après des échecs répétés. Sur le Public Cloud, ils tournent sur des serveurs à part, ne sont **joignables qu'en IPv6** sur les ports 8300 à 8499, et rien ne filtre le réseau. Les logs sont dans `~/admin/logs/services/` |
| https://help.alwaysdata.com/en/docs/web-hosting/sites/http-servers/user-program/ | Le type de site « User program » lance une commande qui écoute sur l'IP et le port indiqués dans le panneau. Rust est cité. La doc ne dit **pas** si le processus est lancé à la demande ni s'il est arrêté quand il est inactif : la phase 1 le mesure |
| https://help.alwaysdata.com/en/docs/web-hosting/tasks/ | Les tâches planifiées utilisent la syntaxe crontab standard, sans les raccourcis `@`. Elles démarrent dans la minute prévue, et un passage encore en cours fait ignorer le suivant. Les logs sont dans `~/admin/logs/jobs/`, et un e-mail part si le code de retour est différent de 0 |
| https://help.alwaysdata.com/en/docs/emails/use-an-email-address/ | Le SMTP sortant est `smtp-[compte].alwaysdata.net` (465 en TLS, ou 587 en STARTTLS). Aucune authentification n'est exigée depuis un site ou une tâche planifiée hébergés chez Alwaysdata |
| https://help.alwaysdata.com/en/docs/web-hosting/sites/customizing/use-probes/ | La sonde native d'Alwaysdata est réservée aux offres Dedicated/Gold, coûte 10 €/mois et alerte l'équipe Alwaysdata : elle n'est pas retenue, et UptimeRobot surveille le veilleur |
| `email-to-markdown/app/` : `packaging/windows/email-to-markdown.iss`, `.github/workflows/release.yml`, `src/updater.rs`, `scripts/build.ps1`, `aidd_docs/memory/deployment.md` | Installeur Inno Setup par utilisateur (`{localappdata}\Programs\…`, `PrivilegesRequired=lowest`), sans ajout au PATH. `ISCC` est lancé à la main, et `build.ps1` reporte la version de `Cargo.toml` dans le `.iss`. Un tag `v*` publie les binaires et `SHA256SUMS`, actions épinglées par SHA. L'updater lit `releases/latest`, vérifie le SHA-256 et remplace avec `self_replace` après `tmp.keep()` |
| `lyremember/app/` : `.github/workflows/release.yml`, `lyremember-app/src-tauri/tauri.conf.json` | Installeurs NSIS et MSI produits par `tauri-action` (Tauri, sans intérêt pour une CLI). Lui reprendre seulement le `workflow_dispatch` qui rejoue un tag perdu. Ses actions ne sont pas épinglées par SHA : ne pas le suivre sur ce point |

## Decisions

| Decision   | Why   |
| ---------- | ----- |
| Tout le nouveau code va dans `monitor/` (crate Cargo, agent PHP et scripts). En dehors, seuls `.gitignore`, `.gitattributes`, `.github/workflows/monitor.yml` et `.github/workflows/monitor-release.yml` changent | C'est la consigne de l'utilisateur. `scripts/deploy.mjs` n'envoie que la liste blanche `DEPLOY_PATHS` et `.php-cs-fixer.dist.php` ne lit que `src/`, donc le module reste intact. `/monitor export-ignore` empêche aussi `monitor/` d'entrer dans une archive du module |
| Le veilleur a deux points d'entrée dans un seul binaire : `monitor serve`, un site « User program » qui reçoit les rapports en HTTPS, et `monitor tick`, une tâche planifiée lancée chaque minute qui fait les contrôles et envoie les alertes. Les deux partagent une base SQLite en WAL | Un service Alwaysdata n'est joignable qu'en IPv6, ce que des hébergeurs du parc peuvent ne pas savoir faire, alors qu'un site sert IPv4, IPv6 et TLS. Confier les contrôles et **tous** les envois d'e-mail à `tick` fait que la permanence de `serve` (non documentée) ne conditionne plus les alertes : `serve` enregistre les incidents à l'état « à notifier », il n'envoie rien. Le WAL n'est sûr que si les deux processus tournent sur le même hôte et sur un système de fichiers local : la phase 1 le mesure avant les phases 2 et 3, les seules où les deux processus écrivent dans la base. Un service Alwaysdata tourne sur un autre serveur et n'est joignable qu'en IPv6 : ce n'est pas un repli. Si le site s'endort sans se relancer à la demande, ou si les hôtes diffèrent, la phase 1 s'arrête et la décision est prise avec l'utilisateur |
| La configuration de production (liste des sites, destinataire des alertes) ne vit que sur le veilleur, dans `~/monitor/config.toml`. Le dépôt ne contient que `config.example.toml`, et `.gitignore` exclut `monitor/config.toml` et `monitor/remote.toml` | Le dépôt est public, et la prestation suppose que le client ne voit rien : la liste des sites surveillés ne doit pas y apparaître |
| Les rapports sont authentifiés par une signature ed25519 propre à chaque site : `ed25519-dalek` côté veilleur, `sodium_crypto_sign_detached` côté agent. Le veilleur n'accepte que les rapports signés avec l'horodatage dans ±300 s, un `seq` strictement croissant et un corps de 64 Ko au plus. Une erreur renvoie une réponse muette | C'est la pièce la plus exposée (brainstorm, « Encore ouvert »). La clé privée ne quitte jamais le site. Aucun secret partagé n'est stocké côté veilleur, et l'agent PHP signe sans dépendance |
| Le pilotage de cette version passe par SSH, toujours avec le chemin complet `~/monitor/bin/monitor`. Sous Windows, le `monitor` installé relaie `status`, `ack`, `check --once` et `site …` vers le veilleur via l'`ssh.exe` du système (`monitor remote …`, liste blanche, arguments validés et entre guillemets). Le veilleur n'expose aucune API de pilotage | Il n'ouvre aucune nouvelle surface réseau, alors qu'une API exigerait sa propre authentification. Une API de pilotage et les cibles Termux/Android attendent la version suivante |
| Windows reçoit un installeur Inno Setup par utilisateur, sur le modèle d'email-to-markdown, avec en plus l'ajout au PATH utilisateur. Il est compilé dans la CI par `monitor-release.yml` sur les tags `monitor-v*`, avec `SHA256SUMS` et `monitor update` (prévisualisation, puis `--apply`) | C'est la consigne de l'utilisateur. Le préfixe `monitor-v` évite toute collision avec les tags `v*` du module (`v1.10.0`). L'updater filtre ce préfixe au lieu de lire `releases/latest`, qui peut désigner une release du module. Le dépôt est public : la release est publique, et le binaire ne contient aucun secret. `SHA256SUMS`, publié dans la même release, protège d'un téléchargement corrompu mais pas d'une release compromise : la signature des binaires attend la version suivante |
| Les alertes partent par e-mail via le SMTP local d'Alwaysdata (`lettre`, rustls), avec un seul envoi par incident ouvert et un rappel par jour | Ni clé ni secret à stocker. UptimeRobot couvre la panne du veilleur lui-même |
| La reprise de l'incident est rejouée en local sur des fixtures. En production, le seul test est la suppression d'un fichier témoin déclaré critique, jamais celle de `wp-config.php` | Une reprise réelle remettrait le site A dans l'état exploité en septembre |
