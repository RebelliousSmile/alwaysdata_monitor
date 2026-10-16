# Réception : reprise de l'incident du 2026-09-07

Promesse de la plus petite version utile : **un e-mail d'alerte moins de
10 minutes après l'incident**, sur le site A, dans l'état exact de septembre.

État de l'incident, rejoué partout :

- `wp-config.php` absent de la racine du site ;
- `wp-admin/setup-config.php` servi avec son formulaire d'installation ;
- la page surveillée (`/kb/`) sans son mot-clé.

Le veilleur doit le voir par deux canaux indépendants, chacun sous 10 min :

| Canal               | Constat                                   | Clé d'incident                                |
| ------------------- | ----------------------------------------- | --------------------------------------------- |
| Agent PHP           | `critical-file` sur `wp-config.php`       | `site-a/agent:critical-file/wp-config.php`    |
| Contrôles externes  | `installer`, `content` (mot-clé absent)   | `site-a/installer/wp-admin/setup-config.php`, `site-a/content/keyword` |

Cadences, comme en production : `tick` chaque minute, agent toutes les 5 min,
`interval = 300` pour les contrôles externes du site.

## Verdict

| Mesure                     | Date       | Résultat                    | Statut      |
| -------------------------- | ---------- | --------------------------- | ----------- |
| Pire cas simulé (25 cas)   | 2026-10-16 | 299 s sur chaque canal      | validé      |
| Reprise locale réelle      | 2026-10-16 | externe 239 s, agent 299 s  | validé      |
| Production (fichier témoin)| 2026-10-16 | alerte à T0+56 s, clôture 2 min 35 s après la restauration | validé |
| Sonde UptimeRobot          | 2026-10-16 | alerte 5 min après le 503, retour 3 min après la relance | validé |

Réception **prononcée le 2026-10-16** : les quatre mesures tiennent la
promesse des 10 minutes.

## 1. Pire cas simulé

```sh
cd vigie && cargo test --locked --test replay_2026_09_07 -- --nocapture
```

`tests/replay_2026_09_07.rs` sert le site A en HTTPS local
(`tests/support/incident_site.rs`, autorité de test générée à chaque lancement)
et rejoue l'incident pour chaque décalage d'une minute entre l'injection et le
prochain passage de chaque canal : 5 × 5 = 25 cas, 15 min simulées chacun,
`tick` chaque minute. L'heure est logique (`tick::run_with`, `ingest::ingest`
la reçoivent en argument) : le test dure une vingtaine de secondes.

Chaque cas exige : aucun e-mail avant l'injection, les trois incidents ouverts,
un e-mail par incident sans doublon, et chaque canal sous 600 s.

Résultat du 2026-10-16 :

```txt
25 cas, pire premier e-mail : 299 s (agent à +4 min, externe à +5 min)
25 cas, pire canal agent seul : 299 s (agent à +4 min, externe à +5 min)
25 cas, pire canal externe seul : 299 s (agent à +4 min, externe à +5 min)
```

Le pire cas est borné par la cadence : 5 min au plus avant que le canal voie
l'incident, puis le passage `tick` suivant. Marge : 301 s sur la promesse.

Preuve négative : avec une promesse ramenée à 4 min, le test échoue.

## 2. Reprise locale réelle

```sh
node vigie/scripts/replay-incident.mjs [--delay <s>] [--keep]
```

Prérequis : cargo, php avec l'extension sodium chargeable
(`php -d extension=sodium`). Durée : 12 à 15 min réelles.

Le script, dans un dossier temporaire :

1. compile `vigie` et l'exemple `replay_local`, puis lance les exécutables de
   `target/debug` directement (pas `cargo run`, dont les processus enfants
   survivraient à l'arrêt) ;
2. écrit une configuration du veilleur (base, site `site-a` sur
   `https://127.0.0.1:<port>`, alertes factices en `example.org`) ;
3. copie l'arborescence de test `agent/php/tests/fixtures/wp-healthy`, crée la
   clé de l'agent (`--init`) et l'enregistre (`vigie site add`) ;
4. lance `vigie serve` (le binaire), l'exemple `replay_local` (site servi et
   `tick` chaque minute) et l'agent PHP toutes les 5 min ;
5. attend l'état sain (un rapport accepté, un passage des contrôles), puis
   `--delay` secondes ;
6. à T0, supprime `wp-config.php` de l'arborescence et met le site servi dans
   l'état de l'incident ;
7. relève le premier e-mail de chaque canal, 11 min au plus ;
8. arrête tout dans un `finally`, vérifie qu'aucun processus ne reste, et
   sort en 0 seulement si chaque canal a alerté sous 600 s.

La ligne `RESULT {json}` en fin de sortie porte les mesures.

Résultat du 2026-10-16, sous Windows 11 (PHP 8.4.11, build `dev`), T0 à
00:50:06 heure de Paris (2026-10-15T22:50:06Z) :

| Heure (UTC) | Événement                                                        |
| ----------- | ---------------------------------------------------------------- |
| 22:49:05    | premier rapport de l'agent accepté, premier passage : 5 contrôles, aucun e-mail |
| 22:50:06    | T0 : `wp-config.php` supprimé, site servi dans l'état de l'incident |
| 22:54:05    | contrôles externes : 2 e-mails (mot-clé absent, installeur ouvert), **T0+239 s** |
| 22:54:05    | deuxième rapport de l'agent, porteur du constat                  |
| 22:55:05    | passage suivant : e-mail « Fichier critique absent : wp-config.php », **T0+299 s** |

```txt
RESULT {"t0":"2026-10-15T22:50:06.000Z","first_alert_s":239,"agent_s":299,"external_s":239,"mails":3,"survivors":0}
```

Trois e-mails, un par incident, aucun avant T0. Aucun processus restant à la
fin (vérifié aussi par la liste des processus), aucun avertissement ni erreur
dans le journal de `vigie serve`. Les deux délais tombent dans l'enveloppe du
pire cas simulé (299 s).

## 3. Production, sans risque

Fait le 2026-10-16, avec l'accord de l'utilisateur.

On ne touche jamais `wp-config.php`, `.htaccess` ni l'installeur en production.
On utilise un fichier témoin :

1. Ajouter `.vigie-canary` à `critical[]` de la config de l'agent du site A,
   déposer le fichier (vide) dans la racine du site, attendre un rapport sain.
2. Le supprimer en notant T0 ; attendre l'e-mail et noter T_alerte.
3. Le restaurer ; attendre l'e-mail de clôture.

Le témoin est restauré vide : même empreinte que celle de la référence, donc
pas d'avertissement `agent:integrity`. Il reste en place, toujours dans
`critical[]`, pour une prochaine reprise. La config d'avant le test est
sauvegardée à côté de `config.json` (`config.json.bak-20261016`).

Résultat du 2026-10-16 (heures lues dans la base du veilleur, colonnes
`opened_at`, `open_notified_at`, `closed_at`, `close_notified_at` de
l'incident) :

| Heure (UTC) | Événement                                                        |
| ----------- | ---------------------------------------------------------------- |
| 06:22:58    | témoin posé, `.vigie-canary` ajouté à `critical[]`, `--dry-run` sans constat |
| 06:25:09    | rapport sain, le témoin entre dans la référence sans incident    |
| 06:55:04    | **T0** : `.vigie-canary` supprimé                                |
| 06:55:08    | rapport de l'agent porteur du constat, incident ouvert (`critical-file`, critique) |
| 06:56:00    | e-mail « Fichier critique absent : .vigie-canary », **T0+56 s**  |
| 06:58:25    | témoin restauré                                                  |
| 07:00:08    | rapport sain, incident clos                                      |
| 07:01:00    | e-mail de clôture reçu (premier signal 06:55:08, rétabli 07:00:08), 2 min 35 s après la restauration |

56 s est un meilleur cas : la tâche planifiée de l'agent est partie 4 s
après la suppression. Le délai dépend du décalage entre l'incident et le
passage suivant de l'agent ; le pire cas reste celui de la simulation
(299 s). Critère de la tâche 4 tenu : alerte sous 10 min, e-mail de clôture
après la restauration.

## 4. Surveillance du veilleur

À faire par l'utilisateur.

Une seule sonde externe : elle couvre la panne du VPS ou du veilleur, que le
veilleur ne peut pas signaler lui-même.

1. Ajouter une sonde HTTP(s) UptimeRobot sur `/health` du veilleur, toutes
   les 5 min, en alerte sur toute réponse autre que 2xx. `/health` répond 503
   quand le dernier `tick` a plus de 3 min.
2. Couper `vigie-tick.timer` une dizaine de minutes (3 min avant le 503, puis
   jusqu'à 5 min avant le passage de la sonde), vérifier que UptimeRobot
   alerte, le réactiver et attendre son e-mail de retour.

Écart au plan : la sonde par mot-clé sur la page surveillée **reste en place**
au lieu d'être remplacée. L'offre gratuite compte 50 sondes, il n'y a pas à
choisir ; elle sert de second avis indépendant du veilleur sur le contrôle
`content` (voir `src/checks/content.rs`).

Conditions de l'offre gratuite, consultées le 2026-10-16 :

- [Conditions d'utilisation](https://uptimerobot.com/terms), section 3 :
  « UptimeRobot is available for any use, including commercial and business
  use. » Dernière entrée du journal des modifications : 2026-05-26.
- [Fair Use Policy](https://uptimerobot.com/terms-fair-use/) (mise à jour du
  2026-06-24), applicable à toutes les offres, même phrase.
- Limites qui comptent ici, section 14 et section 2 : pas de revente ni de
  marque blanche (« UptimeRobot data, status pages, alerts, and API responses
  may not be repackaged, white-labeled, or offered to third parties ») et un
  seul compte (« only having a single account »).

Réponse : surveiller les sites d'une prestation payante avec l'offre gratuite
est permis ; offrir au client les alertes ou une page de statut UptimeRobot
(reconditionnées ou non) demande l'autorisation d'UptimeRobot. Les alertes
d'UptimeRobot restent donc à usage interne ; ce que voit le client vient du
veilleur. Des articles de tiers de
2024 décrivent une offre gratuite réservée à un usage non commercial : ce
n'est plus le texte en vigueur.

Résultat du 2026-10-16 (sonde HTTP(s) sur `/health`, toutes les 5 min), relevé
toutes les 10 s par `curl` sur `/health` :

| Heure (UTC) | Événement                                                        |
| ----------- | ---------------------------------------------------------------- |
| 23:06:00    | dernier `tick` (`last_tick` 1792105560)                          |
| 23:06:52    | `systemctl stop vigie-tick.timer`                                |
| 23:09:00    | `/health` : 200, `age_seconds` 179                               |
| 23:09:10    | `/health` : 503, `"status":"late"`, `age_seconds` 189            |
| 23:14       | e-mail UptimeRobot « Monitor is DOWN », panne vue depuis Ashburn (USA) ; heure à la minute près, lue dans le client de messagerie (01:14 heure de Paris) |
| 23:15:53    | `systemctl start vigie-tick.timer` (heure déduite : `date -u` à 23:17:03 après `sleep 70`) |
| 23:17:03    | `/health` en local : 200                                         |
| 23:19       | e-mail UptimeRobot « Monitor is UP », retour vu depuis l'Amérique du Nord (01:19 heure de Paris, à la minute près) |

Délai : environ 5 min entre le 503 et l'e-mail, borné par l'intervalle de la
sonde ; 8 min environ après le dernier `tick`. Retour : e-mail environ 3 min
après la relance du timer. Critère de la tâche 5 tenu : UptimeRobot alerte
quand `tick` est arrêté.

## Écarts au plan

- **Pas de `src/clock.rs`.** L'heure logique était déjà injectée avant cette
  phase : `tick::run_with(config, now, …)`, `ingest::ingest(…, now)`,
  `heartbeat::evaluate(…, now)` et `serve::router_with_clock`. Aucun appel à
  l'horloge système ne reste dans `tick`, `ingest` ni `heartbeat` ; `tick` ne
  garde `Instant::now()` que pour ses budgets de durée, qui ne décident d'aucune
  échéance. Ailleurs, `checks/tls.rs` lit l'heure réelle pour les jours
  restants du certificat, comme rustls pour sa validité.
- **Pas de dossier `tests/fixtures/incident-2026-09-07/`.** Les pages de
  l'incident sont des fixtures HTML à plat dans `tests/fixtures/`
  (`kb_incident.html`, `setup_config_open.html`…), servies par
  `tests/support/incident_site.rs` ; l'arborescence sans `wp-config.php` est
  celle de l'agent (`agent/php/tests/fixtures/wp-healthy`, dont la reprise
  locale supprime le fichier).
- **`tick` de la reprise locale : un exemple Cargo, pas le binaire.**
  `vigie tick` ne fait confiance qu'aux autorités publiques et envoie par SMTP
  STARTTLS. `examples/replay_local.rs` appelle le même `tick::run_with`, avec
  l'autorité de test du site local et des e-mails écrits sur la sortie
  standard. Le binaire de production n'a ni option ni mode de test ; l'exemple
  n'est pas dans son build. `vigie serve` et l'agent PHP, eux, sont les vrais.
