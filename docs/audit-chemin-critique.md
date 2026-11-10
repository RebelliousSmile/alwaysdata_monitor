# Audit du chemin critique avant déploiement

Issue #4, plan `aidd_docs/tasks/2026_10/2026_10_16_registre-capacites/plan.md`,
phase 2. Le chemin critique va du passage de l'agent PHP (rapport, retrait de
commande, lot de logs) jusqu'à l'e-mail envoyé par `tick`, en passant par
`serve` et la base SQLite partagée.

Chaque point cite sa preuve : un test (fichier et nom), un job de
`.github/workflows/vigie.yml`, ou un relevé masqué. Sans preuve, il porte
**non vérifié** et l'action à faire. Les jobs CI cités :

- **test** : `cargo fmt`, `cargo clippy`, `cargo test --locked --all-targets`,
  sous `ubuntu-24.04` et `windows-latest` ;
- **agent PHP (8.1)** : `php vigie/agent/php/tests/run.php` dans l'image
  `php:8.1-cli` épinglée, sous Linux ;
- **bout en bout serve + agent PHP (8.1)** :
  `cargo test --test agent_e2e -- --ignored`, agent dans la même image, sous
  Linux ;
- **musl (zigbuild)** : binaire `x86_64-unknown-linux-musl`, vérifié statique,
  son empreinte SHA-256 affichée et le binaire publié (artefact `vigie-musl`,
  14 jours).

Les relevés sur le VPS sont masqués : le dépôt est public (hôtes, comptes et
sites remplacés par `<vps>`, `site A`…).

## Anti-rejeu

| Point | Preuve | État |
| --- | --- | --- |
| Rapport : `seq` strictement croissant, rejeu à l'identique refusé (404 silencieux, rien d'écrit) | `tests/ingest.rs` `every_refusal_is_the_same_silent_404_and_stores_nothing` (cas « rejeu ») ; job **test** | Vérifié |
| Rapport : `sent_at` à ±300 s de l'horloge du veilleur | même test (cas « décalage », 600 s) ; `src/report.rs` `MAX_CLOCK_SKEW` ; job **test** | Vérifié |
| Rapport : un rapport accepté par 60 s au plus | même test (cas « débit ») ; job **test** | Vérifié |
| Retrait de commande : `seq` croissant, horloge ±300 s, signature sur le préfixe `vigie-pull-v1\n` | `tests/commands.rs` `replays_forgeries_and_wrong_routes_get_the_silent_404` (rejeu 30 s plus tard, préfixe absent, horloge décalée), `pulls_are_rate_limited` ; `tests/store_concurrency.rs` (rejeu du dernier `seq` refusé après la contention) ; job **test** | Vérifié |
| Retrait de commande : nonce de la requête repris dans la réponse signée, nonce rejoué refusé par l'agent | `agent/php/tests/AgentTest.php` « commandes : réponse non signée par la clé épinglée, préfixe faux ou nonce rejoué : rien ne s'exécute », « nonce neuf » à chaque retrait ; `tests/commands_vectors.rs` ; jobs **agent PHP (8.1)** et **test** | Vérifié |
| Lot de logs : renvoi à l'identique compté une fois (`Duplicate`), plage à cheval refusée | `tests/logs_receive.rs` `a_resent_batch_counts_once_and_the_next_one_follows`, `an_overlapping_batch_is_refused_and_writes_nothing` ; `tests/agent_e2e.rs` `a_batch_of_logs_goes_end_to_end_and_a_resend_counts_once` ; `tests/store_concurrency.rs` (un renvoi tous les trois lots, sous contention) ; jobs **test** et **bout en bout** | Vérifié |
| Nom réservé `integrity` : tout le rapport refusé ; famille inconnue : constat écarté et compté, rapport accepté | `tests/ingest.rs` `an_agent_cannot_report_the_integrity_check_itself` ; `tests/capability.rs` `an_incident_of_a_retired_family_closes_as_unwatched_and_never_reopens`, `a_dropped_family_is_neither_restored_nor_recorded_ok` ; job **test** | Vérifié |

## `SQLITE_BUSY` sous charge

| Point | Preuve | État |
| --- | --- | --- |
| Six écrivains en parallèle sur une même base, chacun sa connexion : passages de `tick`, résultats et incidents, acquittements, rapports d'agent, retraits de commande signés, lots de logs (avec renvois) ; aucune écriture ne rend d'erreur, aucune n'est perdue (dernier tour de chaque écrivain relu à la fin) | `tests/store_concurrency.rs` `six_writers_in_parallel_raise_no_sqlite_busy_and_lose_nothing` ; job **test** (Linux et Windows) | Vérifié |
| Premier démarrage simultané de `serve` et `tick` sur une base neuve | `src/store.rs` `Store::open` (5 s de patience sur « occupé ») et la migration en transaction IMMEDIATE ; tests de migration de `src/store.rs` ; job **test** | Vérifié en un processus |
| Contention entre **processus** distincts (`serve` sous systemd et `tick` du timer) | Le test simule les processus par des threads à connexions séparées : SQLite y prend les mêmes verrous de fichier et de WAL. | **Non vérifié** entre processus. Action : sur le VPS, après le déploiement, lire `journalctl -u vigie-serve -u vigie-tick --since -24h \| grep -ci "database is locked\|busy"` (attendu : 0) |

## Délais

| Point | Preuve | État |
| --- | --- | --- |
| Agent face à un veilleur qui accepte la connexion sans répondre : rendu après `SEND_TIMEOUT` (lu dans `vigie-agent.php`), en code 1, « Envoi échoué » | `tests/agent_e2e.rs` `a_mute_veilleur_releases_the_agent_after_send_timeout` ; job **bout en bout** | Vérifié |
| Agent dont les verrous `state.lock` et `logs.lock` sont déjà pris (`LOCK_NB`) : n'attend pas, envoie son rapport, saute commandes et logs en le disant, sort en code 1 avant `SEND_TIMEOUT` | `tests/agent_e2e.rs` `a_held_lock_makes_the_agent_skip_without_waiting` ; job **bout en bout** | Vérifié |
| Contrôle externe d'un site qui ne répond pas : borné par le délai de requête | `tests/external_checks.rs` `a_hanging_site_is_unreachable_within_the_request_timeout` ; `src/http.rs` `refuses_to_start_a_request_after_the_deadline` ; job **test** | Vérifié |
| Budget du repli des logs, vérifié entre deux lots | `src/analysis/findings_tests.rs` `two_ticks_with_the_budget_spent_mid_series_count_nothing_twice` ; job **test** | Vérifié |
| `serve` : corps d'un rapport ou d'un lot non reçu en 10 s (`REPORT_BODY_TIMEOUT`) refusé | Code seul (`src/serve.rs`), aucun test ne fait traîner un corps | **Non vérifié**. Action : test d'un client qui envoie l'en-tête puis s'arrête, attendu 404 en 10 s et la raison « corps non reçu en 10 s » au journal |

## Cible réelle

Le VPS reçoit le binaire construit dans WSL par `scripts/deploy.mjs`, qui
compare l'empreinte envoyée à celle reçue ; le job **musl** construit le même
commit avec d'autres versions épinglées de cargo-zigbuild et de zig
(`hebergement.md`, « Build ») : les deux empreintes ne sont pas censées être
égales. Ce qu'on compare, c'est le binaire de la CI une fois copié sur la
cible.

| Point | Preuve | État |
| --- | --- | --- |
| Le binaire se compile en statique musl | job **musl (zigbuild)**, étape « binaire statique » (`file … \| grep -q "statically linked"`) | Vérifié en CI |
| Le binaire de la CI tourne sur le VPS (`--version`, `tick` à blanc) et son empreinte est celle du job | Relevé ci-dessous | **Non vérifié** : pas d'accès au VPS depuis la session qui a écrit cet audit. Action : faire le relevé ci-dessous et coller la sortie masquée ici |
| Aucun site sans runtime `php` n'a de clé d'agent (sinon : avertissement `typology`, contrôles d'agent coupés au déploiement) | Relevé ci-dessous | **Non vérifié**. Action : relevé ci-dessous **avant** le déploiement de ce binaire |

### Relevé : binaire de la CI sur la cible

Sur le poste, l'artefact `vigie-musl` du job **musl** du commit à déployer
téléchargé (`gh run download <run> -n vigie-musl`), et l'empreinte affichée
par l'étape « empreinte SHA-256 » de ce job notée :

```console
$ sha256sum vigie
<sha256 du job musl>  vigie
$ scp vigie vigie@<vps>:/tmp/vigie-ci
```

Sur le VPS, en `vigie`, sans toucher la base de production ni envoyer
d'e-mail : une copie de la base (`.backup` de SQLite) et une configuration
dont `database` pointe la copie et `password_file` un fichier absent (tout
envoi échoue et reste en attente dans la copie).

```console
$ sha256sum /tmp/vigie-ci
<même sha256 que le job musl>  /tmp/vigie-ci
$ chmod 700 /tmp/vigie-ci && /tmp/vigie-ci --version
vigie <version du commit>
$ install -d -m 700 /tmp/vigie-audit
$ sqlite3 ~/vigie/data/vigie.db ".backup /tmp/vigie-audit/vigie.db"
$ sed -e "s|^database = .*|database = '/tmp/vigie-audit/vigie.db'|" \
      -e "s|^password_file = .*|password_file = '/tmp/vigie-audit/absent'|" \
      ~/vigie/config.toml > /tmp/vigie-audit/config.toml
$ chmod 600 /tmp/vigie-audit/config.toml
$ /tmp/vigie-ci --config /tmp/vigie-audit/config.toml tick; echo code=$?
code=0
$ /tmp/vigie-ci --config /tmp/vigie-audit/config.toml status | head -3
base : /tmp/vigie-audit/vigie.db (schéma v14)
typologie : <empreinte>
  tick : <empreinte> (notée le <date>)
$ rm -rf /tmp/vigie-audit /tmp/vigie-ci
```

Attendu : même empreinte des deux côtés, `--version` du commit, `tick` en
code 0 sur la copie migrée en v14 (la migration 14 s'y joue, pas sur la base
de production). Les contrôles externes dus partent comme à chaque passage
(lectures HTTP des sites) ; rien n'est écrit sur un site. Masquer l'hôte, les dates et les empreintes de typologie si
la sortie est collée ici.

### Relevé : configuration du VPS

**Avant** le déploiement, avec le binaire en place (qui ne connaît pas encore
le registre) : un site qui a une clé d'agent (`site list`, troisième colonne
autre que `sans agent`) doit avoir le runtime `php` (quatrième colonne,
`php` explicite ou impliqué par `wordpress` et `prestashop`).

```console
$ ~/vigie/bin/vigie site list | awk -F'\t' '$3 != "sans agent" && $4 != "php" { print $1 }'
```

Attendu : aucune ligne. Une ligne nomme un site à corriger avant de déployer :
poser `runtime = "php"` dans son bloc `[[sites]]`, relancer `serve`. Après le
déploiement, `vigie status` le montrerait sinon en avertissement `typology`
et « non surveillé : runtime php absent » sur la ligne de l'agent.

Résultat à consigner (masqué : sites nommés « site A », « site B ») :

| Relevé | Date | Sortie |
| --- | --- | --- |
| Binaire de la CI sur la cible | — | **Non vérifié** |
| Configuration du VPS | — | **Non vérifié** |
