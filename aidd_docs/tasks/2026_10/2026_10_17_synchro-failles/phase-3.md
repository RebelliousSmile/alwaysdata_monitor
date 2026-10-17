---
status: pending
---

# Instruction: Constat vulns-sync, timer systemd, documentation et synchronisation réelle

## Architecture projection

```txt
.
├── CHANGELOG.md                       ✏️ entrée F2 (#16) sous Unreleased
└── vigie/
    ├── README.md                      ✏️ vigie vulns sync, [vulns], timer
    ├── deploy/
    │   ├── provision.sh               ✏️ installe et active vigie-vulns-sync.service et .timer
    │   └── systemd/
    │       ├── vigie-vulns-sync.service ✅ oneshot, durcissements de tick, Nice, IOSchedulingClass=idle, OOMScoreAdjust=500, MemoryMax, TimeoutStartSec=3h
    │       └── vigie-vulns-sync.timer   ✅ OnCalendar=*-*-* 03:40:00, RandomizedDelaySec=45min, Persistent=true
    ├── src/
    │   ├── capability.rs              ✏️ Control::VulnsSync (« vulns-sync »), Needs::Watcher, WATCHER_SITE = "_veilleur" ; watched_by_watcher(config, check, key)
    │   ├── store.rs                   ✏️ close_unwatched(is_watched: impl Fn(&Incident) -> bool, now)
    │   ├── tick.rs                    ✏️ évaluation de fraîcheur des sources déclarées, réconciliation vulns-sync ; prédicat de close_unwatched sur l'incident ; libellé du pseudo-site dans les e-mails
    │   ├── main.rs                    ✏️ vigie status : une ligne par source de failles (âge de la dernière réussite, dernière issue)
    │   └── vulns/sync/
    │       └── freshness.rs           ✅ STALE_AFTER = 3 jours ; findings(declared, states, declared_since, now) -> Vec<Finding>, fonction pure
    ├── tests/
    │   ├── vulns_freshness.rs         ✅ FakeClock : ouverture après 3 jours, clôture rétabli, source retirée, jamais synchronisée
    │   └── capability.rs              ✏️ Control::ALL à 14, vulns-sync jamais surveillé pour un site, surveillé pour _veilleur selon [vulns]
    └── docs/
        ├── failles.md                 ✏️ section « Synchronisation (F2) » ; OSV : plafonds, lecteur zip, incrémental écarté, volumes ; « À vérifier depuis le VPS » mis à jour
        ├── hebergement.md             ✏️ timer, espace disque, mémoire, relevé masqué de la synchronisation réelle, Statut
        └── decisions.md               ✏️ sous-section « Synchronisation des failles (issue #16) »
```

## Test Scope

```mermaid
journey
  section Registre
    Control vulns-sync déclaré => nom unique, jamais surveillé pour un site de la configuration: 5: lib
    Pseudo-site _veilleur => refusé comme identifiant de site par la configuration: 1: lib
  section Fraîcheur avec FakeClock
    Dernière réussite il y a 3 jours moins 1 s => aucun constat: 5: tick
    Dernière réussite il y a 3 jours plus 1 s => avertissement _veilleur/vulns-sync/osv-npm, e-mail d'ouverture: 5: tick
    Synchronisation réussie (loaded, unchanged ou not_modified) puis tick => incident clos rétabli: 5: tick
    Échecs répétés après une réussite récente => aucun constat avant 3 jours: 1: tick
    Source jamais synchronisée => constat 3 jours après le premier tick qui la voit déclarée: 1: tick
    Source retirée de [vulns] sources => incident clos plus surveillé, jamais rétabli: 1: tick
    Section [vulns] retirée => tous les incidents vulns-sync clos plus surveillé: 1: tick
    Base sans tables de failles (schéma antérieur) => tick inchangé, aucune erreur: 1: tick
  section Affichage
    E-mail du constat => « veilleur (bases de failles) », jamais « site retiré de la configuration »: 5: tick
    vigie status => une ligne par source, âge et dernière issue: 5: cli
  section Déploiement
    systemd-analyze verify des deux unités => sans erreur: 5: system
    provision.sh rejoué => idempotent, timer actif: 5: system
  section Relevé réel, à la main sur le VPS
    vigie vulns sync => trois sources chargées, durée, tailles, comptes, disque et mémoire relevés et masqués: 5: operator
    Second vulns sync => not_modified ou unchanged pour les sources inchangées: 5: operator
```

## Tasks to do

1. **`capability.rs`** :
   - `Control::VulnsSync`, nom `vulns-sync`, ajouté en fin de `Control::ALL` (14 contrôles) ; `cms()` → `ALL_CMS` ; `needs()` → `Needs::Watcher` ; `is_agent()` → `false` ; `match` sans joker partout ;
   - `Needs::Watcher` : `Control::watched(site, ctx)` rend **toujours `false`** pour un site de la configuration ;
   - `pub const WATCHER_SITE: &str = "_veilleur"` (hors de la grammaire `[a-z0-9-]` des identifiants de site : un test le vérifie contre le validateur de `config.rs`) ;
   - `watched_by_watcher(config, check, key) -> bool` : `check == "vulns-sync"` et `key` dans `registry::declared(config)` ; tout autre contrôle du pseudo-site → `false` (fail-closed) ; commentaire d'en-tête du module complété (contrôles du veilleur).
2. **`store.rs`** : `close_unwatched` prend `impl Fn(&Incident) -> bool` ; `Incident` expose la clé du constat (dernier segment de `key` après `site/contrôle/`) par une méthode `finding_key()` ; appels et tests existants adaptés sans changement de comportement.
3. **`vulns/sync/freshness.rs`** : `STALE_AFTER = 259_200` ; `findings(declared: &[&str], states: &[(id, Option<last_success_at>, last_outcome, last_error)], declared_since: impl Fn(&str) -> i64, now) -> Vec<Finding>` : un `Finding::new(WATCHER_SITE, "vulns-sync", Warning, <source>, détail)` par source dont `now − (last_success_at ou declared_since) > STALE_AFTER` ; détail sans donnée de la source autre que l'issue et la date (« base osv-npm non synchronisée depuis 4 jours ; dernière issue : failed (délai dépassé) »), assaini et borné.
4. **`tick.rs`** : après le silence des agents et avant `close_unwatched`, si `[vulns]` déclare des sources et que le schéma a `vuln_sources` (`SCHEMA_VULNS_SYNC`) : écrit `meta vulns.declared.<source>` au premier passage qui la voit (jamais réécrit), lit l'état des sources, `store.reconcile(WATCHER_SITE, "vulns-sync", &findings, now)` et `record_result` ; une erreur de lecture est journalisée et n'arrête pas le passage. `watched_by_tick` : incident du pseudo-site → `capability::watched_by_watcher(config, check, incident.finding_key())`, sinon règle actuelle. `site_url` : `WATCHER_SITE` → « veilleur (bases de failles) ».
5. **`main.rs`** : `vigie status` imprime, si `[vulns]` est déclarée, `failles : <source> réussie il y a <âge> (dernière issue : …)` par source, ou « jamais synchronisée » ; lecture seule (`Store::open_read`), schéma antérieur → « aucune base de failles ».
6. **Unités systemd** : `vigie-vulns-sync.service` (`Type=oneshot`, `User=vigie`, `ExecStart=/home/vigie/vigie/bin/vigie vulns sync`, `TimeoutStartSec=3h`, `Nice=10`, `IOSchedulingClass=idle`, `OOMScoreAdjust=500`, `MemoryMax=512M` provisoire, mêmes `Condition*` et durcissements que `vigie-tick.service`, `ReadWritePaths=/home/vigie/vigie/data`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`) ; `vigie-vulns-sync.timer` (`OnCalendar=*-*-* 03:40:00`, `RandomizedDelaySec=45min`, `Persistent=true`) ; `provision.sh` les installe et active le timer, idempotent ; `systemd-analyze verify` vert (à la main ou en CI si disponible).
7. **Tests** : `vulns_freshness.rs` (section « Fraîcheur » : base remplie par `Load` et `mark_fresh`/`record_outcome` de la phase 2, `tick::run_with` avec `FakeClock` et `MemoryNotifier`, e-mail vérifié) ; `capability.rs` (section « Registre ») ; test existant de `close_unwatched` adapté.
8. **Documentation** :
   - `failles.md` : section « Synchronisation (F2) » : commande, timer, sources et identifiants, ordre, plafonds par source et leur mesure, lecteur zip (sous-ensemble admis, refus), rien d'extrait sur disque, requête conditionnelle et empreinte, garde de rétrécissement, bail, constat `vulns-sync` et pseudo-site, `modified_id.csv` évalué et écarté (raisons et chiffres du 2026-10-17), licences et attributions par préfixe (renvoi F1), volumes ; « Hôtes à joindre » inchangé ; « À vérifier depuis le VPS » : joignabilité de `osv-vulnerabilities.storage.googleapis.com` cochée au relevé ;
   - `hebergement.md` : section « Synchronisation des failles (issue #16) » : installation du timer, `systemctl list-timers`, lancement à la main, lecture du journal (`journalctl -u vigie-vulns-sync`), espace disque (dump transitoire ≤ plafond compressé, deux générations pendant un chargement, réserve de 1 Gio), mémoire ; ligne du Statut ;
   - `decisions.md` : sous-section « Synchronisation des failles (issue #16) » de « Failles connues », une ligne par décision du plan et sa raison, écarts à l'issue (ureq au lieu de reqwest, `fetch` en flux, FriendsOfPHP retiré) ;
   - `README.md`, `CHANGELOG.md`.
9. **Synchronisation réelle, à la main sur le VPS** (après déploiement, hors CI) : `vigie vulns sync`, puis `vigie vulns sources`, `du -sh data/`, `df -h ~`, `systemctl show vigie-vulns-sync -p MemoryPeak` (ou `/usr/bin/time -v`) ; second lancement ; relevé collé dans `hebergement.md` avec **valeurs masquées** (aucun nom de site, domaine ni adresse réels ; ETag tronqués) ; plafonds, `MemoryMax` et réserve de disque ajustés si une mesure s'approche à moins d'un facteur 2 ; durée npm comparée au seuil de 30 min qui rouvrirait la question de l'incrémental.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Section « Registre » verte ; `capability.rs` : `Control::ALL` à 14, noms uniques ; aucun incident `vulns-sync` ne peut s'ouvrir sur un site de la configuration ; `close_unwatched` garde son comportement pour les sites (tests existants verts) |
| 3-4, 7 | Section « Fraîcheur » verte avec `FakeClock` ; le constat s'ouvre à 3 jours + 1 s et pas avant, se clôt « rétabli » après une réussite, « plus surveillé » après retrait de la source ; `tick` sur une base sans tables de failles inchangé |
| 5 | `status` affiche les sources ; sans `[vulns]`, aucune ligne de failles |
| 6 | Unités vérifiées par `systemd-analyze verify` ; `provision.sh` rejoué sans effet ; `systemd-analyze security vigie-vulns-sync.service` relevé dans `hebergement.md`, au plus celui de `vigie-tick.service` |
| 8 | `failles.md`, `hebergement.md` et `decisions.md` couvrent chaque décision et chaque limite du plan |
| 9 | Relevé réel consigné et masqué (durée, tailles, comptes par source, place disque, mémoire maximale) ; second lancement en `not_modified` ou `unchanged` pour les sources inchangées |
| 1-9 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
