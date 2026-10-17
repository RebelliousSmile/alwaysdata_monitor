---
status: pending
---

# Instruction: Dérogations auditées et CLI

Lecture des résultats par la CLI, et la seule écriture de F7 : la dérogation, avec aperçu puis `--apply` et inscription dans la chaîne d'audit du site. **Prérequis** : phase 2.

## Architecture projection

```txt
.
└── vigie/
    ├── README.md                      ✏️ commandes site components | vulns | vulns-ack, vulns report
    ├── src/
    │   ├── main.rs                    ✏️ SiteAction::{Components, Vulns { all }, VulnsAck { purl, advisory, reason, until, revoke, apply }} ; VulnsAction::Report ; status : une ligne « failles » par site
    │   ├── command/audit.rs           ✏️ évènements vuln-waived et vuln-waiver-revoked documentés dans Entry.event
    │   └── vulns/
    │       └── matching/
    │           ├── waiver_store.rs    ✅ add / revoke (transaction IMMEDIATE : ligne + audit::append) ; active(site) ; état : valide, expirée, caduque (version, KEV)
    │           └── report.rs          ✅ lignes de site vulns, site components et vulns report : texte assaini, sans caractère de contrôle
    └── tests/
        ├── vulns_cli.rs               ✏️ (F1) site components, site vulns, vulns report sur une base rapprochée
        └── vulns_waivers.rs           ✅ aperçu, --apply, refus, audit vérifié, retrait, expiration vue par tick
```

## Test Scope

```mermaid
journey
  section Lecture
    vigie site components site-a => une ligne par composant : purl, version, portée, source, nombre de failles, gravité maximale ; trié gravité puis purl: 5: cli
    vigie site vulns site-a => failles touchées et inconnues hors dérogation : groupe, composant, version, correctif, gravité et règle, KEV, EPSS, liens, attribution, redistribution: 5: cli
    vigie site vulns site-a --all => ajoute les groupes sous dérogation (motif, échéance) et les dérogations expirées ou caduques: 5: cli
    vigie vulns report => sites, critiques d'abord, puis avertissements ; en-tête « document interne » ; âge des sources et constats vulns-sync ouverts: 5: cli
    vigie status => ligne « failles : 2 critiques, 3 avertissements ; inventaire du AAAA-MM-JJ » par site surveillé: 5: cli
  section Dérogation
    vigie site vulns-ack site-a pkg:wordpress/plugin/exemple-plugin CVE-2099-0002 --reason "…" --until 2099-02-01 => aperçu (groupe, version, échéance, audit), rien d'écrit: 5: cli
    Même commande avec --apply => ligne vuln_waivers, entrée vuln-waived dans la chaîne d'audit de site-a, signée: 5: cli
    vigie site audit site-a --verify => chaîne intègre, entrée de la dérogation présente: 5: cli
    tick suivant => groupe sous dérogation, incident passé en information: 5: cli
    --revoke --reason "…" --apply => retrait audité ; tick suivant => gravité rendue, e-mail d'ouverture: 5: cli
  section Refus, code 2
    Faille dont un CVE est dans KEV => refus « faille exploitée (KEV) : dérogation interdite »: 1: cli
    --until au-delà de 90 jours, dans le passé ou illisible => refus: 1: cli
    Motif vide ou de 501 caractères => refus: 1: cli
    Composant absent du dernier inventaire, version inconnue, faille qui ne touche pas le composant => refus: 1: cli
    purl ou identifiant mal formé, site inconnu ou sans [sites.inventory] => refus: 1: cli
    Sans [commands] (pas de clé d'audit) => refus, message clair: 1: cli
  section Base absente ou antérieure
    Commandes de lecture => « aucune base de failles », code 0 ; vulns-ack => code 2: 1: cli
  section Sortie
    Identifiant, lien ou attribution avec ESC, U+202E => U+FFFD, aucun caractère de contrôle: 1: cli
```

## Tasks to do

1. **`waiver_store.rs`** :
   - `add(store, audit_key, Waiver, now) -> Result<WaiverId, WaiverRefusal>` : relit dans la même transaction IMMEDIATE l'`active_run` du site (composant présent, version connue et égale à celle saisie ou installée, groupe `Affected` ou `Unknown` contenant l'identifiant normalisé), `StoreTables` (aucun CVE du groupe dans KEV), `validate` de la phase 1 ; écrit la ligne et l'entrée d'audit (`audit::append`, chaîne du site, `event = "vuln-waived"`, `detail` JSON : purl sans version, faille, version, échéance, motif, opérateur) et garde son hash ;
   - opérateur = nom du compte de `getpwuid(geteuid())` (jamais `$USER`), uid seul hors Unix ou sans entrée passwd (règle de F3, `phase-4.md` l. 60) ;
   - `revoke(store, audit_key, id, reason, now)` : `revoked_at`, `revoke_reason`, entrée `vuln-waiver-revoked` ;
   - `active(site, now)` et `all(site)` avec leur état (`valide`, `expirée`, `caduque : version`, `caduque : KEV`, `retirée`).
2. **`main.rs`** :
   - `vigie site components <site>` ; `vigie site vulns <site> [--all]` ; lecture par `Store::open_read`, schéma vérifié contre `SCHEMA_VULNS_MATCH` ; site inconnu ou sans `[sites.inventory]` → `UsageError` (code 2) ;
   - `vigie site vulns-ack <site> <purl> <faille> --reason <motif> --until <AAAA-MM-JJ> [--apply]` et `vigie site vulns-ack <site> --revoke <id> --reason <motif> [--apply]` : aperçu (site, composant, version, groupe et ses membres, échéance, « inscrit dans l'audit du site »), puis `--apply` ; `[commands]` exigé pour `--apply` (clé d'audit, comme `enqueue`, `main.rs` l. 848) ;
   - `vigie vulns report` : tous les sites surveillés, critiques d'abord, puis avertissements, puis informations (comptes seuls) ; par site : composants touchés, groupes, KEV, correctifs ; en tête « document interne : contient des données Wordfence ou Friends-Of-Presta, ne pas transmettre » si un groupe est `Internal` ou `FactsOnly` ; en pied, l'âge de chaque source (`sync_state`, F2) et les constats `vulns-sync` ouverts ;
   - `vigie status` : ligne « failles » par site surveillé (comptes par gravité, date du dernier inventaire, « inventaire périmé » le cas échéant).
3. **`report.rs`** : rendu texte commun, chaque champ passé par `LogText`, attributions entières, liens en texte ; version CVSS en décimal, EPSS en %.
4. **`command/audit.rs`** : commentaire d'`Entry.event` complété (`vuln-waived`, `vuln-waiver-revoked`) ; aucune autre modification ; `--verify` existant couvre ces entrées.
5. **Tests** : `vulns_cli.rs` (cas « Lecture », « Base absente », « Sortie ») sur une base rapprochée par `tick::run_with` ; `vulns_waivers.rs` (cas « Dérogation » et « Refus », `FakeClock`, clé d'audit de test, vérification de la chaîne par `audit::verify`).
6. **`README.md`** : les quatre commandes, l'aperçu puis `--apply`, la limite de 90 jours et l'interdiction KEV.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Toute dérogation écrite a son entrée d'audit dans la même transaction (`audit::verify` vert, correspondance par `audit_hash`) ; aucune dérogation KEV, sans version, au-delà de 90 jours ou sans motif ne s'écrit |
| 2 | Codes 0, 1, 2 conformes au reste de la CLI ; sans `--apply`, aucune écriture (base identique octet pour octet) ; `vulns report` trie critiques d'abord |
| 3 | Aucune sortie ne contient de caractère de contrôle ; attributions jamais tronquées |
| 5 | Cas du Test Scope verts ; l'expiration et le retrait sont vus par le `tick` suivant (même incident, e-mail d'ouverture) |
| 1-6 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
