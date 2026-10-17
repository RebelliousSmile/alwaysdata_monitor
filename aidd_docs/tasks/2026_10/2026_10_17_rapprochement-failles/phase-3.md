---
status: pending
---

# Instruction: Dérogations auditées et CLI

Lecture des résultats par la CLI, et la seule écriture de F7 : la dérogation, avec aperçu puis `--apply` et inscription dans la chaîne d'audit du site, **par empreinte du motif**. **Prérequis** : phase 2.

## Architecture projection

```txt
.
└── vigie/
    ├── README.md                      ✏️ commandes site components | vulns | vulns-ack, vulns report
    ├── src/
    │   ├── main.rs                    ✏️ SiteAction::{Components, Vulns { all }, VulnsAck { purl, advisory, source, reason, until, revoke, apply }} ; VulnsAction::Report ; status : une ligne « failles » par site
    │   ├── command/audit.rs           ✏️ évènements vuln-waived et vuln-waiver-revoked documentés dans Entry.event
    │   └── vulns/
    │       └── matching/
    │           ├── waiver_store.rs    ✅ add / revoke (transaction IMMEDIATE : ligne + audit::append avec reason_sha256) ; active(site) ; état : valide, expirée, caduque (version, groupe changé, KEV), retirée
    │           └── report.rs          ✅ rendu texte de site vulns, site components et vulns report : assaini, sans caractère de contrôle
    └── tests/
        ├── vulns_cli.rs               ✏️ (F1) site components, site vulns, vulns report sur une base rapprochée
        └── vulns_waivers.rs           ✅ aperçu, --apply, refus, audit par empreinte, retrait, expiration et groupe changé vus par tick
```

## Test Scope

```mermaid
journey
  section Lecture
    vigie site components site-a => une ligne par (source, composant) : source, purl, version, portée, nombre de failles, gravité maximale ; trié gravité puis purl: 5: cli
    vigie site vulns site-a => groupes touchés et inconnus hors dérogation : groupe, composant, version par source, correctif, gravité et règle, KEV, EPSS, liens, attribution, redistribution: 5: cli
    vigie site vulns site-a --all => ajoute groupes d'information, groupes sous dérogation (échéance, motif) et dérogations expirées, caduques ou retirées: 5: cli
    vigie vulns report => sites, critiques d'abord ; en-tête « document interne » ; âge des sources et constats vulns-sync ouverts: 5: cli
    vigie status => ligne « failles : 2 critiques, 3 avertissements ; inventaire agent du AAAA-MM-JJ » par site surveillé, « inventaire périmé » le cas échéant: 5: cli
  section Dérogation
    vigie site vulns-ack site-a pkg:wordpress/plugin/exemple-plugin CVE-2099-0002 --reason "…" --until 2099-02-01 => aperçu (source agent, groupe et covered_ids, version, échéance, audit), rien d'écrit: 5: cli
    Même commande avec --apply => ligne vuln_waivers (covered_ids gardés), entrée vuln-waived signée dans la chaîne de site-a: 5: cli
    Entrée d'audit relue => detail = { purl, faille, échéance, opérateur, reason_sha256 } ; le texte du motif semé est absent de la chaîne: 5: cli
    vigie site audit site-a --verify => chaîne intègre: 5: cli
    tick suivant => groupe sous dérogation, gravité recalculée: 5: cli
    --revoke <id> --reason "…" --apply => entrée vuln-waiver-revoked avec reason_sha256, motif absent de la chaîne ; tick suivant => gravité rendue: 5: cli
    site remove puis lecture de la chaîne => aucun motif en clair nulle part: 1: cli
  section Refus, code 2
    --until au-delà de 90 jours, dans le passé ou illisible ; motif vide ou de 501 caractères => refus avant toute ouverture de la base: 1: cli
    Faille dont un CVE est dans KEV => refus « faille exploitée (KEV) : dérogation interdite »: 1: cli
    Composant absent du dernier inventaire de la source, version inconnue (« acquitter avec vigie ack »), faille qui ne touche pas le composant => refus: 1: cli
    --source ci sans source ci déclarée ; deux sources déclarées sans --source => refus: 1: cli
    purl ou identifiant mal formé, site inconnu ou non surveillé => refus: 1: cli
    Sans [commands] (pas de clé d'audit) => refus, message clair: 1: cli
  section Base absente ou antérieure
    Commandes de lecture => « aucune base de failles », code 0 ; vulns-ack => code 2: 1: cli
  section Sortie
    Identifiant, lien ou attribution avec ESC, U+202E => U+FFFD, aucun caractère de contrôle: 1: cli
```

## Tasks to do

1. **`waiver_store.rs`** :
   - `add(store, audit_key, Waiver, now) -> Result<WaiverId, WaiverRefusal>` : `validate` de la phase 1 **avant** l'ouverture de la base ; puis, dans une transaction IMMEDIATE, relit l'`active_run` de la source (composant présent, version connue et égale, groupe `Affected` ou `Unknown` contenant l'identifiant normalisé), `StoreTables` (aucun CVE du groupe dans KEV), fixe `covered_ids` = tous les identifiants et alias du groupe ; écrit la ligne et l'entrée d'audit (`audit::append`, chaîne du site, `event = "vuln-waived"`, `detail` = JSON `{ "purl": <purl indexé>, "advisory": <identifiant>, "until": <date>, "operator": <compte>, "reason_sha256": <hex> }`) et garde son hash ;
   - opérateur = nom du compte de `getpwuid(geteuid())` (jamais `$USER`), uid seul hors Unix ou sans entrée passwd (règle de F3, `phase-4.md` l. 62) ;
   - `revoke(store, audit_key, id, reason, now)` : `revoked_at`, `revoke_reason`, entrée `vuln-waiver-revoked` de même forme (`reason_sha256` du motif de retrait) ;
   - `active(site, now)`, `all(site)` avec leur état.
2. **`main.rs`** :
   - `vigie site components <site>`, `vigie site vulns <site> [--all]` : `Store::open_read`, schéma vérifié contre `SCHEMA_VULNS_MATCH` ; site inconnu ou non surveillé → `UsageError` (code 2) ;
   - `vigie site vulns-ack <site> <purl> <faille> [--source agent|ci] --reason <motif> --until <AAAA-MM-JJ> [--apply]` et `vigie site vulns-ack <site> --revoke <id> --reason <motif> [--apply]` : `--until` et `--reason` validés avant toute lecture ; `--source` obligatoire si deux sources sont déclarées ; aperçu (site, source, composant, version, groupe, `covered_ids`, échéance, « inscrit dans l'audit du site par empreinte du motif »), puis `--apply` ; `[commands]` exigé (clé d'audit, comme `enqueue`, `main.rs` l. 848) ; version inconnue → refus qui renvoie vers `vigie ack <incident>` ;
   - `vigie vulns report` : sites surveillés, critiques d'abord, puis avertissements, puis comptes d'information ; en tête « document interne » si un groupe est `Internal` ou `FactsOnly` ; en pied l'âge de chaque source (`sync_state`, F2) et les constats `vulns-sync` ouverts ;
   - `vigie status` : ligne « failles » par site surveillé.
3. **`report.rs`** : rendu commun, `LogText` partout, attributions entières relues depuis les identifiants de source, liens en texte, CVSS en décimal, EPSS en %.
4. **`command/audit.rs`** : commentaire d'`Entry.event` complété (`vuln-waived`, `vuln-waiver-revoked`) ; rien d'autre.
5. **Tests** : `vulns_cli.rs` (« Lecture », « Base absente », « Sortie ») sur une base rapprochée par `tick::run_with` ; `vulns_waivers.rs` (« Dérogation » et « Refus », `FakeClock`, clé d'audit de test, `audit::verify`, motif semé `motif-secret-xyz` cherché dans toute la chaîne et dans la base après `site remove`).
6. **`README.md`** : les quatre commandes, l'aperçu puis `--apply`, 90 jours, KEV, audit par empreinte, version inconnue seulement acquittable.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Toute dérogation a son entrée d'audit dans la même transaction (`audit::verify` vert, correspondance par `audit_hash`) ; aucun texte de motif dans la chaîne (test du motif semé) ; aucune dérogation KEV, sans version, au-delà de 90 jours ou sans motif |
| 2 | Codes 0, 1, 2 conformes ; sans `--apply`, base identique octet pour octet ; refus de `--until` et `--reason` sans ouvrir la base ; `vulns report` trie critiques d'abord |
| 3 | Aucune sortie avec caractère de contrôle ; attributions entières |
| 5 | Cas du Test Scope verts ; ajout, retrait, expiration et « groupe changé » vus par le `tick` suivant |
| 1-6 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucune donnée de production dans les fichiers ajoutés |
