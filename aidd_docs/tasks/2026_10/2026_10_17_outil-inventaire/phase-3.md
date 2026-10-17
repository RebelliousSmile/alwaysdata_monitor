---
status: pending
---

# Instruction: Binaire `vigie-inventory` : CLI, clé, envoi, bout en bout, schéma

## Architecture projection

```txt
.
├── .github/workflows/vigie.yml          ✏️ job inventory-schema : cyclonedx-cli épinglé par SHA-256, validate --input-version v1_7 sur le BOM de chaque fixture
└── vigie/
    ├── Cargo.toml                       ✏️ [[bin]] vigie-inventory (path = src/bin/vigie-inventory.rs) ; aucune dépendance ajoutée
    ├── src/
    │   ├── bin/vigie-inventory.rs       ✅ clap : keygen, pubkey, sbom, push ; codes 0/1/2 ; aucun accès à config.toml ni à la base
    │   ├── inventory/tool.rs            ✅ logique testable du binaire : projet et lockfiles, clé (env ou fichier), signature, envoi ureq, messages
    │   ├── inventory/mod.rs             ✏️ pub mod tool
    │   └── command/key.rs               ➖ sign, load, create, DOMAIN_INVENTORY réutilisés tels quels
    └── tests/
        ├── inventory_tool_cli.rs        ✅ binaire réel (CARGO_BIN_EXE_vigie-inventory) : sous-commandes, options, codes, fichiers
        └── inventory_tool_e2e.rs        ✅ binaire réel contre serve::router_with sur 127.0.0.1 : push accepté, refus croisés des clés
```

## Test Scope

```mermaid
journey
  section Happy path
    keygen --out k => graine 0600 en création exclusive, clé publique seule sur stdout: 5: cli
    pubkey avec VIGIE_INVENTORY_KEY => même clé publique que keygen: 5: cli
    sbom --project-dir fixture --output sbom.json => BOM CycloneDX 1.7 seul, sans enveloppe, sans clé ni réseau: 5: cli
    push --dry-run => enveloppe non signée sur stdout, source ci, aucune connexion ouverte: 5: cli
    push vers un serve de test (site A static, sources = ["ci"], clé enregistrée) => 204, code 0, inventaire ci en base: 5: e2e
    push --output sbom.json => fichier écrit et inventaire envoyé: 5: e2e
    Second push inchangé 241 s plus tard (FakeClock) => 204, seen_at avancé, une seule ligne: 5: e2e
  section Edge case
    Corps signé par la clé d'inventaire rejoué sur /r/v1/report et /r/v1/logs => 404: 1: e2e
    Clé de rapport du site (VIGIE_INVENTORY_KEY = graine de l'agent) sur un site ["ci"] => 404, code 1: 1: e2e
    Clé d'inventaire d'un autre site => 404, code 1: 1: e2e
    Veilleur injoignable ou 5xx => code 1, message sans graine ni corps: 1: cli
    --endpoint http://192.0.2.10 => refus code 2 (https exigé hors boucle locale): 1: cli
    Réponse 301 vers un autre hôte => non suivie, code 1: 1: e2e
    Aucune clé : push => code 2 ; push --skip-without-key => message, code 0, rien envoyé: 1: cli
    VIGIE_INVENTORY_KEY et --key-file ensemble, graine illisible, fichier 0644 ou lien (Unix) => code 2: 1: cli
    keygen sur un fichier existant => code 2, fichier intact: 1: cli
    Aucun lockfile, nom inconnu, --lockfile ../hors, lien sortant, 11 --lockfile => code 2, rien écrit: 1: cli
    Lockfile corrompu => code 2, ni --output écrit ni envoi: 1: cli
    Projet de 2 001 composants => envoyé avec complete false, avertissement --omit-dev sur stderr: 1: e2e
    --version => vigie-inventory 0.1.0 (TOOL_VERSION): 1: cli
    Sortie et erreurs => ni graine, ni signature, ni nom de composant sur stderr: 1: cli
```

## Tasks to do

1. **Cible** : `[[bin]] name = "vigie-inventory"`, `path = "src/bin/vigie-inventory.rs"` dans `vigie/Cargo.toml` ; le binaire `vigie` existant ne change pas. Le job `musl` de `vigie.yml` construit les deux binaires ; son étape « binaire statique » vérifie aussi `target/x86_64-unknown-linux-musl/release/vigie-inventory` et affiche son empreinte.
2. **CLI** (`clap` derive, `version = TOOL_VERSION`) :
   - `keygen --out <fichier>` : `command::key::create(path)` (création exclusive, 0600, dossier vérifié) ; affiche la clé publique base64 et la commande à lancer sur le VPS (`vigie site inventory-key <site> add --pubkey …`) ; jamais la graine ;
   - `pubkey` : clé publique de la graine fournie (`VIGIE_INVENTORY_KEY` ou `--key-file`) ;
   - `sbom [--site S] [--output F]` : BOM seul (`name` = site ou `projet`), JSON indenté, écriture atomique (fichier temporaire du même dossier puis `rename`) ;
   - `push --site S --endpoint URL [--output F] [--dry-run] [--skip-without-key] [--key-file F]` ;
   - options communes : `--project-dir` (défaut `.`), `--lockfile` (répétable, 10 au plus), `--cms wordpress`, `--omit-dev`.
   Identifiant de site validé par la même règle que `config.rs` (`[a-z0-9-]`, 64 caractères au plus ; fonction rendue publique si besoin plutôt que recopiée).
3. **Projet** (`inventory/tool.rs`) : `canonicalize` du projet ; lockfiles explicites relatifs, sans `..`, `canonicalize` puis préfixe du projet (lien sortant refusé), sans doublon ; sinon les cinq noms à la racine ; `vigie:path` en `/` même sous Windows ; aucun lockfile → code 2 « aucun lockfile reconnu dans <dossier> ».
4. **Clé** : `VIGIE_INVENTORY_KEY` (base64 standard de 32 octets, espaces aux bords retirés) ou `--key-file` (`command::key::load`) ; les deux → code 2 ; la variable est lue puis le tampon effacé ; `SigningKey` gardée le temps de signer seulement.
5. **Envoi** : `seq` = heure Unix en ms, `sent_at` = heure Unix ; corps = enveloppe JSON compacte ; signature `command::key::sign(&key, DOMAIN_INVENTORY, &[&corps])` ; `ureq` (rustls, webpki-roots, `max_redirects(0)`, délai global 30 s) ; `POST <endpoint>/r/v1/inventory`, en-têtes `Content-Type: application/json`, `X-Vigie-Site`, `X-Vigie-Signature` (noms exacts de F5) ; `https` exigé sauf `127.0.0.1`/`[::1]` ; 204 → code 0 et résumé (« inventaire envoyé : N composants, complet » ou « incomplet : … ») ; autre statut ou erreur réseau → code 1 (« inventaire refusé (raison dans journalctl -u vigie-serve) » ou « veilleur injoignable : <genre d'erreur> », sans URL complète ni corps).
6. **Messages** : stderr en français, une ligne par fait (lockfiles lus, composants, ignorés, écartés, tronqués) ; jamais de nom ou de version de composant, de graine, de signature ou de corps ; `--dry-run` seul écrit l'enveloppe sur stdout, `sbom` sans `--output` le BOM.
7. **Tests CLI** (`tests/inventory_tool_cli.rs`) : binaire par `env!("CARGO_BIN_EXE_vigie-inventory")`, dossiers temporaires (`tempfile`), fixtures de la phase 2 copiées ; chaque cas « cli » du Test Scope ; capture de stderr vérifiée sans graine ni nom de composant (un paquet fictif nommé `secret-xyz` dans un lockfile fabriqué).
8. **Bout en bout** (`tests/inventory_tool_e2e.rs`) : `serve::router_with` sur `127.0.0.1:0` comme `agent_e2e.rs`, base temporaire, configuration à site A `static` (`sources = ["ci"]`) et site B `wordpress` (`sources = ["agent-php", "ci"]`) ; clés enregistrées par `Store` ; le binaire réel pousse avec `--endpoint http://127.0.0.1:<port>`. Vérifie : 204 et inventaire en base (`last_inventory(site, Ci)`) ; corps signé capturé (via `--dry-run` signé par le test avec la même graine) rejoué sur `/r/v1/report` et `/r/v1/logs` → 404 ; graine de l'agent du site B utilisée comme clé d'inventaire → refus (site A) ; serveur qui répond 301 → code 1. Horloge : `FakeClock` recalée sur l'heure réelle avant chaque envoi (l'outil prend l'heure réelle), assertion `|FakeClock − heure réelle| ≤ 270 s` comme `agent_e2e.rs`.
9. **Schéma officiel** (`vigie.yml`, job `inventory-schema` sur `ubuntu-24.04`) : télécharge `cyclonedx-linux-x64` de `CycloneDX/cyclonedx-cli` à une version épinglée, vérifie sa SHA-256 (`sha256sum -c`), construit `vigie-inventory`, produit `sbom` pour chaque dossier de `tests/fixtures/inventory-tool/` (et `--cms wordpress` sur `composer/`), puis `cyclonedx validate --input-file … --input-version v1_7 --fail-on-errors` ; tout échec rouge. Version et empreinte relevées sur la release officielle à l'implémentation (la plus récente de plus de deux semaines), notées en commentaire du job et dans `decisions.md` (phase 4).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `cargo build --release --bin vigie-inventory` passe sous Linux et Windows ; le job `musl` affiche les deux empreintes et vérifie les deux binaires statiques |
| 2-4 | Chaque cas « cli » du Test Scope est un test ; `keygen` laisse un fichier 0600 (Unix) et n'écrit jamais la graine ailleurs |
| 5 | Aucun envoi en clair hors boucle locale ; aucune redirection suivie ; codes 0/1/2 conformes |
| 6-7 | stderr d'un passage complet ne contient ni la graine (base64), ni la signature, ni `secret-xyz` |
| 8 | `cargo test --locked --test inventory_tool_e2e` passe : push accepté, trois refus croisés, renvoi inchangé sans nouvelle ligne |
| 9 | Job `inventory-schema` vert ; un BOM modifié à la main (champ `licenses` ajouté) le fait échouer sur la liste blanche du test Rust, et un `specVersion` faux sur `cyclonedx validate` (essai consigné dans la PR) ; commit `feat(inventory): binaire vigie-inventory (#20)` |
