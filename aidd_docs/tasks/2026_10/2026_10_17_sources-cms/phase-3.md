---
status: pending
---

# Instruction: Branchement sur F2 : jeton, verrou de relecture, débit, plafonds

Les deux convertisseurs deviennent des sources du cadre de synchronisation de F2. **Prérequis** : F2 mergé ; relire le plan F2 tel qu'implémenté et reporter tout écart dans « Dépendances » du plan avant de commencer.

## Architecture projection

```txt
.
└── vigie/
    ├── config.example.toml                ✏️ [vulns.wordfence] commenté : token_file, terms_reviewed, rappel « usage interne, relecture consignée dans docs/failles.md »
    ├── src/
    │   ├── secret.rs                      ✅ open_safely, check_parent, check_mode déplacés de command/key.rs ; read_token(path) -> Token ; Token sans Debug ni Display en clair
    │   ├── lib.rs                         ✏️ pub mod secret
    │   ├── command/key.rs                 ✏️ utilise secret.rs (règles inchangées, tests existants verts)
    │   ├── config.rs                      ✏️ [vulns] de F2 : identifiants wordfence et friends-of-presta dans la liste fermée ; [vulns.wordfence] { token_file (absolu), terms_reviewed (AAAA-MM-JJ) } ; deny_unknown_fields
    │   └── vulns/
    │       ├── sources/
    │       │   ├── wordfence.rs           ✏️ impl VulnSource : SourceMeta (intervalle minimal 30 min, max_dropped_ratio 1 %, Redistribution::Internal, plafonds) ; ready() (verrou) ; fetch() (verrou revérifié, Bearer en HeaderValue sensible, seul hôte www.wordfence.com, 401/403 par SyncError::Status)
    │       │   ├── friends_of_presta.rs   ✏️ impl VulnSource : fetch() (archive, redirection github.com → codeload.github.com, conditionnel), plafonds
    │       │   └── mod.rs                 ✏️ enregistrement des deux sources dans le registre de F2 (actives si déclarées dans [vulns] sources)
    │       └── sync/
    │           └── registry.rs            ✏️ (F2) KNOWN += wordfence, friends-of-presta ; redistribution(source_id: &str) -> Option<Redistribution>
    └── tests/
        ├── vulns_cms_sync.rs              ✅ synchronisation par le serveur HTTPS de test de F2, sur fixtures fictives ; vigie vulns match de bout en bout
        └── config_edges.rs                ✏️ [vulns.wordfence] : chemin relatif, date invalide, clé inconnue
```

## Test Scope

```mermaid
journey
  section Verrou de relecture
    wordfence absent de [vulns] sources => source absente de vulns sync et de vulns sources: 5: cli
    wordfence déclaré sans [vulns.wordfence], ou l'inverse => ConfigError, code 2: 1: cli
    Section présente, constante None => refus explicite, aucune requête reçue par le serveur de test, motif dans vulns sources, config valide, vulns sync en code 1 comme toute source non synchronisée (règle F2): 1: cli
    Constante Some(2099-01-01) en test et terms_reviewed différent => refus explicite, aucune requête: 1: cli
    fetch() appelé directement sans ready(), constante None => refus, aucune requête: 1: lib
    Constante et terms_reviewed égaux => synchronisation lancée: 5: cli
  section Jeton
    Fichier 0600 dans un dossier 0700, propriétaire => lu, en-tête Authorization Bearer reçu par le serveur de test: 5: lib
    Fichier 0644, dossier 0755, lien symbolique, autre propriétaire (Unix) => refus avant toute requête, message sans le jeton: 1: lib
    Jeton avec espace, saut de ligne interne, 15 ou 513 caractères => refusé ; jeton suivi de \r\n => accepté sans \r\n: 1: lib
    Fichier de 10 Mio => lecture arrêtée à 1 Kio, refus ; FIFO à la place du fichier => refus sans blocage: 1: lib
    En-tête Authorization => HeaderValue marquée sensible: 1: lib
    format!("{:?}", token) et journal du passage => aucun octet du jeton: 1: lib
  section Débit Wordfence
    Seconde synchronisation à t + 10 min => refusée sans requête par le débit de F2 (last_request_at), heure de la prochaine tentative ; à t + 31 min => lancée: 1: lib
    Réponse 429 Retry-After 3600 => SyncError::Status, retry_after_until posé par F2, tentative refusée avant t + 1 h: 1: lib
    Réponse 302 vers un autre hôte => refusée par Download, jeton jamais envoyé ailleurs (le second serveur ne reçoit rien): 1: lib
    Réponse 401 ou 403 => SyncError::Unauthorized ou Forbidden de F2, affichée « jeton refusé », corps non journalisé: 1: lib
    LOADER_VERSION de la génération active différente, même SHA-256 => rechargement ; même version et même SHA-256 => aucune écriture: 1: lib
  section Friends-Of-Presta
    Redirection 302 servie par le serveur de test (hôte de substitution) => archive lue, révision gardée ; hôtes de production github.com et codeload.github.com vérifiés dans meta(): 5: lib
    Redirection vers un hôte non autorisé => erreur, base précédente intacte: 1: lib
    Seconde synchronisation, ETag inchangé ou même SHA-256 => aucune écriture: 5: lib
  section Bout en bout
    vigie vulns match pkg:wordpress/plugin/exemple-plugin@1.2.3 => WF-<uuid> touchée, corrigée en 1.2.4, attribution Wordfence, « usage interne »: 5: cli
    vigie vulns match pkg:wordpress/core/core@6.4.1 => faille du noyau fictive: 5: cli
    vigie vulns match pkg:prestashop/module/exemplemodule@1.5.0 => FOP-… touchée, corrigée en 1.5.1, « faits seulement »: 5: cli
    vigie vulns match pkg:prestashop/module/modulelibre@3.0.0 => « plage inconnue », jamais « aucune faille »: 1: cli
    vigie vulns sources => wordfence et friends-of-presta : licence, redistribution, révision, entrées, écartées par raison, out_of_scope, lignes unevaluable: 5: cli
    registry::redistribution(wordfence | friends-of-presta | osv-packagist | kev) => Some(Internal | FactsOnly | Free | Free) ; chaque identifiant de KNOWN => Some ; identifiant inconnu ou vide => None: 1: lib
    Écartées au-delà de 1 % selon Reason::is_drop (bad_record en masse) => source en échec par max_dropped_ratio de F2, génération active intacte ; 50 % de empty_copyrights => synchronisée: 1: lib
  section Échecs
    Flux Wordfence tronqué, de 513 Mio, trop lent => source en échec, génération active intacte: 1: lib
    Archive au-delà des plafonds => source en échec, génération active intacte: 1: lib
```

## Tasks to do

1. **`secret.rs`** : déplacer `open_safely`, `check_parent`, `check_mode` (Unix et hors Unix) de `command/key.rs` sans changer leurs règles ; erreur `SecretError` sans contenu du fichier ; `read_token(path)` : `symlink_metadata` d'abord (fichier ordinaire exigé : FIFO, socket, périphérique refusés sans ouverture), ouverture en `O_NOFOLLOW | O_NONBLOCK` puis `fstat` (fichier ordinaire, droits, propriétaire), lecture bornée `take(1024)`, `\r` et `\n` finaux retirés, grammaire `[A-Za-z0-9._~+/=-]{16,512}` ; `Token` : `expose()` seul accès, `Debug` → `Token(***)`, pas de `Display`, pas de `Clone` ; `HeaderValue` construite par `Token::header()` et marquée `set_sensitive(true)` ; tests de `key.rs` existants inchangés et verts ; tests des refus repris pour le jeton.
2. **Configuration** : `wordfence` et `friends-of-presta` ajoutés à la liste fermée de `[vulns] sources` (F2) ; `wordfence` déclaré ⇔ sous-section `[vulns.wordfence]` présente (sinon `ConfigError`) ; sous-section `token_file` (chemin absolu, comme `password_file`) et `terms_reviewed` (date `AAAA-MM-JJ` valide) ; `deny_unknown_fields` ; aucune validation contre la constante dans `config.rs` (la configuration reste valide, le refus vient de la source) ; `config.example.toml` commenté, chemin d'exemple `/home/vigie/vigie/keys/wordfence-token`.
3. **`impl VulnSource for Wordfence`** :
   - `SourceMeta` (F3 y **ajoute** les champs `redistribution` et `loader_version`, absents de F2, et les renseigne pour les sources OSV de F2) : URL, hôte unique `www.wordfence.com`, licence, `Redistribution::Internal`, `LOADER_VERSION = 1`, **intervalle minimal de 30 min** (appliqué par F2 : `last_request_at`, `retry_after_until`), `max_dropped_ratio` 1 %, plafonds (corps 512 Mio, durée 15 min, entrées 200 000) ;
   - `ready()` : constante `None` → `NotReady::TermsNotReviewed` ; date différente → `NotReady::TermsMismatch { binaire, config }` ; jeton illisible → `NotReady::Token(raison)` ; chaque refus est enregistré dans `vuln_sources.last_error` (texte fixe, sans jeton) et visible dans `vulns sources` ; le débit n'est **pas** vérifié ici (F2 le fait pour toutes les sources) ;
   - `fetch()` : **revérifie** la constante et `terms_reviewed` (refus sans requête si `fetch` est appelé sans `ready`) ; GET `https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production` par `Download`, `Authorization` en en-tête sensible, aucun `Content-Encoding` demandé (règle F2), conditionnel si F2 a gardé un ETag ou un Last-Modified ; statuts non 2xx/304 rendus par `SyncError::Status` de F2 (401 → `SyncError::Unauthorized`, 403 → `SyncError::Forbidden`, noms de F2, affichés « jeton refusé », sans corps ; 429 et `Retry-After` gérés par F2) ; puis `parse_feed` (phase 1) sur le fichier du dossier de travail, vers le `Sink` de F2.
4. **`impl VulnSource for FriendsOfPresta`** : `SourceMeta` (URL du plan, hôtes `github.com` et `codeload.github.com`, licence `CC-BY-SA-4.0`, `Redistribution::FactsOnly`, `LOADER_VERSION = 1`, `max_dropped_ratio` 1 %, plafonds : archive 64 Mio, décompressé 512 Mio, 50 000 membres, avis 1 Mio, durée 10 min) ; conditionnel et SHA-256 par F2 ; `parse_archive` (phase 2) ; révision (commit) rendue pour `vuln_sources`.
5. **Registre** : les deux sources enregistrées auprès de F2, actives si déclarées ; `pub fn redistribution(source_id: &str) -> Option<Redistribution>` dans `vulns/sync/registry.rs` (lu par F7 sous ce nom) : `match` avec un bras explicite par identifiant de `KNOWN`, F4 comprises (`wordfence` → `Internal`, `friends-of-presta` → `FactsOnly`, `osv-packagist`, `osv-npm`, `osv-crates-io`, `kev`, `epss` → `Free`), seul le bras final `_ => None` pour un identifiant inconnu (F7 le traite comme `Internal`) ; test `redistribution_covers_known` : `Some` pour chaque identifiant de `KNOWN`, égal au `SourceMeta.redistribution` de la source quand elle en a un, `None` pour `inconnue` et la chaîne vide ; `vigie vulns sources` imprime aussi `redistribution` (`interne`, `faits seulement`, `libre`) et la révision.
6. **Tests** `vulns_cms_sync.rs` sur le serveur HTTPS de test de F2 (autorité de test, `Trust::Custom`) et l'horloge injectée : cas du Test Scope ; les URL de production sont remplacées par `SyncOptions::endpoint_override` de F2 (construit par le code, jamais par la configuration) ; le verrou se teste en passant la date de relecture en paramètre (`ready_with(reviewed: Option<&str>, …)`, que `ready()` appelle avec la constante), la constante réelle restant `None` : aucun `cfg(test)` ne modifie le verrou.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Tests de `key.rs` inchangés et verts ; refus du jeton sur droits, lien, propriétaire et grammaire ; aucun jeton dans `Debug`, erreurs ni journaux |
| 2 | `config_edges.rs` vert ; une section `[vulns.wordfence]` avec un binaire à `None` n'empêche ni `serve` ni `tick` de démarrer |
| 3 | Cas « Verrou », « Jeton » et « Débit » verts ; aucune requête n'atteint le serveur de test sans verrou ouvert, y compris par un appel direct de `fetch` ; débit et `Retry-After` tenus par le seul mécanisme de F2 (aucune colonne ni compteur ajouté par F3) |
| 4 | Cas « Friends-Of-Presta » verts ; aucune requête hors des hôtes autorisés |
| 5-6 | Cas « Bout en bout » et « Échecs » verts ; `redistribution_covers_known` vert, aucun identifiant de `KNOWN` sans niveau ; une source en échec laisse la génération active intacte ; « plage inconnue » jamais rendue comme « aucune faille » |
| 1-6 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; `check-tls-deps.sh` vert ; `Cargo.lock` sans crate nouvelle |
