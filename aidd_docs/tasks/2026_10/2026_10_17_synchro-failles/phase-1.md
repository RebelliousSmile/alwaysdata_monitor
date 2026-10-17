---
status: pending
---

# Instruction: Téléchargement borné, dossier de travail et lecteur zip strict

Phase indépendante de F1 : aucun accès à la base, aucune faille analysée. Elle livre les trois briques que le moteur de la phase 2 (et F3, F4) assemble.

## Architecture projection

```txt
.
└── vigie/
    ├── Cargo.toml                     ✏️ flate2 (default-features = false, rust_backend) passe de [dev-dependencies] à [dependencies] ; Cargo.lock sans paquet nouveau
    ├── src/
    │   ├── http.rs                    ✏️ agent(trust, connect_timeout) -> ureq::Agent extrait de Http::new (https_only, max_redirects 0, http_status_as_error false, USER_AGENT, racines) ; Http s'en sert sans changement de comportement
    │   └── vulns/
    │       ├── mod.rs                 ✏️ pub mod sync
    │       └── sync/
    │           ├── mod.rs             ✅ rôle du cadre, renvoi à docs/failles.md ; Limits { compressed, unpacked, entries, entry (= F1 4 Mio), central_directory, duration } ; SyncError (typée, message assaini)
    │           ├── download.rs        ✅ Download : Request { url, sensitive_headers }, Validators { etag, last_modified, sha256 }, Fetched { NotModified, Dump(DumpFile) }, DumpFile { path, sha256, bytes, validators }
    │           ├── workdir.rs         ✅ WorkDir::prepare(base_dir, source) : <dossier de la base>/vulns-work/<source>/ 0700, vidé ; create_file() 0600 create_new ; Drop nettoie ; free_space() (statvfs sous Unix)
    │           └── zip.rs             ✅ ZipReader::open(path, &Limits) ; entries() dans l'ordre des offsets ; Entry { name, Skipped(reason) | Data(Vec<u8>) }
    └── tests/
        ├── vulns_zip.rs               ✅ zips sains (classique, ZIP64 de fin), zips hostiles générés, fuzz à graine fixe
        ├── vulns_download.rs          ✅ téléchargeur contre le serveur HTTPS local
        └── support/
            ├── dump_server.rs         ✅ serveur HTTPS local générique (autorité rcgen) : routes programmées, ETag et 304, comptes et en-têtes reçus
            └── zipgen.rs              ✅ écrivain zip minimal des tests (stocké, deflate par flate2, ZIP64 de fin) et mutations hostiles
```

## Test Scope

```mermaid
journey
  section Zip sain
    Zip de 3 entrées deflate => 3 entrées, contenus et CRC exacts: 5: lib
    Zip de 70 000 petites entrées avec ZIP64 de fin => 70 000 entrées lues dans l'ordre des offsets: 5: lib
    Entrée stockée (méthode 0) => lue: 5: lib
  section Zip, entrée sautée et comptée
    Entrée déclarée à 5 Mio => sautée sans décompression, raison too_large: 1: lib
    Noms ../../x.json, /etc/x.json, a/b.json, x.txt, entrée dossier => sautés, raison bad_entry_name, aucun fichier créé: 1: lib
  section Zip, dump refusé
    Somme des tailles déclarées au-delà du plafond => refus avant toute décompression: 1: lib
    Entrée qui décompresse plus que sa taille déclarée (bombe menteuse) => refus, au plus taille + 1 octets produits: 1: lib
    Entrées locales qui se recouvrent (bombe par recouvrement) => refus: 1: lib
    CRC faux, flux deflate corrompu, longueur réelle plus courte => refus: 1: lib
    Méthode 12, drapeau chiffré, descripteur de données, ZIP64 par entrée => refus: 1: lib
    En-tête local dont le nom ou la méthode diffère du répertoire central => refus: 1: lib
    Fin de fichier absente, tronquée, répertoire central hors du fichier ou non contigu, plusieurs disques => refus: 1: lib
    Nombre d'entrées au-delà du plafond ou ZIP64 de fin incohérent => refus: 1: lib
  section Zip, fuzz
    50 000 mutations d'octets d'un zip sain => aucune panique, mémoire bornée: 1: lib
  section Téléchargement
    200 avec ETag et Last-Modified => fichier 0600 écrit, SHA-256 et validateurs rendus: 5: lib
    Validateurs connus et serveur en 304 => NotModified, If-None-Match et If-Modified-Since envoyés, aucun fichier: 5: lib
    Content-Length au-delà du plafond => refus sans lire le corps: 1: lib
    Corps sans Content-Length qui dépasse le plafond => refus à plafond + 1 octet: 1: lib
    Corps tronqué (moins que Content-Length) => échec, fichier supprimé: 1: lib
    Statut 500 ou 403 => échec avec le code: 1: lib
    Serveur muet au-delà de l'échéance => échec en temps borné: 1: lib
    URL en http ou hôte hors liste => refus sans connexion: 1: lib
    Redirection vers un hôte de la liste en https => suivie ; vers un autre hôte, en http ou plus de 3 => refus: 1: lib
    En-tête sensible et redirection vers un autre hôte de la liste => en-tête absent de la seconde requête: 1: lib
    ETag de 300 caractères ou avec octet de contrôle, Last-Modified illisible => non gardés: 1: lib
  section Dossier de travail
    Dossier absent => créé en 0700 ; fichiers d'un passage interrompu => supprimés: 5: lib
    Dossier remplacé par un lien symbolique => refus: 1: lib
    Fin normale ou erreur => dossier vidé: 5: lib
    Espace libre insuffisant (seuil injecté) => refus avant écriture: 1: lib
```

## Tasks to do

1. **`Cargo.toml`** : déplacer `flate2 = { version = "1", default-features = false, features = ["rust_backend"] }` dans `[dependencies]` (commentaire : lecture des dumps OSV, F3 et F4) ; vérifier que `Cargo.lock` ne gagne aucun paquet et que `check-tls-deps.sh` reste vert.
2. **`http.rs`** : extraire `pub fn agent(trust: &Trust, connect_timeout: Duration) -> Agent` de `Http::new` (mêmes réglages), `Http::new` l'appelle ; tests existants inchangés.
3. **`sync/mod.rs`** : `Limits` (champs ci-dessus, `Limits::osv(ecosystem)` avec les valeurs du plan : crates.io 32 Mio / 64 Mio / 20 000 / 15 min ; Packagist 64 Mio / 256 Mio / 50 000 / 15 min ; npm 640 Mio / 1,5 Gio / 700 000 / 90 min ; `entry` = borne F1 de 4 Mio, `central_directory` = 64 Mio) ; `SyncError` par cause (`Http { status }`, `Network`, `TooLarge { what }`, `Truncated`, `Deadline`, `Zip(reason)`, `Disk`, `Io`, `HostRefused`, …), `Display` en français sans donnée de la source.
4. **`workdir.rs`** :
   - `WorkDir::prepare(base_dir, source_id)` : `base_dir` = dossier parent de la base ; crée `vulns-work/` et `vulns-work/<source>/` en 0700 (Unix, `DirBuilderExt::mode`) ; refuse un lien symbolique (`symlink_metadata`) ou un propriétaire différent de l'uid courant (Unix) ; supprime le contenu restant (fichiers seulement, jamais en suivant un lien) ;
   - `create_file(name)` : `OpenOptions::create_new`, mode 0600 (Unix) ;
   - `free_space()` : `libc::statvfs` sous Unix, `None` ailleurs ; `ensure_space(needed)` : `needed + 1 Gio` de réserve, seuil injectable pour les tests ;
   - `Drop` : vide le dossier de la source (erreurs journalisées, jamais de panique).
5. **`download.rs`** :
   - `Download::new(trust, hosts: &[&str], validators: Validators, limits, deadline)` ; `get_to_file(&Request, &WorkDir) -> Result<Fetched, SyncError>` ;
   - avant connexion : schéma `https` et hôte (minuscules, sans `www.` implicite) dans `hosts`, sinon `HostRefused` ;
   - requête : `If-None-Match` si ETag connu, `If-Modified-Since` si Last-Modified connu ; en-têtes sensibles de `Request` envoyés à l'hôte d'origine seulement ;
   - redirections suivies à la main (301, 302, 303, 307, 308), 3 au plus, cible résolue par `Url::join`, revérifiée (https, hôte de la liste) ; en-têtes sensibles retirés dès que l'hôte change ;
   - 304 → `NotModified` ; 200 → `Content-Length` > `limits.compressed` → `TooLarge` ; `ensure_space` ; corps lu par `into_reader().take(limit + 1)` (lecteur `ureq` sans limite propre, vérifié dans ureq 3.4.2) écrit dans `<source>.zip.part` avec SHA-256 au fil de l'eau ; dépassement → `TooLarge` ; octets ≠ `Content-Length` → `Truncated` ; autre statut → `Http { status }` ;
   - `timeout_global` = temps restant jusqu'à l'échéance ; `Deadline` si dépassé ;
   - validateurs de la réponse : ETag gardé si ASCII imprimable de 1 à 256 caractères, `Last-Modified` gardé s'il s'analyse en date HTTP (RFC 9110, par `jiff`) ; jamais journalisés en entier.
6. **`zip.rs`** :
   - `open` : taille du fichier ≤ `limits.compressed` ; recherche de la fin de fichier dans les `22 + 65 535` derniers octets, longueur de commentaire cohérente avec la fin exacte du fichier ; disques à 0 ; si un champ vaut `0xFFFF`/`0xFFFFFFFF`, localisateur ZIP64 (20 octets avant, un seul disque) puis enregistrement ZIP64 (taille ≥ 44, entrées du disque = total) ; `cd_offset + cd_size` = début de l'enregistrement de fin (ZIP64 ou classique) ; `cd_size` ≤ `limits.central_directory` ; entrées ≤ `limits.entries` ;
   - analyse du répertoire central entièrement en mémoire : signature, drapeaux (bit 0, 3, 6, 13 refusés ; bit 11 admis), méthode 0 ou 8, aucune taille ni offset à `0xFFFFFFFF`, somme des tailles déclarées ≤ `limits.unpacked` (en `u64` saturant) ;
   - disposition : enregistrements locaux triés par offset, `[offset, offset + 30 + nom + extra local + compressé)` sans recouvrement et sous `cd_offset` ; en-tête local lu et comparé (signature, nom, méthode, drapeaux, CRC, tailles) ;
   - `entries()` : itérateur dans l'ordre des offsets ; nom hors `[A-Za-z0-9._-]{1,64}\.json` ou finissant par `/` → `Skipped(BadEntryName)` ; taille déclarée > `limits.entry` → `Skipped(TooLarge)` sans décompression ; sinon lecture de `compressed_size` octets, `DeflateDecoder` (ou copie pour la méthode 0) lu jusqu'à `uncompressed_size + 1` ; longueur ≠ déclarée ou CRC (`flate2::Crc`) ≠ → `Err(Zip(..))` qui fait refuser le dump ; total réellement décompressé ≤ `limits.unpacked`.
7. **`tests/support/zipgen.rs`** : écrivain minimal (entrées stockées ou deflate, ZIP64 de fin au-delà de 65 535 entrées ou sur demande) et mutations nommées (taille déclarée fausse, CRC faux, recouvrement, drapeau, méthode, nom local différent, fin tronquée, offset hors fichier, entrées ZIP64 incohérentes) ; aucun zip binaire commité.
8. **`tests/support/dump_server.rs`** : reprend l'autorité de test et le serveur rustls de `tests/external_checks.rs` (thread par connexion, 127.0.0.1) ; routes `path → Reply` programmables en cours de test (`Ok { body, etag, last_modified }` avec 304 si `If-None-Match` correspond, `Status(u16)`, `Redirect(url)`, `Truncated { announced, sent }`, `HugeLength`, `Endless` sans `Content-Length`, `Hang`) ; compte les requêtes et garde les en-têtes reçus pour les assertions.
9. **Tests** : `vulns_zip.rs` (sections « Zip » du Test Scope ; fuzz xorshift à graine fixe comme `logs/tests.rs`, plafonds réduits) ; `vulns_download.rs` (sections « Téléchargement » et « Dossier de travail » ; droits 0700/0600 vérifiés sous Unix seulement ; échéance de test de 2 s).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | `Cargo.lock` : aucune ligne `name =` ajoutée ; `check-tls-deps.sh vigie/Cargo.lock` vert ; tests de `http.rs` et `external_checks` inchangés et verts |
| 3, 6-7 | Chaque cas « Zip » du Test Scope est un test et passe ; aucune bombe ne fait produire plus de `taille déclarée + 1` octets par entrée ni plus du plafond décompressé ; aucun fichier créé hors du dossier de travail ; fuzz vert et reproductible en moins de 10 s en debug |
| 4-5, 8 | Chaque cas « Téléchargement » et « Dossier de travail » passe contre le serveur local ; aucune connexion vers un hôte hors liste (compte de requêtes du serveur à 0) ; dossier de travail vide à la fin de chaque test |
| 1-9 | fmt, clippy, tests verts sur Linux et Windows ; musl vert ; aucun test n'appelle un hôte réel |
