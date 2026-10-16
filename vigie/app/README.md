# Console Vigie

Client Windows et Android de l'API du veilleur (`/api/v1`, voir
[`../docs/api-console.md`](../docs/api-console.md)). Tauri 2, Vue 3, Pinia.
Le jeton d'appareil reste côté Rust : aucune commande ne le renvoie au
webview (voir « Jeton de l'appareil »).

## Installation

Les fichiers viennent d'une release `console-vX.Y.Z` du dépôt GitHub :
`vigie-console_X.Y.Z_x64-setup.exe`, `vigie-console_X.Y.Z_arm64.apk` et
`SHA256SUMS`. Vérifier l'empreinte du fichier téléchargé avant de l'installer :

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

```powershell
Get-FileHash .\vigie-console_X.Y.Z_x64-setup.exe -Algorithm SHA256
```

### Windows

1. Lancer `vigie-console_X.Y.Z_x64-setup.exe`. L'installeur n'est pas signé :
   SmartScreen affiche « Windows a protégé votre ordinateur ». Cliquer
   « Informations complémentaires », puis « Exécuter quand même ».
2. L'installation se fait pour l'utilisateur courant, sans droits
   d'administrateur. WebView2 est déjà présent sous Windows 11 ; s'il manque,
   l'installeur le télécharge.
3. Une version suivante s'installe par-dessus, l'appairage est conservé.

### Android

1. Télécharger l'APK depuis la release, sur le téléphone.
2. L'ouvrir. Android demande d'autoriser l'installation d'applications
   inconnues pour le navigateur ou le gestionnaire de fichiers utilisé :
   l'autoriser pour cette source, puis revenir et installer.
3. Une version suivante, signée par la même clé, s'installe par-dessus, sans
   désinstaller : l'appairage est conservé.

L'APK de debug produit par la CI (`console.yml`) est signé par une autre clé :
on ne passe de l'un à l'autre qu'en désinstallant, ce qui efface l'appairage.

## Appairage

1. Sur le VPS, créer un code valable 10 minutes et une seule fois :

   ```sh
   ~/vigie/bin/vigie device pair --name téléphone
   ```

   La commande exige la section `[api]` de la configuration du veilleur
   (`public_url` en https). Elle affiche un QR code et un lien `vigie://pair`.
2. Dans la console, écran Appairage :
   - Android : « Scanner le QR code », ou coller le lien ;
   - Windows : coller le lien dans « Lien d'appairage », puis « Appairer ».
3. La console ouvre Mes sites. Sur le VPS, `~/vigie/bin/vigie device list`
   liste l'appareil comme actif.

Retirer un appareil : Réglages, « Retirer cet appareil ». Le veilleur révoque
son jeton et la console l'oublie. Si le veilleur est injoignable, la console
l'oublie quand même et affiche la commande `vigie device revoke <id>` à lancer
sur le VPS. Un appareil révoqué depuis le VPS revient à Appairage à sa
requête suivante.

### Jeton de l'appareil

`device.json` (dossier de données de l'application) ne porte que l'adresse
du veilleur, le numéro et le nom de l'appareil. Le jeton est rangé à part :

- Windows : Credential Manager, identifiant générique `vigie-console/device`,
  persistance « ordinateur local » (il ne suit pas un profil itinérant) ;
- Android : fichier privé de l'application dans son dossier `no_backup`.
  L'APK interdit en plus la sauvegarde et le transfert vers un autre
  téléphone (`allowBackup="false"`, `dataExtractionRules`) : un téléphone
  restauré doit être appairé de nouveau.

Réglages indique où vit le jeton. « Ancien fichier » : la console n'a pas pu
le déplacer hors de `device.json` (trousseau verrouillé ou interdit) ; elle
fonctionne quand même et réessaie à chaque lancement.

- Mise à jour depuis la 0.1.1 : au premier lancement, le jeton de
  `device.json` est rangé dans le trousseau (ou dans `no_backup`), relu, puis
  `device.json` est réécrit sans lui. Une sauvegarde Android faite avant la
  mise à jour garde l'ancien fichier : la révoquer au besoin
  (`vigie device revoke <id>`).
- Retour à la 0.1.1 : elle ne lit pas le nouveau `device.json`. Réappairer.
- Stratégie de groupe Windows interdisant le Credential Manager : un appareil
  déjà appairé le reste (« Ancien fichier »), mais un nouvel appairage est
  refusé, et le jeton qu'il venait d'obtenir est révoqué aussitôt.

Une adresse en http n'est acceptée que sur la boucle locale (`127.0.0.1`,
`localhost`, `[::1]`), et seulement dans un build de debug.

## Développement

```sh
pnpm install
pnpm tauri dev        # fenêtre Windows, recharge à chaud
pnpm lint && pnpm typecheck && pnpm test
cd src-tauri && cargo clippy --all-targets -- -D warnings && cargo test --all-targets
```

`src-tauri/tests/contract.rs` appelle chaque commande du client contre le
routeur du veilleur, en processus : un changement de l'API qui casse la console
le fait échouer.

`src-tauri/gen/android` n'est pas versionné : la CI le régénère par
`tauri android init` à chaque build.

## Clé de signature Android

L'APK de release est signé par une clé stable : sans elle, le téléphone
refuse d'installer une version par-dessus la précédente. La clé ne va jamais
dans le dépôt ; elle vit dans un coffre de mots de passe, d'où on la
restaure si elle est perdue localement. La perdre pour de bon oblige à
désinstaller la console sur chaque téléphone, puis à l'appairer à nouveau.

Création, une seule fois, avec le `keytool` d'un JDK 17 :

```sh
keytool -genkeypair -v -storetype PKCS12 -keystore vigie-release.jks \
  -alias vigie -keyalg RSA -keysize 4096 -validity 10000
```

En PKCS12, le mot de passe du magasin sert aussi pour la clé : un seul mot de
passe. Ranger `vigie-release.jks` (en pièce jointe) et le mot de passe dans le
coffre, puis poser les trois secrets du dépôt :

```sh
base64 -w0 vigie-release.jks | gh secret set ANDROID_KEYSTORE_BASE64
gh secret set ANDROID_KEY_ALIAS --body vigie
gh secret set ANDROID_KEY_PASSWORD   # saisi au clavier, hors de l'historique
```

Sans ces trois secrets, le job Android de `console-release.yml` échoue avant
le build : aucun APK non signé n'atteint une release.

## Release

`.github/workflows/console-release.yml` produit l'installeur Windows, l'APK
signé et `SHA256SUMS`, puis crée une release GitHub en brouillon avec les trois
fichiers. Les tags `v*` du module PrestaShop ne le déclenchent pas.

1. Bumper la version dans les trois fichiers, à la même valeur :
   - `package.json` (`tauri.conf.json` la lit) ;
   - `src-tauri/Cargo.toml` ;
   - `src-tauri/Cargo.lock` : `cargo update -p vigie-console` après le bump
     de `Cargo.toml`.
2. Compléter [`CHANGELOG.md`](./CHANGELOG.md), commiter, pousser sur `main`.
3. Tagger et pousser le tag :

   ```sh
   git tag console-vX.Y.Z
   git push origin console-vX.Y.Z
   ```

   Le workflow s'arrête avant tout build si les trois versions diffèrent, ou
   si le tag ne vaut pas `console-v` suivi de cette version.
4. Ouvrir le brouillon de la release : il doit contenir l'installeur, l'APK
   et `SHA256SUMS`. Télécharger les deux binaires et vérifier leurs empreintes.
5. Publier le brouillon, puis vérifier à nouveau les fichiers depuis la
   release publiée, et installer.

Essai sans tag : lancer le workflow à la main (Actions, console-release, Run
workflow, ou `gh workflow run console-release.yml --ref <branche>`). GitHub
n'offre ce lancement que si le workflow existe déjà sur `main`. Il produit un
brouillon `console-vX.Y.Z-manuel.N` marqué préversion. Un brouillon ne crée pas son tag : le supprimer après
vérification, sans le publier.
