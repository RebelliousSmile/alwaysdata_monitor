---
status: pending
---

# Instruction: Jeton dans le trousseau, garde-fous verrouillés

## Architecture projection

```txt
.
└── vigie/app/
    ├── src-tauri/
    │   ├── Cargo.toml        ✏️ keyring-core + windows-native-keyring-store (cible Windows seulement)
    │   └── src/
    │       ├── secret.rs     ✅ SecretStore : Windows (Credential Manager, Local), Android (fichier privé 0600), mémoire à échecs provoqués
    │       └── lib.rs        ✏️ Status.token_storage ; nettoyage d'entrée orpheline au démarrage
    │       └── pairing.rs    ✏️ device.json sans jeton ; migration de l'ancien format
    ├── eslint.config.js      ✏️ vue/no-v-html en erreur
    └── src/security-config.spec.ts ✏️ capacités, v-html/innerHTML, plugins interdits
```

## Tasks to do

1. `SecretStore` et ses trois implémentations ; `pairing` l'utilise.
2. Migration d'un `device.json` 0.1.1 (struct héritée, jeton du fichier qui fait foi, relecture, réécriture atomique) ; échec → jeton du fichier, `token_storage = "file_legacy"` ; révocation si l'écriture échoue à l'appairage ; suppression des deux côtés.
3. Tests de garde-fous (plan) ; patch `allowBackup` dans `console.yml` et `console-release.yml`, vérifié par `aapt2` ; `cargo tree` Android sans `keyring-core`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Avec la mémoire : appairage, relecture, révocation ; migration d'un `device.json` 0.1.1 : jeton déplacé, fichier sans jeton ; sur le runner Windows : aller-retour réel dans le Credential Manager puis suppression |
| 2bis | Store mémoire en échec d'écriture ou de relecture : appareil resté appairé, `token_storage = "file_legacy"` ; échec à l'appairage : jeton révoqué ; aucune erreur ne contient le jeton |
| 3 | Une capacité ajoutée, un `v-html`, un plugin `fs` transitif ou une commande Tauri nouvelle font échouer la CI ; APK sans sauvegarde autorisée |
