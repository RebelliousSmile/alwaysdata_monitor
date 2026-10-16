---
status: pending
---

# Instruction: Jeton dans le trousseau, garde-fous verrouillés

## Architecture projection

```txt
.
└── vigie/app/
    ├── src-tauri/
    │   ├── Cargo.toml        ✏️ keyring (cible Windows seulement)
    │   └── src/
    │       ├── secret.rs     ✅ SecretStore : Windows (Credential Manager), Android (fichier privé 0600), mémoire
    │       └── pairing.rs    ✏️ device.json sans jeton ; migration de l'ancien format
    ├── eslint.config.js      ✏️ vue/no-v-html en erreur
    └── src/security-config.spec.ts ✏️ capacités, v-html/innerHTML, plugins interdits
```

## Tasks to do

1. `SecretStore` et ses trois implémentations ; `pairing` l'utilise.
2. Migration d'un `device.json` 0.1.1 portant le jeton ; échec → ancien fichier gardé.
3. Tests de garde-fous.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Avec la mémoire : appairage, relecture, révocation ; migration d'un `device.json` 0.1.1 : jeton déplacé, fichier sans jeton ; sur le runner Windows : aller-retour réel dans le Credential Manager puis suppression |
| 3 | Une capacité ajoutée, un `v-html` ou un plugin `fs` font échouer la CI |
