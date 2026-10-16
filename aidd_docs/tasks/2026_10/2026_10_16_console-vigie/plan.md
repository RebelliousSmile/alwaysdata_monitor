---
objective: "La Console Vigie, installée depuis une release GitHub sur Windows et sur Android, s'appaire au veilleur et affiche ses vraies données. Les écrans des maquettes sans source de données sont présents, signalés « pas encore disponible »."
status: in-progress
---

<!-- Fill or omit these sections; never add, rename, or reorder one. -->

# Plan: Console Vigie

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Ajouter au veilleur une API authentifiée par appareil, avec appairage par QR code ou par code collé. La construire en Tauri 2 (Vue 3, Vite, Tailwind, pile de lyremember) d'après les maquettes. La publier par GitHub Releases pour Windows et Android. |
| **Source** | Décision du plan `2026_10_15_veilleur-multisites/plan.md`, qui sort la console du plan veilleur (« ancienne phase 6 »). Maquettes et passation dans `aidd_docs/design/vigie-design/` (`HANDOFF.md`, `maquettes/*.dc.html`, `canvas.json`, `tokens.css`). Demandes de l'utilisateur du 2026-10-16 : des fonctionnalités peuvent être nommées sans être encore implémentées, et GitHub doit produire les releases Windows et Android. |

## Phases

| #   | Phase                                              | File                         |
| --- | -------------------------------------------------- | ---------------------------- |
| 1   | Veilleur : appareils, appairage, authentification  | [`phase-1.md`](./phase-1.md) |
| 2   | Veilleur : API de lecture et acquittement          | [`phase-2.md`](./phase-2.md) |
| 3   | Console : squelette, système visuel, navigation    | [`phase-3.md`](./phase-3.md) |
| 4   | Console : appairage et écrans alimentés            | [`phase-4.md`](./phase-4.md) |
| 5   | Releases GitHub et mise en service                 | [`phase-5.md`](./phase-5.md) |

## Resources

| Source | Verified |
| ------ | -------- |
| https://v2.tauri.app/plugin/barcode-scanner/ | Le plugin s'ajoute pour les cibles Android et iOS seulement (`#[cfg(mobile)]`), avec les permissions `barcode-scanner:allow-scan` et `allow-cancel`. API : `scan({ formats: [Format.QRCode] })`. Il demande Rust 1.90 ou plus, et le veilleur est déjà en 1.93. Sous Windows, on colle le code. |
| https://v2.tauri.app/plugin/stronghold/ | Plugin disponible sur toutes les plateformes, mais il demande un mot de passe maître. Il n'est pas retenu : voir les Décisions sur le jeton. |
| https://v2.tauri.app/distribute/sign/android/ | Signature release : un keystore, `gen/android/keystore.properties` et un `signingConfig` release dans `app/build.gradle.kts`. Le keystore et le fichier de propriétés ne doivent jamais être versionnés ; en CI, ils sont reconstitués depuis les secrets en base64. |
| https://v2.tauri.app/distribute/google-play/ | Android 7.0 (SDK 24) au minimum. Build `tauri android build --apk --target aarch64`. |
| https://github.com/tauri-apps/tauri-action | v1 en cours, avec l'option `mobile: android` déclarée expérimentale. L'action n'est pas retenue : les deux jobs lancent `tauri build` directement, comme le job Android de lyremember, et un job final crée le brouillon. Une release en brouillon ne crée son tag qu'à la publication. |

## Decisions

| Decision | Why |
| -------- | --- |
| La console est un client de l'API du veilleur tel qu'il est construit : un agent PHP pousse des rapports signés, et l'outil n'écrit jamais sur un site. L'architecture du `HANDOFF.md` (§2 et §5 : service SSH qui lit les logs, relève les ressources et écrit `.htaccess` et `robots.txt` par une file) n'est pas reprise. | C'est la décision du plan veilleur : aucun accès stocké chez l'hébergeur, et une compromission du VPS ne donne pas la main sur les sites. Réintroduire SSH et l'écriture serait une décision produit à part, à prendre avant d'alimenter Trafic, Erreurs, Ressources ou Blocages. |
| Tous les écrans des maquettes sont routés. Ceux qui n'ont pas de source (Trafic : Visiteurs, Journal, Blocages ; Erreurs ; Ressources ; AjoutSite ; Emails ; sourdines ; file d'écriture) affichent un état « pas encore disponible », sans donnée d'exemple. | La navigation est complète dès le départ, et le principe 5 du HANDOFF (« jamais présenter comme actuelle une donnée non relue ») vaut aussi pour les données inventées. |
| La seule écriture de la console est l'acquittement d'un incident, dans la base du veilleur. Ajouter ou retirer un site, faire tourner une clé ou accepter une référence d'empreintes reste en CLI sur le VPS. | La surface d'un jeton volé reste la lecture et l'arrêt des relances. Les actions qui changent la confiance dans un site demandent un accès SSH. |
| Un jeton par appareil : 32 octets aléatoires, conservés en SHA-256 côté veilleur, et révocables par `vigie device revoke`. L'appairage passe par un code à usage unique, valable 10 minutes, affiché en QR code dans le terminal du VPS et en texte à coller. | Ce dispositif est prévu dans le HANDOFF (§2) sans y être dessiné. Une base volée ne contient aucun jeton utilisable, et retirer un appareil ne touche pas les autres. |
| Les appels réseau sont faits côté Rust par reqwest en rustls avec les racines webpki-roots embarquées, ce qui évite de dépendre du magasin de certificats d'Android. Le jeton reste dans un fichier du répertoire de données privé de l'application et ne passe jamais au webview. | Pas de CORS à ouvrir sur le veilleur, une CSP limitée à `'self'` et `ipc:`, et aucun jeton lisible par du JavaScript. Le Credential Manager n'a pas d'équivalent commun sous Android, et stronghold exige un mot de passe à chaque ouverture. |
| La console vit dans `vigie/app/`, comme dans l'arborescence du HANDOFF. Elle a son propre workflow CI. Ses releases portent des tags `console-v*`, distincts des tags `v*` du module PrestaShop. | Le dépôt publie déjà des tags `v1.x` pour le module, et l'on évite toute collision. Le veilleur garde sa CI. |
| L'APK Android est signé avec une clé release stable dès la première version. `gen/android` est créé en phase 3 par `tauri android init` et versionné, puis reçoit son `signingConfig` release en phase 5. | Le piège est documenté dans lyremember : changer de clé interdit toute mise à jour (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`), et un `gen/android` régénéré en CI perd le `signingConfig`. |
