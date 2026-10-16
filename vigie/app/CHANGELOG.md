# Changelog de la console Vigie

Versions de la console (`vigie/app`), publiées par les tags `console-vX.Y.Z`.
Le veilleur a son propre historique.

## 0.1.0

Première version, Windows et Android.

- Appairage par lien `vigie://pair`, collé sous Windows ou scanné sous Android.
  Le jeton reste côté Rust, jamais dans le webview. Adresse en https exigée.
- Retrait de l'appareil depuis Réglages ; si le veilleur est injoignable,
  la commande `vigie device revoke` à lancer est affichée.
- Écrans alimentés par l'API : Mes sites, À traiter, Alerte (acquittement),
  Disponibilité, Contrôles, Paramètres et Réglages en lecture.
- Chaque donnée porte l'heure de sa lecture ; hors ligne, les dernières
  données restent affichées avec un bandeau.
- Badges À traiter et Santé sur les incidents ouverts, hors information.
- Écrans sans source de données présents, signalés « pas encore disponible ».
