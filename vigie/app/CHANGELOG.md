# Changelog de la console Vigie

Versions de la console (`vigie/app`), publiées par les tags `console-vX.Y.Z`.
Le veilleur a son propre historique.

## À venir

- Jeton de l'appareil hors de `device.json` : Credential Manager sous Windows,
  fichier privé du dossier `no_backup` sous Android. Un `device.json` de la
  0.1.1 est migré au premier lancement ; en cas d'échec, l'appareil reste
  appairé et Réglages l'indique. Retour à la 0.1.1 : réappairer.
- Android : sauvegarde et transfert d'appareil désactivés.
- Garde-fous verrouillés par des tests : capacités, absence de `v-html`,
  plugins `fs`, `shell` et `http` interdits, liste des commandes figée.

## 0.1.1

- Android : l'en-tête ne passe plus sous la barre d'état, ni la barre du bas
  sous la barre de navigation. L'app s'affiche bord à bord et réserve les
  marges de sécurité du système.

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
