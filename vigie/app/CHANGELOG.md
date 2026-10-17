# Changelog de la console Vigie

Versions de la console (`vigie/app`), publiées par les tags `console-vX.Y.Z`.
Le veilleur a son propre historique.

## Non publiée

Prérequis de publication : le veilleur du VPS sert les routes `components`,
`vulns` et `vulns/sources` de l'API (#21, phase 4). Face à un veilleur en
retard, les deux écrans restent « pas encore disponible » (404).

- Failles (#21) : composants du site et failles connues rapprochées, par
  groupe d'alias, avec gravité, KEV, EPSS, versions corrigées, dérogation
  en cours et source de l'inventaire ; « Afficher plus » sur un passage
  figé. Le contrôle « Failles des composants » remplace « pas encore
  disponible » dans Contrôles.
- Sources de failles (Réglages) : jeux de données chargés, date de la
  dernière synchronisation et incidents de synchronisation en cours.

## 0.2.0

Prérequis de publication : le veilleur du VPS sert la pagination et les
routes `logs` de l'API (#5, phase 2) et écrit l'analyse des logs (#8), tous
deux déployés avant de pousser le tag `console-v0.2.0`. Les propositions de
Trafic citent `vigie site recommend` (#13), à fusionner avant aussi. Face à
un veilleur en retard, Visiteurs, Blocages et Ressources restent « pas encore
disponible » (404) et les incidents clos arrivent en une seule liste, sans
« Afficher plus ».

- Trafic alimenté par l'analyse des logs : Visiteurs (IP au score moyen ou
  élevé, avec leurs raisons), Blocages (règles de l'analyse, robots vus sur
  24 h) et, dans Santé, Ressources (charge heure par heure, heures au-delà du
  seuil). Trois états : site sans source de logs, « pas encore disponible » ;
  analyse pas encore écrite, « analyse en attente » ; sinon les données.
  Journal reste « pas encore disponible » : aucune ligne de log n'est servie.
- Les actions des maquettes (bloquer une IP, un abonnement /64, un robot,
  autoriser) sont des propositions : la console n'écrit rien et cite la
  commande `vigie site recommend <site>` à passer sur le VPS.
- « Afficher plus » pour les incidents clos (Disponibilité) et les verdicts
  d'IP. Un curseur expiré fait reprendre la liste au début, avec un avis.
- Erreurs de l'API nommées : trop de requêtes (« réessayer dans N s », sans
  relance automatique), requête refusée (400, 415).
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
