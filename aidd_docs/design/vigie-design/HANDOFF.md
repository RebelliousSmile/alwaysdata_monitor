# Vigie — passation design → code

Vigie surveille et protège les sites gérés par FX (surtout PrestaShop chez Alwaysdata) : disponibilité, visiteurs automatisés et blocages, erreurs, ressources du compte, contrôles de sécurité, alertes email.

Ce dossier contient :

- `maquettes/` — les 16 écrans validés (`*.dc.html`) et `canvas.json` (l'index et les notes de spec). **Ce sont des maquettes, pas du code à reprendre.** Chaque fichier est du HTML + une classe JS `Component` dont `renderVals()` contient les données d'exemple et la logique d'interaction : lis-la, elle décrit les comportements attendus.
- `tokens.css` — les jetons de design à utiliser tels quels.
- ce document — tout ce qui ne se voit pas sur les écrans.

## 1. Principes non négociables

1. **Un site à la fois.** Pas de comparaison entre sites. On choisit un site et on fait le point.
2. **Des faits et des volumes, pas de statistiques.** Pas de moyennes, de tendances ni de pourcentages d'évolution. Oui : « 405 requêtes, 38 Mo, 02:14 → 02:31 ».
3. **Mobile d'abord** (390 px). Cibles tactiles ≥ 44 px. Au-delà de 900 px : la barre du bas devient une colonne à gauche, et listes et détail s'affichent côte à côte.
4. **Rien n'est écrit sur un serveur sans passer par la file d'écriture** (voir §5).
5. **Une donnée ancienne porte toujours son heure.** Vigie ne présente jamais comme actuelle une donnée qu'il n'a pas pu relire.
6. **Le rouge veut dire gravité ou danger, rien d'autre.** Un état n'est jamais porté par la couleur seule : symbole `× ! i ✓ ?` ou libellé en plus.

## 2. Architecture cible

Deux morceaux : un téléphone en veille ne surveille rien.

```
vigie/                      (workspace Cargo)
├── crates/vigie-core       bibliothèque partagée : parsing des logs (combined + php + apache),
│                           regroupement en rafales, détection des robots, génération et diff
│                           du bloc « # BEGIN Vigie » (.htaccess / robots.txt), règles d'alerte
├── crates/vigie-daemon     service permanent sur un serveur : lecture SSH incrémentale, sondes HTTP,
│                           relevés de ressources, contrôles, emails, file d'écriture, API HTTPS
└── app/                    Tauri 2 (Android, iOS, ordinateur) + interface web (Vue + Vite)
                            client de l'API du service, aucune surveillance en local
```

Bibliothèques suggérées, à confirmer : `axum` (API), `tokio` (planification), `russh` ou `ssh2` (SSH), `lettre` (SMTP), `sqlx` + SQLite (historique 30 jours), `reqwest` (sondes).

Authentification app ↔ service : un jeton par appareil, ajouté en scannant un QR code depuis l'ordinateur, révocable. **Pas encore dessiné.**

Lecture des logs : fichiers lus en entier, en reprenant à la position où s'est arrêtée la lecture précédente (inode + offset). Plus de `tail -n`. Plus de cron côté Alwaysdata : le service planifie tout.

## 3. Écrans et routes

Schéma : `/s/{site}/{vue}?date=AAAA-MM-JJ&de=HH:MM&a=HH:MM&src=http,php&q=…`. **Tout lien transmet son contexte** (date, fenêtre, sources, filtre).

| Route | Maquette | Rôle |
|---|---|---|
| `/` | `Main` | Mes sites, triés : non conforme, aveugle, à vérifier, OK. Chaque ligne affiche l'heure de la dernière lecture |
| `/s/{site}` | `ATraiter` | Arrivée sur un site : points ouverts du plus grave au moins grave, « le reste va bien », alertes envoyées. Variante WordPress dans le réglage `site` |
| `/s/{site}/alerte/{id}` | `Alerte` | Détail d'alerte : quand, quoi, combien, faits liés, actions (lignes, sourdine, résolue). Cible des liens des emails |
| — | `Emails` | Modèles d'email : immédiat, email du matin, « Vigie ne voit plus le site » |
| `/s/{site}/trafic` | `Site` | Visiteurs automatisés. Filtre « À trier » par défaut, panneau « Décider… » |
| `/s/{site}/trafic/journal` | `Journal` | Requêtes regroupées par visiteur et par rafale, sources http/php/apache/sites mêlées dans l'ordre du temps |
| `/s/{site}/trafic/blocages` | `Blocages` | Règles en place avec leurs refus du jour, blocage manuel, liste blanche, sauvegardes avec diff |
| `/s/{site}/erreurs` | `Erreurs` | Erreurs regroupées par message, sourdine limitée dans le temps |
| `/s/{site}/sante` | `Dispo` | Sondes, incidents, certificat |
| `/s/{site}/sante/ressources` | `Ressources` | Compte Alwaysdata (partagé), moments les plus chargés et leur contexte |
| `/s/{site}/sante/controles` | `Controles` | Checklist : socle commun + jeu par CMS + contrôles personnalisés |
| `/s/{site}/parametres` | `Parametres` | Connexion, chemins, logs lus, fréquences, surcharges d'alerte, retrait |
| `/reglages` | `Reglages` | Règles d'alerte globales, destinataires, clés SSH, thème |
| `/ajouter` | `AjoutSite` | Ajout en 4 étapes : adresse, SSH, détection, contrôles |
| — | `Etats` | Aveugle, écriture échouée, première lecture, vide, hors ligne, confirmation |
| — | `Systeme` | Jetons et composants (voir `tokens.css`) |

Navigation d'un site : barre du bas **À traiter / Trafic / Erreurs / Santé**, avec badges = nombre de points ouverts. Trafic et Santé ont un sélecteur à 3 segments. Une seule action « Relire » dans l'en-tête, toujours à la même place. Le retour depuis Paramètres ramène à l'écran d'origine.

## 4. Règles métier

- **À trier** : visiteur automatisé jamais décidé (ni bloqué, ni interdit, ni autorisé), au-delà de 50 req/jour (seuil réglable).
- **Très actif** : au-delà du seuil « IP très active » (250 req/jour par défaut, global, surchargeable par site). C'est un badge, pas une catégorie.
- **Catégories** (nature) : Inconnu, Robot IA, Robot SEO, Moteur, Aperçu de liens. Robots vérifiés par plage officielle ou DNS inverse quand c'est possible.
- **IPv6** : on propose de bloquer le /64 (l'abonnement) ou l'adresse seule, avec la conséquence affichée.
- **Autoriser** (liste blanche) : n'écrit rien dans les fichiers. Le visiteur n'est plus jamais « à trier », ne déclenche plus d'alerte et ne peut plus être bloqué par une règle automatique. Googlebot et bingbot sont en garde-fou permanent.
- **Sourdine d'une erreur** : 24 h, 7 jours ou jusqu'à la prochaine mise à jour du module concerné. Elle se lève seule si le volume double.
- **Alertes** : immédiates ou dans l'email du matin. Au plus 1 email / 30 min par règle et par site, sauf « Site injoignable » et « Vigie ne voit plus un site ». Option « Prévenir quand c'est rétabli ». Un email non envoyé à cause de la limite apparaît comme « Non envoyé · déjà alerté à HH:MM ».
- **Ressources** : ce sont celles du compte Alwaysdata, partagées entre ses sites. Il faut le dire à l'écran. Charge CPU : valeur instantanée seulement.
- **Contrôles** : un état parmi non conforme, à vérifier, choix assumé, OK. Le titre énonce le constat quand ce n'est pas OK. Jeux : socle commun (tous sites) + PrestaShop (+ WordPress à écrire). Contrôles personnalisés : URL → code, fichier contient / ne contient pas, en-tête présent, commande SSH **en lecture seule sur liste blanche** (cat, grep, ls, stat, php -v, composer show).
- **Vigie ne touche jamais aux règles qu'il n'a pas écrites** (par ex. les règles combinées `[OR]`). Il les signale.
- **Fuseau** : Europe/Paris partout. **Conservation** : 30 jours de détail par défaut, ce qui limite aussi la navigation par jour.

## 5. File d'écriture (.htaccess et robots.txt)

Toute modification passe par une file **par site**, quel que soit l'écran d'où elle part : Visiteurs, Journal, Blocages, Contrôles, restauration d'une sauvegarde. La file survit au changement d'onglet.

1. **Vérifier** : le diff s'ouvre. Le bouton Appliquer n'existe que dans cette vue.
2. **Appliquer** : sauvegarde datée → écriture du bloc `# BEGIN Vigie … # END Vigie` (en tête du .htaccess, en fin de robots.txt) → test HTTP de l'accueil et de /commande.
3. **Test en échec** : remise du fichier précédent, puis écran « Modification annulée automatiquement ». Les modifications restent dans la file.
4. **Succès** : bandeau « Annuler · 30 s », qui restaure la sauvegarde.

PrestaShop régénère robots.txt : le service remet son bloc s'il a disparu, et le signale.

Forme du bloc .htaccess (Apache 2.4) :

```apache
# BEGIN Vigie
SetEnvIfNoCase User-Agent "GPTBot" vigie_bot
<RequireAll>
  Require all granted
  Require not env vigie_bot
  Require not ip 203.0.113.209
</RequireAll>
# END Vigie
```

## 6. Actions risquées

Débloquer, restaurer, désactiver une protection : confirmation, puis passage par la file. Retirer tous les blocs Vigie ou retirer un site : confirmation **en tapant le nom du site**. Le bouton rouge plein n'existe qu'au moment de confirmer un blocage ou un retrait.

## 7. Non dessiné, à faire

- ~~Thème clair~~ : fait (#34), jetons dans `vigie/app/src/styles/tokens-light.css`
- Mise en page large (> 900 px)
- Appairage d'un appareil (QR code + jeton)
- Jeu de contrôles WordPress détaillé
- Liste complète « Voir les 11 autres règles » et historique complet des alertes

## 8. Données des maquettes

Les noms entre crochets (`[client-1].fr`, `[compte]`, `[nom du module]`, `[CVE à renseigner]`) sont des emplacements à remplacer. Les volumes de robots et de ressources du 13 et 14/10 viennent du module PrestaShop « Alwaysdata Log Viewer » en production. Les autres chiffres sont des exemples.
