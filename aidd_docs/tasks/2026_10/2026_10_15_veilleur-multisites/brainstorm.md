# Veilleur multi-sites : sécurité et performance des sites livrés

> Synthèse du brainstorm du 2026-10-15 (`aidd-refine:01-brainstorm`), approuvée comme source du plan.

Il s'agit d'un outil unique, écrit en Rust, qui te sert à garantir la sécurité et la performance de tous les sites que tu livres : tes projets et ceux de tes clients, en PHP comme en JavaScript. Il ne sert qu'à toi, pour diagnostiquer, réagir et agir. Le client ne voit rien. Tu le vends comme une prestation de surveillance avec intervention préventive. Il reprend `alwaysdata_monitor`, aujourd'hui enfermé dans un seul PrestaShop, et en généralise la logique à tout le parc.

L'outil part de deux incidents réels. Le premier est la dérive du site A : un `wp-config.php` disparu, un installeur détourné par un robot, et des semaines hors ligne sans le savoir. Le second est l'envahissement de la boutique B par les robots, les scripts et les outils SEO. Il doit voir ce genre de dérive en quelques minutes, sans multiplier les outils ni ouvrir de nouvelle porte sur les sites.

## Ce qui est clair

- **Un seul binaire Rust**, compilé pour Windows, Linux et Android, avec deux rôles :
  - le **veilleur** : une instance unique, toujours allumée, sur le compte Alwaysdata. Elle reçoit les rapports, fait les contrôles et envoie les alertes ;
  - le **poste de pilotage** : n'importe quelle autre installation, qui se connecte au veilleur.
- **Trois familles de contrôles**, chacune issue d'un incident vécu :
  - **l'exposition, vue de l'extérieur** : contenu attendu de la page, installeur ouvert, `.env`, `.git/` ou sauvegardes accessibles, TLS, en-têtes de sécurité ;
  - **l'intégrité et la dérive, vues de l'intérieur** : fichier critique disparu ou modifié, nouveau `.php` dans `uploads/`, versions et dépendances vulnérables, configuration de l'hébergement modifiée (domaines rattachés, accès MySQL) ;
  - **le trafic et la performance, à partir des logs** : la logique actuelle du module (classement des robots, score de suspicion, erreurs 500, charge), plus le temps de réponse serveur et la saturation.
- **L'agent par site** n'envoie que des rapports signés au veilleur. Il ne fait que lire, n'expose aucune URL et n'écrit jamais. Une tâche planifiée de l'hébergeur le lance.
  - Un fichier PHP sert pour les sites PHP, un petit module pour les applications Node.
  - Les sites statiques ne sont couverts que par les contrôles externes.
  - Un agent qui n'envoie plus rien déclenche lui-même une alerte.
- **Agir passe toujours par ta validation.** L'outil reprend les garde-fous du module actuel :
  - jamais de blocage d'un moteur de recherche, d'un navigateur ni d'un aperçu de réseau social ;
  - le niveau d'intervention suit le type de robot : `robots.txt`, puis User-Agent, puis IP ;
  - une sauvegarde avant chaque écriture et un retour arrière en une commande.

  Les écritures passent par FTP ou par API. L'accès est demandé au moment d'agir au lieu d'être stocké.
- **Le multitenant ajoute un avantage** : un robot nuisible repéré sur un site est connu de tous les autres.
- **Une seule sonde UptimeRobot** surveille le veilleur lui-même. Elle couvre une panne d'Alwaysdata.
- **Test de réception** : rejouer l'incident du site A. L'alerte doit partir en moins de 10 minutes, au premier signal.

## Encore ouvert

- **Un processus permanent chez Alwaysdata** : il faut vérifier qu'il est autorisé, et voir sous quelle forme.
- **Les conditions d'UptimeRobot** : il faut vérifier si l'offre gratuite autorise un usage dans une prestation payante.
- **Le RGPD** : les logs contiennent des IP, donc il faut un contrat de sous-traitance avec chaque client et une durée de conservation définie.
- **Le point d'entrée du veilleur** : il reçoit les rapports des agents, ce qui en fait la pièce la plus exposée. Son authentification doit être conçue en premier.
- **Les hébergeurs sans tâche planifiée** : il faut recenser ceux du parc. Pour eux, le repli est le FTP, qui suppose de stocker un accès en lecture.
- **Remis à plus tard** : Cloudflare comme levier d'action facultatif, le blocage pour les applications Node, les Core Web Vitals. Le canal d'alerte est l'e-mail ; un autre canal reste à décider.
- **Le module PrestaShop actuel** : il faut décider s'il reste en service sur la boutique B jusqu'à ce que le veilleur le remplace, ou s'il est archivé.
- **Le nom de l'outil**.

## Prochaine étape

Planifier la plus petite version utile. Elle se limiterait au veilleur sur Alwaysdata, aux contrôles externes et à l'agent PHP posé sur le site A. Elle serait validée en rejouant l'incident de septembre. L'analyse des logs du module viendrait ensuite.

## Précision ajoutée au moment du plan (2026-10-15)

Tout le nouveau développement vit dans un répertoire `monitor/` du dépôt, sans casser le module PrestaShop actuel.

## Tranché le 2026-10-16

Chaque point de « Encore ouvert » a reçu une décision datée, consignée dans
[`vigie/docs/decisions.md`](../../../../vigie/docs/decisions.md) (issue #11).
