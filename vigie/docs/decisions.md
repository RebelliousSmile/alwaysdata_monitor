# Décisions de produit

Registre daté des décisions qui orientent Vigie. Les plans de
`aidd_docs/tasks/` et les issues GitHub y renvoient au lieu de les répéter.
Une décision révisée garde son entrée d'origine et reçoit une nouvelle entrée
datée.

## Points ouverts du brainstorm du 2026-10-15 (issue #11)

Source : section « Encore ouvert » de
`aidd_docs/tasks/2026_10/2026_10_15_veilleur-multisites/brainstorm.md`.

| Point | Décision du 2026-10-16 | Raison | Issues |
| --- | --- | --- | --- |
| RGPD | Les logs d'accès collectés sont conservés 30 jours, puis purgés. Les query strings sont masquées dès l'analyse. Un contrat de sous-traitance est signé avec chaque client avant de collecter ses logs : c'est l'affaire de l'exploitant, pas du code | 30 jours suffisent à voir les tendances des robots sur un mois. Les query strings portent des jetons de réinitialisation et des paniers | #1, #8 |
| Processus permanent chez Alwaysdata | Sans objet | Le veilleur tourne sur le VPS. L'agent est lancé par la tâche planifiée de l'hébergeur et ne reste pas en mémoire | — |
| Hébergeurs sans tâche planifiée | Constat : certains sites n'offrent qu'un accès FTP et SQL, sans SSH ni outil d'administration. Choix par défaut, faute de besoin exprimé, et révisable : en V1, ces sites ne sont couverts que par les contrôles externes, comme les sites statiques. Aucun accès FTP n'est stocké. Piste pour plus tard : un agent déposé une fois par FTP, l'accès étant saisi au moment de l'installation, puis appelé par le veilleur en HTTPS signé | Stocker un accès FTP donne le plus grand rayon d'impact possible si le veilleur est compromis. La règle du brainstorm tient : l'accès est demandé au moment d'agir, jamais stocké | #1 |
| Module PrestaShop actuel | Maintenu inchangé sur la boutique B, jusqu'à ce que l'analyse de logs du veilleur le remplace | Sa logique de classement des robots est la seule en service tant que l'analyse de logs n'est pas livrée | #7, #1, #8 |
| Canal d'alerte | L'e-mail seul pour la V1 | La console Android affiche déjà les incidents ouverts. Un second canal n'a pas de besoin exprimé | — |
| Nom de l'outil | Vigie, figé. « Veilleur » reste le nom du démon | Le nom est en service depuis le 2026-10-15 : crate, binaire, unités systemd, console | #12 |
| Remis à plus tard | Inchangé : Cloudflare comme levier d'action, blocage pour les applications Node, Core Web Vitals | Hors de la V1 | — |

Points déjà tranchés ailleurs :

- conditions de l'offre gratuite d'UptimeRobot : [`reception.md`](./reception.md) ;
- authentification du point d'entrée des agents : [`protocole-agent.md`](./protocole-agent.md).

## Décisions transverses du 2026-10-16

| Décision | Raison | Issues |
| --- | --- | --- |
| Agir sur un site suit toujours trois temps : Vigie propose, l'exploitant valide, l'application se fait par une commande explicite (`--apply`). Aucune action n'est automatique. Cette décision revient sur « l'outil n'écrit jamais sur un site » du plan de la console | Les garde-fous des issues (signature, anti-rejeu, liste fermée d'actions, sauvegarde et retour arrière) rendent l'écriture acceptable si l'exploitant valide chaque action | #10, #6, #13, #4 |
| La typologie d'un site a deux axes. Le type de CMS (`generic`, `wordpress`, `prestashop`) filtre les contrôles, comme aujourd'hui. Le runtime (`php`, `node`, `static`) filtre les commandes. `wordpress` et `prestashop` impliquent `php`, ce que la lecture de la configuration vérifie | Le CMS seul ne dit pas ce qu'un site peut exécuter, et le runtime seul ne dit pas quels contrôles lui appliquer | #2, #4 |
| Les signatures restent encodées en base64 standard avec remplissage, et l'agent PHP utilise l'extension sodium native. #9 et #6 demandaient de l'hex minuscule et sodium_compat | L'agent signe ainsi en production ; changer d'encodage obligerait à redéployer chaque agent avec une période où le veilleur accepte les deux formats. L'extension sodium est présente chez Alwaysdata (`hebergement.md`). L'encodage est figé et documenté dans `protocole-agent.md`, ce qui était le vrai besoin | #9, #6 |

## Sonde UptimeRobot (issue #3)

Une sonde UptimeRobot HTTP(s) interroge `/health` du veilleur toutes les
5 min. Elle couvre la panne du VPS ou du veilleur, que le veilleur ne peut pas
signaler lui-même ; elle ne surveille pas les sites. `/health` répond 503
quand le dernier `tick` a plus de 3 min (`src/serve.rs`, test
`health_thresholds`). Les conditions de l'offre gratuite et l'essai du
2026-10-16 (alerte environ 5 min après le 503, retour environ 3 min après la
relance) sont dans [`reception.md`](./reception.md), section 4.

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Pas de webhook entrant en V1. Les alertes UptimeRobot arrivent par e-mail, n'entrent pas dans la base de Vigie et restent à usage interne | Un seul canal d'incidents suffit. Les conditions d'UptimeRobot interdisent de reconditionner ses alertes pour un tiers : ce que voit le client vient du veilleur |

Si un webhook entrant devient utile, il respecte toutes ces exigences :

- un secret partagé rotable, distinct des clés Ed25519 des agents ;
- un HMAC-SHA256 du corps et de l'horodatage, comparé en temps constant ;
- un anti-rejeu de ±300 s sur l'horodatage ;
- une limite de débit par IP, 10 appels par minute ;
- un schéma JSON strict qui refuse les champs inconnus ;
- un traitement strictement en lecture seule : aucun appel ne déclenche d'action.

## Socle (issue #9)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_socle-transversal/plan.md`.

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Dans `serve`, une seule connexion écrit, sous `Mutex`, appelée depuis `spawn_blocking`, au lieu d'une task dédiée et d'un canal mpsc. Entre processus (`serve`, `tick`, la CLI), la sérialisation passe par WAL, `busy_timeout` à 5 s et des transactions d'écriture toutes en `IMMEDIATE` | Même but que l'issue (une connexion qui écrit, écritures sérialisées), avec moins de code. Un canal ne traverse pas les processus ; une transaction DEFERRED qui passe en écriture échoue en `SQLITE_BUSY` sans attendre |
| Les erreurs de `/api/v1` portent `{"error":{"code","message","request_id"}}` et chaque réponse un `X-Request-Id`, cité par le journal. `/r/v1/report` et les routes inconnues gardent leur 404 sans corps | Le 404 muet du point d'entrée des agents ne doit rien révéler (`protocole-agent.md`) |
| L'horloge injectable (`clock.rs`) porte les décisions de fenêtre ; les délais d'E/S réelles restent sur l'horloge système | Simuler la durée d'une E/S réelle ne teste rien ; ce sont les décisions qui doivent se rejouer à heure fixe |
| Base64 et ext-sodium gardés : la case « hex minuscule » de l'issue est close | Décision transverse ci-dessus |
| Une clé Ed25519 par usage, écrite dans `protocole-agent.md` ; la clé de commandes et son épinglage arrivent avec #10 et #6 | Créer aujourd'hui une clé sans usage serait du code mort |
| gitleaks sur tout l'historique, build musl par zigbuild et contrôle des `Cargo.lock` en CI | Un dépôt public ; une dépendance TLS qui casse musl se voit au push, pas au déploiement |

## Contrat des logs (issue #7)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_logsource/plan.md` ; contrat :
[`logs.md`](./logs.md).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Fixtures synthétiques au format réel au lieu des « logs réels » de l'issue | Dépôt public : aucune ligne de production |
| `Entry` ajoute `host`, `query_keys`, `referer_present`, `referer_host` et `duration_us` aux champs de l'issue | Un fichier Alwaysdata couvre tous les sites du compte ; le module se sert des clés de requête et de l'absence de referer ; le temps de réponse est au brainstorm |
| Seules les clés de la query string passent, jamais les valeurs ; le referer est réduit à son hôte | RGPD, query strings masquées dès l'analyse |
| Le découpeur Apache combined, listé dans #1, est livré par #7 | Partie exposée aux octets hostiles, écrite et fuzzée une fois ; il rend `expected.json` vérifiable dès #7 |
| Une ligne n'est jamais rejetée pour sa longueur sous 4 Mio : chaque champ est tronqué ; l'agent coupe chaque ligne à 16 Kio | Un robot ne doit pas se cacher en gonflant sa ligne |
| `fetch(from, max_entries)` et `Fetched.more` figés dès maintenant | Une borne ajoutée plus tard casserait chaque adaptateur |

