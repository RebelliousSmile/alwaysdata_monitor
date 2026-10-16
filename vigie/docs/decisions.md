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
