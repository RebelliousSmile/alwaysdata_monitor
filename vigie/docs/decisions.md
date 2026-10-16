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

## Adaptateur Alwaysdata (issue #1)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_adaptateur-alwaysdata/plan.md`,
relu en trois tours ; contrat : [`logs.md`](./logs.md#transport-alwaysdata-issue-1).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| L'agent pousse (`POST /r/v1/logs`), signé par sa clé de rapport avec le préfixe `vigie-logs-v1\n` ; le veilleur ne lit jamais l'hébergeur | Aucun accès FTP ou API stocké ; une signature ne vaut que pour son point d'entrée |
| RGPD : rien de brut n'est stocké. Le veilleur normalise à la réception et n'écrit que des `Entry` (clés de query string, hôte du referer) ; 30 jours de conservation, purgés par `tick` | Les valeurs de query string n'existent jamais en base : rien à masquer après coup |
| Filtre d'hôtes côté agent (`logs.hosts`, fail-closed) et refiltre au veilleur (`[sites.logs] hosts`, une ligne sans hôte est rejetée) | Minimisation : un fichier Alwaysdata couvre tout le compte |
| Idempotence par limite haute de `(site, file, gen)` et lot `pending` renvoyé à l'identique ; un trou est admis et compté | Une réponse perdue ne double rien et ne bloque jamais l'agent |
| Plafonds : 16 Kio par ligne, 44 Kio gardés et 4 Mio lus par lot, 20 lots et 20 s par passage côté agent ; 50 Mo par site et par jour UTC côté veilleur | 48 Kio en base64 font déjà 64 Kio ; bornes mémoire et CPU des deux côtés ; un retard se rattrape |
| `log_entries.id` en `AUTOINCREMENT`, curseur de `AlwaysdataSource` = dernier id servi | Après une purge totale, un id redonné sous le curseur serait sauté en silence |
| Un lot de logs ne vaut ni rapport ni preuve de vie | Le battement de cœur reste porté par le rapport |
| Le chemin complet (`tests/logs_contract.rs`) rejette `apache-combined.log` en `host` | Fixture sans hôte en tête : hors format Alwaysdata, écartée par le filtre fail-closed |

## Typologie des sites (issue #2)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_typologie-kind/plan.md` ; contrat :
[`protocole-commandes.md`](./protocole-commandes.md).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Le champ des commandes s'appelle `runtime`, et non `kind` comme dans l'issue | `kind` désigne déjà le CMS ; deux axes, comme la décision transverse ci-dessus |
| Le registre des capacités est `config.toml` sur le VPS, non signé. Sa version est l'empreinte SHA-256 de la projection `id kind runtime` de chaque site, notée par `serve` et par `tick` et comparée par `vigie status` | Une signature ne protégerait que contre qui tient déjà le compte `vigie`. `serve` lit la configuration une fois : son empreinte dit ce qu'il applique |
| Toutes les commandes n'admettent que `php` tant qu'aucun agent Node n'existe | Fail-closed |
| L'enveloppe d'une commande porte `v` et `site`, et son schéma refuse tout champ inconnu | La clé de commandes est commune à tous les sites ; une version permet d'évoluer sans casser les agents |

## Canal de commandes (issue #10)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_canal-commandes/plan.md`, relu en
quatre tours de sécurité ; contrat : [`protocole-commandes.md`](./protocole-commandes.md).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Trois clés : la clé de rapport de l'agent signe aussi ses retraits, avec le préfixe `vigie-pull-v1\n` (exception consignée à « une clé par usage ») ; une clé de commandes lue par `serve` seul ; une clé d'audit distincte | Pas de seconde clé à installer sur chaque site ; la séparation de domaine empêche qu'une signature de rapport vaille retrait ; la clé la plus dangereuse ne quitte pas `serve` |
| `htaccess-apply` et `htaccess-rollback` restent indisponibles dans le code jusqu'à #13 | Un bloc `.htaccess` libre donne l'exécution de code : la liste fermée de directives doit être vérifiée côté agent |
| La configuration est relue à chaque retrait : site connu et `permit` contre l'état du fichier | `serve` ne lit sinon la configuration qu'au démarrage |
| Résultat toujours accusé (`acked`), avec `accepted` ; persisté par l'agent jusqu'à l'accusé | Le passage de l'agent est un processus court : un résultat perdu bloquerait la file, un résultat refusé sans accusé serait renvoyé pour toujours |
| Pas d'exception « commandes concurrentes » : une seule commande non close par site | Pas de besoin exprimé ; plus simple à auditer |
| Ancre externe de l'audit : la tête de chaque chaîne modifiée part par e-mail depuis `tick` | Une fin de chaîne coupée ne se voit que contre une tête connue d'ailleurs ; `serve` n'envoie jamais d'e-mail |
| `rotate-key` n'est pas un remède à une compromission du site | Qui tient la clé de l'agent peut répondre avec sa propre clé ; le remède reste la réinstallation et `site rotate-key` hors canal |

## Agent PHP et commandes (issue #6)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_agent-commandes/plan.md`.

| Décision du 2026-10-16 | Raison |
| --- | --- |
| ext-sodium native et base64, pas `sodium_compat` | Décision transverse du 2026-10-16 |
| Clé publique de commandes épinglée dans `config.json` en 0600 (dossier 0700), pas compilée dans le fichier PHP | Le fichier de l'agent est le même pour tous les sites ; qui peut écrire `config.json` sous ce compte peut aussi remplacer l'agent |
| Le résultat d'une commande est persisté localement (`state.json`) jusqu'à l'accusé, contre « rien écrit en local » de l'issue | Contrat de #10 : un passage court perdrait sinon le résultat et bloquerait la file |
| Le test de bout en bout parle en http à la boucle locale, pas en HTTPS ; il est hors de `cargo test` ordinaire et lancé en CI avec le PHP 8.1 épinglé | Le veilleur est en HTTP derrière Caddy ; pas de PHP dans le CI Rust ; la version visée est 8.1 |
| La bascule de clé n'a lieu que sur une réponse signée, jamais sur un 204 | Un 204 forgé ou mal routé enfermerait l'agent dehors |


## Console, poste de pilotage (issue #12)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_console-shell/plan.md`.

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Sous Windows, le jeton d'appareil vit dans le Credential Manager (`keyring-core` et `windows-native-keyring-store`, store construit explicitement, persistance `Local`, cible `vigie-console/device`) ; `device.json` ne garde que l'URL, l'id et le nom. Un `device.json` 0.1.1 est migré au lancement ; en cas d'échec, l'appareil reste appairé sur l'ancien fichier (`file_legacy`, affiché dans Réglages) et la migration est retentée | Exigence « keyring OS » de l'issue, sans copie du jeton par le profil itinérant ni appareil bloqué par une migration ratée |
| Sous Android, le jeton reste dans un fichier 0600 du dossier `no_backup` de l'application, et le manifeste coupe sauvegarde et transfert (`allowBackup`, `dataExtractionRules`, vérifiés sur l'APK). Un store Keystore existe (`android-native-keyring-store`) ; il est écarté par choix (crate jeune, appels JNI), pas faute d'existence | Le bac à sable par application tient lieu de trousseau ; sans les règles d'extraction, le transfert vers un nouveau téléphone copierait le jeton et rendrait deux appareils indiscernables pour la révocation |
| Sous une stratégie de groupe qui interdit le trousseau, un appareil déjà appairé reste appairé (fichier hérité), mais un nouvel appairage est refusé et le jeton émis aussitôt révoqué | Ne pas casser l'existant, ne pas créer de jeton hors trousseau |

## Analyseur de logs (issue #8)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_analyseur-logs/plan.md` ;
fonctionnement : [`logs.md`](./logs.md#analyse-issue-8).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Partage entre sites limité aux signatures d'UA de robots normalisées (`Seo`, `AiTraining`, `Unknown` à jeton de robot), jamais un UA d'outil générique, jamais d'IP ; 100 par site, 30 jours. Partager des IP entre clients demanderait une décision datée de l'exploitant : **refusé par défaut** | Un robot nuisible est connu de tous les sites sans transférer de données personnelles d'un client à l'autre |
| Une signature notée ailleurs ajoute 15 points hors du score propre ; seul le score propre (≥ 70) note une signature | Pas de boucle d'auto-entretien entre sites |
| Pas de « timeout par entrée » (issue) : le travail par entrée est borné (classement en cache, règles en nombre fini, glob borné à 256 × 2048) et un budget global de 10 s par passage, vérifié entre deux lots de 500, arrête le reste | Un délai par entrée n'a pas de sens pour un traitement en mémoire de coût constant ; le curseur opaque n'a pas de position partielle |
| La protection porte sur le **niveau d'action**, pas sur le verdict : `SearchEngine`, `OtherEngine`, `SocialPreview`, `Browser` et `AiUser` sont protégés des actions robots.txt et UA de #13, mais une IP à UA de navigateur peut être suspecte | « Jamais de blocage d'un moteur, d'un navigateur ni d'un aperçu social » (#13) ; le scraper de facettes à UA Firefox est le cas principal du score |
| `AiUser` protégé, écart au PHP où il n'a aucune protection | Il agit pour une personne qui a demandé la page |
| Constats agrégés : un par règle, un seul `suspicious-ips` (5 pires IP), `bots-ai-training` en information, `load` ; clé = identifiant, jamais une valeur de log ; détail assaini à l'écriture | Un botnet de 1 000 IP ne fait pas 1 000 e-mails ; un chemin ou une IP d'attaquant n'entre jamais dans une clé |
| Minimisation : profils et verdicts d'IP 48 h, résumés d'analyse sans IP et signatures 30 jours, détails des incidents `logs` clos masqués à 30 jours, y compris pour un site qui n'a plus de source | RGPD |
| `close_unwatched` garde le contrôle `logs` d'un site qui a une source (prédicat provisoire dans `tick.rs`, repris par le registre de #4) | Sinon chaque passage clôt puis rouvre |
| Les verdicts ne sont recalculés, et l'instantané écrit, que quand un passage a replié des entrées ; sinon ils sont repris du dernier instantané | Les profils ne bougent pas sans entrée nouvelle ; relire 10 000 profils chaque minute pour rien coûterait le budget |
