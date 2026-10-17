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

## API de la console (issue #5)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_api-v1/plan.md` ; contrat :
[`api-console.md`](./api-console.md).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Pas de mTLS : `serve` écoute sur `127.0.0.1:8080`, Caddy l'expose en TLS (Let's Encrypt) ; l'API est authentifiée par un jeton d'appareil de 32 octets aléatoires, gardé en SHA-256, comparé en temps constant, révocable un par un. Le stockage du jeton côté client relève de #12 | Un téléphone hors du VPS doit joindre l'API ; un certificat client par appareil sous Android et Windows coûte plus qu'il n'apporte face à un jeton aléatoire révocable. L'issue admet l'une ou l'autre voie |
| Limite de débit en mémoire de `serve`, deux tables : par appareil (120 par minute, rafale 30, jamais évincée, après l'authentification et avant « vu le ») ; par IP cliente (IPv4, IPv6 sur son /64 ; 10 par minute) pour l'appairage, avant tout traitement, et pour les échecs d'authentification, qu'elle change de 401 en 429. Un seau d'IP vide ne bloque jamais un jeton valide. Table d'IP bornée à 4 096 clés, seuls les seaux pleins évincés, fermée quand elle est pleine. IP cliente : dernière valeur de `X-Forwarded-For` si le pair est la boucle locale (Caddy), sinon le pair | Freine le forçage des codes et un appareil emballé, sans verrouiller un utilisateur légitime derrière un NAT partagé, ni se laisser vider par arrosage d'adresses |
| Aucun en-tête CORS ; `OPTIONS` reçoit le 404 commun ; `nosniff` et `no-store` sur toute réponse, erreurs comprises ; 415 seulement pour un `POST` qui annonce un corps d'un autre type que JSON | La console appelle depuis Rust : aucun navigateur à autoriser, pas de CSRF par formulaire ; aucune requête de la console 0.1.1 ne change de réponse |
| Une ligne de journal par appel (request_id, appareil, méthode, gabarit de route, statut, durée), 429 regroupés par IP et par minute ; jamais de jeton, de code ni d'en-tête | Traçabilité exigée par l'issue, sans donnée sensible ni journald noyé sous une attaque |
| Liste blanche des DTO vérifiée par instantané des clés JSON (`tests/fixtures/api-keys.json`, `facts` et `observed` exclus nommément) et recherche de valeurs semées (jeton, code et leurs empreintes, clé publique d'agent, signatures d'audit, mot de passe SMTP) | Une struct du store sérialisée par mégarde, ou un champ ajouté, fait échouer le CI jusqu'à relecture |
| Texte d'origine log assaini par un type (`LogText`) dont tout constructeur remplace contrôles C0, C1, DEL, U+2028, U+2029 et contrôles bidi par U+FFFD ; chemins sans query string, referer réduit à son origine ; `vue/no-v-html` en erreur dans la console | Le JSON échappe déjà les guillemets ; restent l'injection de terminal et de journal, le texte bidi trompeur et les jetons dans les URL |
| RGPD : les lignes de journal des 429 citent l'IP cliente, gardée par journald selon sa rétention sur le VPS (`hebergement.md`) ; aucune autre ligne de l'API ne la cite. `/logs/ips` ne sert que ip, score, niveau, raisons (en codes, jamais le libellé qui peut citer un UA ou un reverse DNS) et classe, niveaux moyen et élevé, instantané de 48 h au plus (filtré à la lecture, en plus de la purge de #8) | L'exploitant a besoin de l'IP pour décider (#13) ; le reste du profil n'est pas nécessaire |
| Pagination par clé de toute liste qui croît : `limit` 1..100 (50 par défaut), curseur base64url opaque de 256 caractères au plus, 400 `bad_request` sinon. Incidents clos en SQL (`closed_at DESC, id DESC`, index `(site, closed_at, id)`, migration 12) ; verdicts d'IP sur l'instantané de #8 que le curseur fixe, 409 `cursor_expired` (distinct de `conflict`) s'il a été purgé. `incidents` garde son nom et devient la première page (compatibilité de la console 0.1.1). Sites (200 au plus dans `config.toml`) et contrôles non paginés | Exigence de l'issue ; pas de doublon ni de trou entre deux pages, et aucune mise à jour forcée des appareils appairés |

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

## Recommandations htaccess (issue #13)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_recommandations-htaccess/plan.md`,
relu en quatre tours ; fonctionnement : [`htaccess.md`](./htaccess.md).

| Décision du 2026-10-16 | Raison |
| --- | --- |
| Analyse (déterministe, `Analysis` → `Proposal`) séparée de la génération du bloc, testée par fichiers de référence | Le texte est la partie fragile |
| Gradation robots.txt → UA (jeton du catalogue, 30 j) → IP (score propre élevé, reverse DNS hébergeur, 24 h) ; rien contre moteurs, aperçus, navigateurs, `AiUser`, ni IP d'une classe protégée, ni site `behind_proxy` | Garde-fous de l'issue et protections de #8 |
| robots.txt reste une proposition à poser à la main | Plus petite surface : la liste fermée des commandes ne s'y étend pas |
| Grammaire fermée **par groupes**, validée au veilleur et par l'agent, au code de refus près, sur des vecteurs générés et un fuzz différentiel à graine fixe | Un `.htaccess` libre donne l'exécution de code ; deux validateurs divergent sinon en silence ; la validation tient même si le veilleur est compromis |
| Toute règle expire dans Apache (`%{TIME}`, fuseau du site au veilleur, `tz` explicite à l'agent) ; sondes d'horloge Apache dans le bac à sable | Pas d'écriture à l'expiration ; `%{TIME}` est l'heure locale du serveur web |
| Bac à sable différentiel `-a`/`-b` à nonces, compare-and-swap, copie privée dans le dossier de l'agent, reprise d'après l'empreinte, retour arrière seulement si le fichier a encore la nouvelle empreinte | Jamais d'écrasement d'une modification d'un tiers ; une copie dans le webroot pourrait être réécrite par une porte dérobée |
| Intégrité : empreintes attendues admises tant qu'une commande `htaccess-*` est `served` ou `unknown` ; la référence ne suit `current_sha256` que s'il en fait partie | Le rapport part avant le retrait qui porte le résultat |
| **Écart au plan** : `new_sha256` n'est pas calculé par `site recommend` ; un premier `htaccess-apply` à `new_sha256: null` le fait calculer par l'agent sans rien écrire, le second `--apply` applique le bloc ainsi préparé | Le veilleur ne connaît du `.htaccess` que des empreintes, et SHA-256 n'est pas composable. Les paramètres et le contrôle de l'agent restent ceux du plan |
| IP sortantes du veilleur déclarées dans `[logs] protect_ips` ; adresses source des retraits relevées par `serve` (migration 13, `agent_sources`, 30 jours) | Le veilleur ne connaît pas son adresse publique ; seule l'adresse d'un retrait signé est sûre, pas un UA déclaratif |
| Un groupe d'UA repris du bloc en place n'est pas exigé « pas 403 » dans `-a` du bac à sable | Il y est déjà actif : le contrôle vise les groupes neufs |
| Smoke-test d'après la bascule : au moins 10 s, même budget de 30 s épuisé | Ne jamais laisser une bascule sans contrôle faute de budget |
| L'écriture passe par le canal de commandes, pas par FTP | Le canal de #10 ne stocke aucun accès (décision du 2026-10-16) |

## Registre de capacités final (issue #4)

Plan : `aidd_docs/tasks/2026_10/2026_10_16_registre-capacites/plan.md`,
relu en quatre tours ; audit : [`audit-chemin-critique.md`](./audit-chemin-critique.md).

| Décision du 2026-10-17 | Raison |
| --- | --- |
| `capability.rs` est la seule déclaration : `Control { Check, Heartbeat, Integrity, Agent(AgentFamily), Logs, Typology }` et `CommandKind`, CMS admis et condition d'existence par des `match` sans joker (agent enregistré et runtime effectif `php` pour `heartbeat`, `agent:integrity` et les familles, référence d'empreintes en plus pour l'intégrité, source de logs pour `logs`) ; `CheckKind::cms` y est déplacé, le prédicat provisoire de `tick` pour `logs` (#8) aussi | Une seule déclaration ; une variante nouvelle oblige à décider ; une clé d'agent sur un site `static` n'ouvre rien |
| Familles fermées, celles qu'émet l'agent PHP : `root`, `critical-file`, `must-contain`, `uploads-php` (WordPress seul). **Nom réservé → refus du rapport, famille inconnue → écart** : `integrity` fait refuser tout le rapport (règle de `report.rs`, gardée) ; une famille bien formée mais inconnue ou non admise pour le site est écartée, comptée dans `reports.dropped` (dernier rapport), journalisée par `serve` et montrée par `status`, le rapport restant accepté | Fail-closed sans casser un agent plus récent ; un agent ne fabrique ni intégrité ni incident hors typologie |
| Un seul verdict `capability::watched(site, contrôle, contexte)` pour `tick` (`close_unwatched`), l'ingestion (`ingest` reçoit la configuration typée de `serve`, `accept_report` ne réconcilie que les contrôles surveillés) et l'API ; un nom inconnu du registre n'est jamais surveillé | Le même verdict partout, vérifié sur toute la matrice par les trois chemins réels (`tests/capability.rs`) |
| Un incident dont le contrôle n'est plus surveillé est clos par `tick` avec la raison `unwatched` (migration 14, `incidents.close_reason`), et son e-mail dit « plus surveillé », jamais « rétabli » ; son constat étant désormais écarté, il ne se rouvre pas | L'e-mail de clôture part plus tard : la raison est en base. Pas de faux « rétabli » ni de cycle clos/rouvert |
| Clé d'agent sur un site sans runtime `php` : `site add` et `site rotate-key` la refusent ; déjà en base, elle ouvre l'avertissement `typology` (« agent enregistré sur un site sans runtime php : déclarer runtime = "php" »), clos « rétabli » quand `php` est déclaré, « plus surveillé » quand la clé est retirée | Pas de perte silencieuse de surveillance à la mise à jour : un `generic` sans runtime avec agent était surveillé avant #4 |
| **Écart au plan** : l'appel d'`ingest` du rejeu du 2026-09-07 (`tests/replay_2026_09_07.rs`) passe la configuration typée (`&config.sites`) au lieu des identifiants ; ses assertions et sa promesse de 10 min ne changent pas | `ingest` reçoit `&Site` (décision du plan) : la liste d'identifiants ne dit pas le CMS, l'appel ne pouvait pas rester identique |
| Le job `musl` affiche l'empreinte SHA-256 du binaire et le publie en artefact (`vigie-musl`, 14 jours) | Le relevé de la cible compare le binaire de la CI à ce qui tourne sur le VPS ; un binaire compilé n'est pas un binaire qui tourne sur la cible |

## Failles connues (issues #14 à #22)

Sources, standards et conventions : [`failles.md`](./failles.md) (issue #14,
F0). Les marques [V], [S] et [NV] des faits cités y sont.

| Décision du 2026-10-17 | Raison |
| --- | --- |
| Confidentialité : l'inventaire d'un client ne sort jamais du VPS. Seules des bases complètes sont téléchargées, jamais une API interrogée par composant d'un site. L'inventaire est une donnée du client : le dernier inventaire et 30 jours d'historique sont gardés ; les détails des incidents `vulns` sont masqués 30 jours après leur clôture ; `site remove` purge le tout. La règle ne vise que les inventaires des clients : le contrôle des lockfiles de Vigie (F8) interroge `api.osv.dev` | Une requête par composant dirait à un tiers ce que fait tourner chaque client, et quelles failles le touchent. Les dépendances de Vigie sont publiques dans le dépôt |
| Sources admises : OSV.dev, écosystèmes `Packagist`, `npm` et `crates.io` (GHSA en CC-BY 4.0, RustSec en CC0, DRUPAL en MIT, MAL en Apache-2.0, chaque mention conservée avec l'enregistrement) ; noyau et modules natifs PrestaShop par les GHSA d'OSV ; CISA KEV par le miroir officiel `cisagov/kev-data` (CC0) ; FIRST EPSS, avec l'attribution « See EPSS at https://www.first.org/epss » | Bases complètes, téléchargeables sans clé, ETag et 304 pour OSV et le miroir KEV, licences qui admettent le stockage et l'usage commercial |
| FriendsOfPHP n'est pas importé séparément ; #16 (F2) s'en trouve réduit | Son contenu est déjà dans les GHSA, donc dans l'export OSV Packagist : un second import ferait des doublons |
| Wordfence Intelligence **v3**, **admis sous réserve**. #17 ne branche pas l'import avant la relecture, depuis le VPS, des conditions et de la page v3, consignée et datée dans `failles.md`. Tant que ces conditions ne tranchent pas l'affichage aux clients d'un prestataire, l'usage reste interne à l'exploitant. Jeton gratuit dans un fichier 0600 sur le VPS, jamais dans le dépôt ; une requête toutes les 30 min au plus, synchro quotidienne. Attribution : la mention `copyrights` de chaque enregistrement (Defiant, licence, lien, mention MITRE) est reproduite partout où la faille est affichée | Le flux v2 sans clé a été retiré le 2026-03-09. Les conditions n'ont été lues que par des sources secondaires : wordfence.com n'est pas joignable du conteneur |
| Friends-Of-Presta pour les modules PrestaShop. Les avis sont sous CC BY-SA 4.0 ; l'ambiguïté avec le `LICENSE.txt` MIT du thème est notée. Usage interne, affiché avec attribution, texte des avis jamais redistribué | Seule source pour les modules tiers ; sans redistribution, la clause de partage dans les mêmes conditions ne s'applique pas |
| Redistribution : tout ce qui est publié ou transmis à un tiers, client compris. Un document destiné à un client ne reprend de Friends-Of-Presta que des faits (CVE, module, plage, vecteur CVSS, CWE, date) avec le lien, jamais le texte de l'avis | Les faits ne relèvent pas de la licence de l'avis ; son texte, si |
| Sources écartées : WPScan, Patchstack, et NVD comme source de détection (enrichissement éventuel plus tard) | WPScan : 25 appels par jour, usage non commercial, stockage et cache interdits. Patchstack : API sur devis. NVD : pas de correspondance fiable avec les composants visés |
| purl : types officiels `composer` (en minuscules), `npm` et `cargo` (sensibles à la casse, `case_sensitive: true` dans leurs définitions, comparés tels quels). WordPress selon la proposition purl-spec n° 347 : `pkg:wordpress/plugin/<slug>@<v>`, `pkg:wordpress/theme/<slug>@<v>`, `pkg:wordpress/core/core@<v>`. PrestaShop par symétrie, faute de proposition : `pkg:prestashop/module/<nom_technique>@<v>`, `pkg:prestashop/core/prestashop@<v>`. À revoir si la spec officialise autre chose. **Écart à l'issue #14**, qui proposait `pkg:wordpress-plugin/<slug>` | Un identifiant commun aux deux côtés du rapprochement ; la n° 347 est la seule proposition en cours pour WordPress |
| Correspondance : Packagist `prestashop/prestashop` → `pkg:prestashop/core/prestashop`, `prestashop/<x>` (x ≠ `prestashop`) indexé sous les deux purl `pkg:composer/prestashop/<x>` et `pkg:prestashop/module/<x>` (le vendor publie aussi des bibliothèques qui ne sont pas des modules) ; Bedrock `wpackagist-plugin/<slug>` et `wpackagist-theme/<slug>` → purl `wordpress` (limite des extensions premium documentée). Dans une boutique (F5), un composant Composer de type `prestashop-module` est remplacé par la version lue dans `modules/<x>/config.xml`. Les doublons GHSA et Friends-Of-Presta sont fusionnés par CVE. Les avis Friends-Of-Presta de catégorie `dependancies` (bibliothèques tierces embarquées dans des modules) sont écartés à l'import et comptés (`out_of_scope`) : ces bibliothèques sont détectées par OSV sur les composants `composer` et `npm` de l'inventaire ; une bibliothèque copiée dans un module sans `composer.lock` n'est pas vue | Les modules natifs ont des GHSA ; la version de `config.xml` est celle qui tourne ; une faille ne doit apparaître qu'une fois |
| Les extensions émettent du CycloneDX 1.7 ; le veilleur accepte un sous-ensemble strict de 1.6 et de 1.7, par liste blanche : un inventaire qui porte `authors`, `supplier`, `licenses` ou une propriété hors de `vigie:*` est refusé en entier (404 muet, compté au journal) | 1.7 est la dernière version stable ; accepter 1.6 laisse une extension en retard d'une version fonctionner. Ces champs n'aident pas au rapprochement et peuvent porter des données du client |
| Modèle interne : sous-ensemble du schéma OSV 1.9.x. Champs inconnus ignorés, champs retenus validés et bornés ; entrée invalide écartée et comptée ; entrées `withdrawn` ignorées ; plages `SEMVER` traitées, `GIT` ignorées ; `last_known_affected_version_range` lu | Les bases sont des données tierces : une entrée malformée ne doit ni casser l'import ni passer en silence. Aucun composant n'est identifié par un commit |
| Versions : un comparateur par écosystème, écrit et testé par Vigie (Composer selon `composer/semver` : normalisation de `VersionParser` puis `version_compare`, pré-versions comprises ; npm et Cargo selon semver ; WordPress et PrestaShop selon la sémantique de `version_compare`), choisi selon l'écosystème de la source. Les `ranges` sont toujours évaluées ; l'énumération `versions[]`, désormais présente pour Packagist (osv.dev n° 426 fermée), sert de contrôle croisé. Une version non analysable n'est jamais « non vulnérable » : constat « version inconnue », de gravité information | OSV ne fournit pas d'ordre Composer correct ; un faux « non vulnérable » est pire qu'un doute signalé |
| Versions libres de Friends-Of-Presta (« <= 1.5.0 ») : analyse prudente. Une formulation non reconnue marque la faille « plage inconnue », de gravité information, signalée pour toute version du module. L'exploitant peut saisir une **correction de plage**, auditée sur le VPS, distincte d'une dérogation | Le champ `Impacted release` est du texte libre ; mieux vaut un signalement de trop qu'une faille tue. Une correction rend la plage évaluable, une dérogation masque une faille |
| Gravité : critique si un CVE de la faille est dans KEV, si l'entrée est `MAL-` (paquet malveillant) ou si CVSS ≥ 9,0 ; avertissement si CVSS ≥ 7,0, EPSS ≥ 0,1 ou gravité inconnue (sauf une entrée Wordfence `informational: true` sans score : information) ; information pour le reste. Les règles se lisent de haut en bas. Une « version inconnue » sur un composant qui a une faille critique est un avertissement. Les règles critiques et d'avertissement priment sur `informational: true` de Wordfence, qui ne fait passer en information qu'une faille qu'aucune d'elles ne retient. Score lu dans l'ordre : `cvss.score` Wordfence, score de la ligne `severity` de Friends-Of-Presta, CVSS v3.1 calculé depuis le vecteur OSV, sinon `database_specific.severity` GHSA (`CRITICAL` = 9, `HIGH` = 7, `MODERATE` = 5, `LOW` = 3) ; jamais de calcul v4. « Aucun correctif » est toujours affiché et ne fait jamais baisser la gravité | Une faille exploitée ou un paquet malveillant sont urgents ; une gravité inconnue ne doit pas passer pour faible ; un seul calculateur CVSS, en v3.1, à écrire et tester |
| Dérogations : par site, composant et faille, motif obligatoire, expiration à 90 jours au plus, liées à la version du composant, inscrites dans l'audit ; jamais globales ; interdites pour une faille KEV. Le contrôle des dépendances de Vigie (F8, CI) a sa propre règle de 92 jours | Une dérogation oubliée, générale ou survivant à une mise à jour masquerait une faille ; une faille exploitée ne se tolère pas |
| Typologie : contrôle `vulns` dans le registre de capacités (#4), surveillé si une source d'inventaire est déclarée (agent PHP avec inventaire activé, ou clé d'inventaire enregistrée, #20), ce qui couvre `node` et `static`. Sans inventaire reçu depuis plus de 7 jours : constat d'avertissement « inventaire périmé », jamais une perte de surveillance. Sources par site : Wordfence pour `wordpress`, Friends-Of-Presta pour `prestashop`, OSV pour tout composant `composer`, `npm` ou `cargo` | `capability.rs` est la seule déclaration des contrôles ; un inventaire qui cesse d'arriver doit se voir |
| Réseau : wordfence.com, cisa.gov et les hôtes EPSS ne sont joignables que depuis le VPS. Les tests utilisent des fixtures locales. La liste des hôtes à autoriser est dans `failles.md` | Le conteneur de développement refuse ces hôtes ; un test ne doit dépendre d'aucun réseau |
| Fixtures : jamais l'inventaire d'un client. Wordfence et Friends-Of-Presta toujours fictives, de même structure ; vrais enregistrements OSV ou GHSA admis seulement avec un fichier `NOTICE` dans leur dossier (source, licence, lien, modifications) | Dépôt public : c'est une redistribution |

## Dépendances (issue #22)

Plan : `aidd_docs/tasks/2026_10/2026_10_17_osv-scanner/plan.md`. Job `deps`
(« osv-scanner ») de `.github/workflows/garde-fous.yml`.

| Décision du 2026-10-17 | Raison |
| --- | --- |
| osv-scanner **2.6.0** (`google/osv-scanner`, Apache-2.0), binaire `osv-scanner_linux_amd64` épinglé par sa SHA-256 (`ca69b3d3…b108`, lue dans `osv-scanner_SHA256SUMS` de la release et recalculée sur le binaire), téléchargé à chaque run, jamais mis en cache. 2.7.0 est écartée | 2.7.0 avait cinq jours à l'épinglage : trop récente pour qu'une compromission ait été signalée. 2.6.0 lit déjà RUSTSEC-2026-0253 et détecte et filtre comme 2.7.0 (essais locaux) |
| Provenance SLSA de la release (`multiple.intoto.jsonl`) à vérifier une fois, à l'épinglage, avec `slsa-verifier verify-artifact osv-scanner_linux_amd64 --provenance-path multiple.intoto.jsonl --source-uri github.com/google/osv-scanner --source-tag v2.6.0` (slsa-verifier vérifié par sa propre somme). Pas en CI. **Non faite le 2026-10-17** : le conteneur de développement n'atteint pas `tuf-repo-cdn.sigstore.dev` ; à faire depuis un poste qui l'atteint, sortie masquée consignée dans la PR | La somme dit « même binaire qu'à l'épinglage », la provenance « construit par google/osv-scanner depuis ce tag » ; une vérification suffit pour un binaire figé par sa somme |
| Quatre lockfiles nommés : `vigie/Cargo.lock`, `vigie/app/src-tauri/Cargo.lock`, `vigie/app/pnpm-lock.yaml`, `composer.lock` ; base en ligne `api.osv.dev` ; ni `--recursive`, ni `--config`, ni `--call-analysis` | Un lockfile absent ou renommé sort en 127 au lieu d'être sauté. L'analyse d'appels Rust exécuterait les scripts de build |
| Fail-closed : tout code non nul fait échouer le job (1 = faille, 127 = erreur, réseau compris, 128 = aucun paquet). Aucune tolérance de sévérité ; un « non maintenu » RustSec compte comme une faille | Une panne réseau ne doit pas passer pour « aucune faille » |
| Workflow aussi lancé chaque lundi à 05:17 UTC (`schedule`) ; gitleaks et `tls-deps` repassent avec lui | Une faille se publie sans qu'aucun commit ne change |
| Remédier avant d'excepter : `rqrr` 0.10 → 0.11 (dev-dependency de `tests/cli.rs`), `lru` 0.16.4 → 0.18.5, hors de RUSTSEC-2026-0253 | Un correctif existait |
| **Exceptions au plus près du lockfile** : `vigie/app/osv-scanner.toml` (braces `GHSA-vfj7-8cjw-p6xm`, postcss-selector-parser `GHSA-rj75-hqrm-r3gf`) et `vigie/app/src-tauri/osv-scanner.toml` (glib `GHSA-wrw7-89jp-8q8g`, proc-macro-error `RUSTSEC-2024-0370`), échéance 2027-01-17. Aucun fichier à la racine ni dans `vigie/` | Chaque lockfile ne lit que le `osv-scanner.toml` de son dossier, sans remontée vers le parent : une exception de la console ne masque pas la même faille dans le veilleur ou le module |
| Raison glib, mot pour mot : « pile gtk3 de tauri, compilée seulement pour Linux desktop ; aucun livrable Linux (release Windows et Android uniquement, console-release.yml) ; lever si une cible Linux est publiée ou si tauri quitte gtk-rs 0.18 ». proc-macro-error : macro de compilation de la même pile, levée aux mêmes conditions. braces et postcss-selector-parser 6 : outils de build de la console (devDependencies), absents du `dist` embarqué ; lever si un correctif amont est publié, au passage à tailwind 4, ou si l'un d'eux entre dans `dependencies` | Pas de correctif atteignable sans migration ; aucune de ces dépendances n'est dans un livrable publié ni dans le veilleur du VPS ; chaque raison dit quand elle cesse d'être vraie |
| **Script de contrôle** `vigie/scripts/check-osv-exceptions.py`, lancé avant le scan sur tous les `osv-scanner.toml` suivis par git : chaque `[[IgnoredVulns]]` a un `id`, une `reason` non vide et un `ignoreUntil` en date TOML au plus tard 92 jours après la date UTC du run ; toute autre clé de premier niveau est refusée, **`PackageOverrides` compris** (il ignore un paquet entier sans échéance). Une échéance passée n'est pas une erreur du script : osv-scanner rend la faille | osv-scanner accepte une exception sans échéance ou à 2099 : la règle « datée, motivée, ≤ 3 mois » ne tient pas à la seule relecture. 92 jours = trois mois calendaires au plus long |
| **Le script et le job `deps` sont la règle.** Les exceptions et le refus de `PackageOverrides` passent par ce script : une PR qui modifie `check-osv-exceptions.py` ou le job `deps` de `garde-fous.yml` se relit avec le même soin qu'une PR qui ajoute une exception | Affaiblir le contrôle (limite, clés admises, lockfiles, code de sortie) ouvre la même porte qu'une exception, sans en avoir l'air |
| `composer.lock` régénéré d'après `composer.json` (0 paquet, `require-dev` retiré en 1.10.0) et toujours scanné ; `composer validate --no-check-publish` fait échouer le job si le lock redevient périmé | Scanner un lock qui ne reflète pas `composer.json` ne prouve rien ; le lock vide reste le point d'entrée d'une future dépendance |
| cargo-deny écarté pour l'instant ; à réévaluer si une politique de licences devient nécessaire | osv-scanner lit déjà RustSec ; les crates TLS interdites restent gardées par `check-tls-deps.sh` |

### Quand le job `osv-scanner` est rouge

1. Lire l'étape en échec. **Exceptions** : corriger le `osv-scanner.toml`
   nommé. **composer.lock** : `composer update --no-install`, puis commit.
   **Scan** : lire chaque faille sur `https://osv.dev/<id>`.
2. Mettre à jour la dépendance si un correctif est atteignable
   (`cargo update -p <crate>`, `pnpm update <paquet>`, `composer update
   <paquet>`), puis vérifier que les tests restent verts.
3. Sinon seulement, ajouter en PR une exception dans le `osv-scanner.toml` du
   **dossier du lockfile** : `id`, `reason` (origine, pourquoi non
   exploitable chez nous, condition de levée), `ignoreUntil` au plus tard
   92 jours après le jour (le script la refuse sinon). À l'échéance, la
   faille revient : remédier ou renouveler, motif revu.
4. Une exception signalée « unused ignores » (faille corrigée, ou échéance
   passée) : la retirer, ou la renouveler si la faille est toujours là.
5. Sortie 127 (réseau, `api.osv.dev` injoignable) : relancer le job,
   **jamais** excepter.
6. Le cron hebdomadaire notifie l'auteur du dernier changement du cron.
   GitHub désactive les crons d'un dépôt public sans activité depuis
   60 jours : le réactiver depuis l'onglet Actions (workflow garde-fous).
7. Reproduire en local, à la racine du dépôt, avec les commandes du job :

```sh
python3 -I vigie/scripts/check-osv-exceptions.py $(git ls-files ':(glob)**/osv-scanner.toml')
composer validate --no-check-publish
OSV_SCANNER_VERSION=2.6.0
OSV_SCANNER_SHA256=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
curl -sSfL -o osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
echo "${OSV_SCANNER_SHA256}  osv-scanner" | sha256sum -c -
chmod +x osv-scanner
./osv-scanner scan source --lockfile=vigie/Cargo.lock --lockfile=vigie/app/src-tauri/Cargo.lock --lockfile=vigie/app/pnpm-lock.yaml --lockfile=composer.lock
```

Sans accès à `api.osv.dev`, ajouter au scan `--offline-vulnerabilities
--download-offline-databases` (bases OSV complètes téléchargées une fois,
puis `--offline-vulnerabilities` seul). Supprimer le binaire `osv-scanner` après usage : il n'est pas
ignoré par git.
