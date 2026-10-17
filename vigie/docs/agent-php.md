# Agent PHP

L'agent est un fichier PHP unique, sans dépendance
([`agent/php/vigie-agent.php`](../agent/php/vigie-agent.php)), lancé par une
tâche planifiée sur le compte d'hébergement du site. À chaque passage, il lit
l'arborescence du site sans rien y écrire, signe un rapport et l'envoie au
veilleur selon le [protocole v1](./protocole-agent.md).

Prérequis : PHP 8.1 ou plus en ligne de commande, avec l'extension sodium (le
code de retour 3 signale qu'elle manque).

## Ce que l'agent contrôle

| Contrôle | Constat |
| -------- | ------- |
| `root` | Critique si la racine `root` est introuvable : aucun autre contrôle n'est lancé |
| `critical-file` | Critique si un fichier de `critical` est absent, illisible ou un lien qui sort de `root`. L'empreinte SHA-256 de chacun part dans `files` |
| `must-contain` | Critique si un fichier de `must_contain` est absent ou ne contient plus son texte, par exemple le bloc de verrou de l'installeur dans `.htaccess` |
| `uploads-php` | Critique pour chaque fichier PHP sous `uploads` (500 entrées et 20 s au plus), avec chemin, taille et empreinte. Seul un `index.php` de silence de moins de 64 octets est exempté. Avertissement si le parcours est interrompu par une borne |

Le rapport porte aussi des faits : version de WordPress (`wp-includes/version.php`),
version de PHP, version de l'agent. Les liens symboliques ne sont jamais suivis
hors de `root`.

Le rapport ne dépend d'aucun état : son `seq` est l'heure en millisecondes (seul le canal de commandes, facultatif, garde un état, voir plus bas). C'est le
veilleur qui compare les empreintes à la référence du site et ouvre un
avertissement `agent:integrity` quand un fichier critique change (voir
[Intégrité des fichiers critiques](./protocole-agent.md#intégrité-des-fichiers-critiques)).

Appelé par le web, le fichier sort aussitôt sans rien lire ni envoyer. Il n'a
pourtant rien à faire sous `~/www` : le script de déploiement refuse cette
destination.

Codes de retour : 0 succès, 1 envoi échoué, 2 configuration ou usage, 3 sodium
absent. Un code différent de 0 fait échouer la tâche planifiée. Ordre d'un
passage : rapport, commandes, inventaire, logs ; l'échec de l'un n'empêche pas
les suivants.

## Pose

Les exemples visent le site A et le compte `<compte-site-a>`. Les commandes
`ssh` passent par WSL avec la clé dédiée de la cible.

1. **Accès SSH.** Ajouter la cible à `vigie/deploy/targets.json` (fichier ignoré
   par git, modèle `site-a-agent` dans `targets.example.json`), puis créer et
   autoriser la clé :

   ```powershell
   wsl ssh-keygen -t ed25519 -N "" -C vigie-site-a-agent -f ~/.ssh/vigie_agent
   wsl ssh-copy-id -i ~/.ssh/vigie_agent.pub <compte-site-a>@<hote-ssh-alwaysdata>
   ```

   Une clé WSL déjà autorisée sur le compte, celle d'un déploiement du site par
   exemple, peut servir à la place : indiquer son chemin dans `sshKey`. Noter
   ce choix, car au retrait cette clé reste en place (voir [Retrait](#retrait)).

2. **Envoi de l'agent** dans `~/vigie-agent/vigie-agent.php` :

   ```powershell
   node vigie/scripts/deploy-agent.mjs site-a-agent           # prévisualisation
   node vigie/scripts/deploy-agent.mjs site-a-agent --apply   # envoi
   ```

3. **Configuration**, sur le compte du site, dans `~/.vigie-agent/config.json`
   (modèle : [`agent/php/config.example.json`](../agent/php/config.example.json)).
   Toute clé inconnue est refusée.

   | Clé | Rôle |
   | --- | ---- |
   | `site` | Identifiant du site dans `config.toml` du veilleur |
   | `endpoint` | `https://<sous-domaine-du-veilleur>/r/v1/report` |
   | `root` | Racine absolue du site, par exemple `/home/<compte-site-a>/www` |
   | `kind` | `wordpress`, `prestashop` (agent 0.5.0) ou `generic` (défaut) ; ne règle que les contrôles et l'inventaire de l'agent. Ce qui compte pour les commandes est le `runtime` déclaré dans `config.toml` **du veilleur** : un site PHP déclaré `generic` y pose `runtime = "php"`, sinon il n'admet aucune commande (`protocole-commandes.md`) |
   | `critical` | 30 chemins relatifs au plus, présence et empreinte |
   | `must_contain` | 10 règles `{"file": …, "text": …}` au plus |
   | `uploads` | Dossier à parcourir, `wp-content/uploads` par défaut pour `wordpress`, `null` pour ne rien parcourir |
   | `commands` | Facultatif : canal de commandes, voir [Commandes du veilleur](#commandes-du-veilleur) |
   | `logs` | Facultatif : logs HTTP poussés au veilleur, voir [Logs HTTP](#logs-http) |
   | `inventory` | Facultatif : inventaire des composants (agent 0.5.0), voir [Inventaire](#inventaire-agent-050-issue-19) |

4. **Clé de signature** :

   ```sh
   php ~/vigie-agent/vigie-agent.php --init
   ```

   La clé privée est écrite dans `~/.vigie-agent/secret.key` (dossier 0700,
   fichier 0600) ; la clé publique est affichée en base64. `--init` refuse
   d'écraser une clé existante, et l'agent refuse une clé lisible par d'autres
   utilisateurs.

5. **Enregistrement sur le veilleur** :

   ```sh
   ~/vigie/bin/vigie site add site-a --pubkey <clé-publique>
   ```

6. **Essai à blanc**, qui affiche le rapport sans le signer ni l'envoyer :

   ```sh
   php ~/vigie-agent/vigie-agent.php --dry-run
   ```

   Attendu : `findings: []` et le code 0. Un constat à ce stade existe déjà en
   production : le traiter avant la tâche planifiée, sinon le premier rapport
   ouvre un incident (voir [Extension qui range du PHP dans uploads](#extension-qui-range-du-php-dans-uploads)).

7. **Tâche planifiée**, à créer dans le panneau du compte `<compte-site-a>`
   (Avancé → Tâches planifiées, type commande, toutes les 5 minutes) :

   ```txt
   php /home/<compte-site-a>/vigie-agent/vigie-agent.php
   ```

   Chemin absolu : rien ne garantit que la tâche démarre dans le dossier
   personnel. Chaque passage est journalisé, avec son code de retour, dans
   `~/admin/logs/jobs/<année>/<id-de-tâche>-<date>.log`. Si le PHP du compte
   affiche un avertissement au démarrage (`Module "intl" is already loaded`
   par exemple), il part dans la sortie de chaque passage sans changer le
   code de retour.

   Le premier rapport accepté pose la référence des empreintes. Vérifier sur
   le veilleur que `~/vigie/bin/vigie status` montre un rapport de moins de
   6 minutes pour le site. Au-delà de `agent_silence` (900 s par défaut) sans
   rapport accepté, le veilleur ouvre un incident `heartbeat`.

## Extension qui range du PHP dans uploads

Certaines extensions écrivent leurs propres fichiers `.php` sous `uploads`.
C'est le cas de Sucuri Scanner : ses fichiers de données sont du PHP, dans
`wp-content/uploads/sucuri/`. L'agent les signale comme `uploads-php`
critiques, à raison : un dossier où PHP peut écrire et que le web sert est
exactement l'endroit où l'on cherche un webshell. Ne pas les exempter dans
l'agent, sortir les données du webroot :

1. Sauvegarder `wp-config.php` (copie en 0600 hors du webroot).
2. Copier le dossier hors du webroot, par exemple `~/sucuri-data` (0700).
3. Déclarer ce dossier dans `wp-config.php`, avant la ligne
   `/* That's all, stop editing! */` :

   ```php
   define( 'SUCURI_DATA_STORAGE', '/home/<compte-site-a>/sucuri-data' );
   ```

4. Vérifier `php -l wp-config.php` et que le site répond, puis supprimer
   `wp-content/uploads/sucuri/`.
5. Relancer `--dry-run` : les constats `uploads-php` ont disparu.

La constante vit dans `wp-config.php` : un `wp-config.php` réécrit (nouvelles
clés et salts, restauration) doit la reprendre, sinon Sucuri recrée ses
fichiers dans `uploads` et l'agent ouvre un incident critique.

## Modification voulue d'un fichier critique

Une mise à jour de WordPress, du `.htaccess` ou de `wp-config.php` ouvre un
avertissement `agent:integrity` au rapport suivant. Une fois la modification
vérifiée :

```sh
~/vigie/bin/vigie site accept site-a
```

Les empreintes du dernier rapport deviennent la référence et les incidents
d'intégrité sont clos. Un fichier qui change encore après `accept` est de
nouveau signalé.

## Mise à jour de l'agent

Relancer `deploy-agent.mjs` depuis `main` : l'ancien fichier est conservé en
`~/vigie-agent/vigie-agent.php.prev`, et la tâche planifiée prend le nouveau à
son passage suivant. La configuration et la clé ne changent pas.

## Rotation de la clé

Sur le compte du site :

```sh
mv ~/.vigie-agent/secret.key ~/.vigie-agent/secret.key.old
php ~/vigie-agent/vigie-agent.php --init
```

Sur le veilleur, avec la nouvelle clé publique :

```sh
~/vigie/bin/vigie site rotate-key site-a --pubkey <nouvelle-clé-publique>
```

Entre les deux étapes, les rapports signés par la nouvelle clé sont refusés et
la tâche planifiée échoue : enchaîner les deux sans attendre. Supprimer ensuite
`secret.key.old`. En cas de fuite de la clé, faire `rotate-key` (ou
`site remove`) d'abord : les rapports signés par l'ancienne clé sont refusés
dès maintenant.

## Commandes du veilleur

Facultatif, fermé par défaut. Avec une section `commands` dans `config.json`,
l'agent retire après chaque rapport la commande de son site
([`protocole-commandes.md`](./protocole-commandes.md)) :

```json
"commands": {
  "endpoint": "https://<sous-domaine-du-veilleur>/r/v1/commands",
  "pubkey": "<sortie de vigie commands pubkey>"
}
```

- `pubkey` **épingle** la clé de commandes du veilleur : une réponse signée
  par une autre clé n'exécute rien. Elle ne change que par une nouvelle pose.
- Avec `commands`, l'agent exige `config.json` en 0600 et son dossier en 0700,
  au propriétaire du processus, sans lien symbolique : sinon il refuse de
  retirer. Sous Windows, `commands` est refusé (droits non vérifiables).
- L'état du canal vit à côté de la clé, dans `state.json` (0600, écrit par
  fichier temporaire puis `rename`, sous `flock` de `state.lock`) : séquences,
  commande en cours, résultat en attente d'accusé. Un passage concurrent saute
  les commandes. Un état illisible ou ouvert arrête le canal, pas le rapport.
- Ce que l'agent exécute : `ping` (rien, répond `pong`), `rotate-key` (voir
  ci-dessous), `htaccess-apply` et `htaccess-rollback` (voir plus bas). Tout
  autre nom fait rejeter la réponse. Aucun `eval`, aucun appel shell.
- Une commande n'est exécutée qu'une fois ; son résultat est renvoyé à chaque
  passage jusqu'à l'accusé du veilleur. Une exécution interrompue revient
  `failed` (« exécution interrompue »).
- `rotate-key` : nouvelle paire dans `secret.key.new`, preuve de possession
  envoyée avec le résultat ; la bascule (`secret.key.new` devient
  `secret.key`, l'ancienne est gardée en `secret.key.old`) n'a lieu que sur un
  accusé accepté, ou sur une réponse **signée** à un retrait signé par la
  nouvelle clé. Un 204 de rapport, non signé, ne fait jamais basculer.
- Activer côté veilleur : `vigie site commands site-a enable`. Un site PHP
  déclaré `generic` dans `config.toml` doit y porter `runtime = "php"`.

### `.htaccess` (agent 0.4.0, issue #13)

`htaccess-apply` remplace le bloc `# BEGIN vigie` du `.htaccess` de `root`,
`htaccess-rollback` remet la copie précédente ; procédure complète dans
[`htaccess.md`](./htaccess.md). Deux clés de `config.json` les activent :

```json
"url": "https://site-a.example.org/",
"tz": "Europe/Paris"
```

- `url` : adresse https de la racine servie par `root` (http seulement vers
  la boucle locale, pour les tests). Le bac à sable et le smoke-test y
  envoient des requêtes : 5 s chacune, 30 s en tout, aucune redirection
  suivie.
- `tz` : fuseau du serveur web, celui de `%{TIME}` ; appliqué par
  `date_default_timezone_set`, jamais celui de `php.ini`. Les sondes
  d'horloge du bac à sable refusent tout écart avec l'horloge réelle
  d'Apache.
- Sans l'une d'elles, `htaccess-*` répond `refused`.
- L'agent revalide le bloc par sa propre grammaire fermée et son propre
  corpus d'UA protégés (`PROTECTED_UAS`) avant toute écriture, puis bac à
  sable (`vigie-essai-<hex>-a` et `-b`, supprimés dans tous les cas),
  compare-and-swap, copie privée `htaccess.prev` (0600) dans **son** dossier,
  bascule par `rename`, smoke-test et retour automatique.
- `state.json` porte `htaccess_pending` pendant une bascule : un passage
  interrompu est repris en tête du passage suivant, avant tout retrait. Un
  `state.json` d'agent 0.2.0 ou 0.3.0 est migré sans perte.
- Retour arrière à la main : `cp ~/.vigie-agent/htaccess.prev ~/www/.htaccess`.

## Logs HTTP

Facultatif. Avec une section `logs`, l'agent pousse, après le rapport et le
retrait, les lignes nouvelles du log HTTP d'Alwaysdata à `/r/v1/logs`
(contrat : [`logs.md`](./logs.md#transport-alwaysdata-issue-1)) :

```json
"logs": {
  "dir": "/home/<compte-site-a>/admin/logs/http",
  "hosts": ["site-a.example.org", "www.site-a.example.org"]
}
```

| Clé | Rôle |
| --- | ---- |
| `dir` | Chemin absolu du dossier `admin/logs/http` du compte : l'agent y lit `<année>/http-<date>.log` et `.log.gz`, sans suivre de lien hors de lui |
| `hosts` | 1 à 20 hôtes du site, en minuscules, sans port : seules leurs lignes partent (un fichier Alwaysdata couvre tout le compte) |

- `endpoint` doit finir par `/r/v1/report` : les lots partent sur
  `/r/v1/logs` du même veilleur.
- Côté veilleur, `config.toml` active la réception pour le site :

  ```toml
  [sites.logs]
  source = "alwaysdata"
  hosts = ["site-a.example.org", "www.site-a.example.org"]
  # tz = "Europe/Paris"   # seulement si les lignes n'ont pas de décalage
  ```

  Sans `source`, tout lot du site est refusé.
- La position vit dans `logs.json` (0600, à côté de la clé), sous `flock` de
  `logs.lock` : un passage concurrent saute les logs, pas les commandes. Un
  état illisible ou ouvert arrête les logs (code 2) ; le supprimer fait
  repartir du début du fichier le plus récent, relu au pire une fois.
- Un lot envoyé et non accusé (réponse perdue, refus) est renvoyé à
  l'identique au passage suivant : le veilleur ne le compte qu'une fois.
- 20 lots de 44 Kio et 20 s au plus par passage : un retard se rattrape en
  quelques passages, dans la limite de 50 Mo par jour côté veilleur.
- Avec une rotation de clé non accusée, l'agent essaie aussi la nouvelle clé,
  comme pour le rapport.

## Inventaire (agent 0.5.0, issue #19)

Facultatif. Avec une section `inventory`, l'agent relève les composants du
site et les pousse au veilleur, signés, à `/r/v1/inventory`, en CycloneDX 1.7
(contrat : [`protocole-agent.md`](./protocole-agent.md#inventaire-des-composants-issue-19),
conventions purl : [`failles.md`](./failles.md#conventions-purl)). Le site ne
connaît aucune base de failles : le rapprochement se fait sur le veilleur (F7).

```json
"inventory": {
  "enabled": true,
  "composer": ["app/composer.lock"],
  "npm": ["theme/package-lock.json"]
}
```

| Clé | Rôle |
| --- | ---- |
| `enabled` | Obligatoire, `true` ou `false`. Section absente ou `false` : aucun relevé, aucun fichier `inventory.*` |
| `composer`, `npm` | Facultatifs : 10 chemins relatifs au plus chacun, segments de `[A-Za-z0-9._@+-]`, lus **en plus** de `composer.lock` et `package-lock.json` de la racine (lus s'ils existent) |

- `endpoint` doit finir par `/r/v1/report` : l'inventaire part sur
  `/r/v1/inventory` du même veilleur.
- Côté veilleur, `config.toml` active la réception pour le site (sans elle,
  tout inventaire est refusé avant même la lecture du corps) :

  ```toml
  [sites.inventory]
  source = "agent-php"
  ```

### Ce qui est relevé

Lecture seule, sans jamais exécuter ni inclure de PHP du site, ni analyseur
XML : `file_get_contents` borné et `json_decode` seulement. Rien n'est deviné :
le `kind` de `config.json` choisit les sources.

| `kind` | Sources |
| --- | --- |
| `wordpress` | cœur (`wp-includes/version.php`) ; extensions (`wp-content/plugins/<slug>/`, en-tête `Plugin Name:` du `<slug>.php` puis des autres `.php` du premier niveau, 20 au plus ; fichier unique `plugins/<x>.php`) ; mu-plugins (`wp-content/mu-plugins/*.php` portant `Plugin Name:`, `vigie:scope = mu`) ; thèmes (`style.css` portant `Theme Name:`, `Template:` en `vigie:parent`) |
| `prestashop` | noyau (`src/Core/Version.php` en 8.1 et suivantes dont 9, `app/AppKernel.php` en 1.7 et 8.0, `config/settings.inc.php` en 1.6, littéraux seulement) ; modules (`modules/<x>/<x>.php`) |
| tous | `composer.lock` (`packages` → `required`, `packages-dev` → `dev`) et `package-lock.json` v2 et v3 |

- **Version d'un module PrestaShop** : d'abord le littéral `$this->version` du
  fichier principal (64 Kio), version qui tourne ; repli sur `config.xml`
  (8 Kio), lu comme du texte (UTF-8 valide, sans NUL, sans `<!` autre que
  `<![CDATA[`) ; les deux lus et différents → version du littéral et
  `vigie:config-version` (cache régénéré par PrestaShop).
- **Composer et CMS** : sur un site `prestashop`, un paquet `prestashop-module`
  n'est jamais émis en `pkg:composer` (son module vient du relevé de
  `modules/`, version d'installation périmée du lockfile ignorée, rien s'il
  n'y est pas) ; sur un site `wordpress`, `wpackagist-plugin/<slug>` et
  `wpackagist-theme/<slug>` (Bedrock) deviennent `pkg:wordpress/…`, le relevé
  du disque l'emportant. **Sur un site `generic`, ils restent en
  `pkg:composer` et ne sont jamais rapprochés** d'une faille WordPress.
- **Registre** : un paquet de `composer.lock` compte s'il porte
  `notification-url` (Packagist, dépôts Composer) ou si son nom est
  `wpackagist-plugin/…` ou `wpackagist-theme/…` (WPackagist n'en écrit pas) ;
  sinon (`path`, vcs, `package` en ligne) il est écarté et compté dans
  `skipped`. Dans `package-lock.json`, `resolved` en `git+`, `git:`,
  `github:`, `file:`, ou URL qui n'a pas la forme d'une archive de registre
  (`…/-/<fichier>.tgz`) : écarté et compté. Les membres du projet (clé `""`,
  workspaces, `link: true`) et les paquets `extraneous` ne sont ni émis ni
  comptés. Même règle que l'outil d'inventaire (#20).
- **Alias npm** : le nom est le champ `name` de l'entrée s'il existe (le vrai
  paquet), sinon ce qui suit le dernier `node_modules/` de la clé ; casse
  gardée ; `dev: true` → `dev`, `devOptional: true` → `required`.
- **Doublons** : pour WordPress et PrestaShop, un composant par purl sans
  version ; pour Composer et npm, un par (purl complet, `vigie:path`), deux
  lockfiles pouvant porter deux versions réelles du même paquet.
- **Grammaire** : la même que le veilleur (`purl.json` rejoué par les tests).
  Aucune valeur n'est tronquée : une version de plus de 128 caractères, à `~`
  ou piégée devient vide (purl sans `@`) ; un nom hors grammaire écarte le
  composant, compté.

### Bornes et inventaire partiel

2 000 composants ; 8 Kio par en-tête, 64 Kio pour un fichier principal de
module ; 500 entrées par dossier listé ; lockfiles de 4 Mio, profondeur JSON
32 ; 20 s de relevé ; corps de 512 Kio, des composants étant retirés depuis
la fin (cœur, extensions, mu, thèmes, noyau, modules, Composer, npm) au-delà.
Un dossier ou un fichier en lien symbolique (même vers l'intérieur pour un
dossier d'extension, de thème ou de module), hors racine, illisible, un
lockfile trop gros, invalide ou en v1, une borne atteinte : `complete = false`
et `skipped` compté. **Seul un inventaire complet vaut absence d'un
composant** pour le rapprochement.

### Envoi, relevé économe et état

- Envoi quand l'empreinte de la liste change, et au moins toutes les 24 h
  (le veilleur garde l'inventaire frais sans le réécrire). Après un refus ou
  un échec réseau, pas de nouvel essai avant 1 h (code 1, raison dans
  `journalctl -u vigie-serve`).
- Relevé seulement si l'empreinte (chemin, mtime, taille) des dossiers listés
  et des fichiers lus au relevé précédent a changé, si le dernier relevé date
  d'une heure, ou si un renvoi est dû : un passage toutes les 5 minutes ne
  relit pas 50 extensions pour rien.
- État dans `inventory.json` (0600, à côté de la clé), sous `flock` de
  `inventory.lock` : un passage concurrent saute l'inventaire (« un autre
  passage relève l'inventaire : ce passage le saute »), jamais les commandes.
  Un état illisible, ouvert ou en lien arrête l'inventaire (code 2), le
  rapport part quand même ; le supprimer refait un relevé et un envoi.
  `state.json` n'est jamais touché.
- Avec une rotation de clé non accusée, l'agent essaie aussi la nouvelle clé.

### Pose et relecture

1. Veilleur d'abord : `[sites.inventory] source = "agent-php"`, puis
   redémarrer `vigie-serve`.
2. Agent 0.5.0 déployé, puis relecture sans rien signer, envoyer ni écrire :

   ```sh
   php ~/vigie-agent/vigie-agent.php --inventory
   ```

   `--inventory` est exclusif avec `--dry-run` et `--init`, et marche avant
   l'activation.
3. Ajouter `"inventory": {"enabled": true}` à `config.json`.

### Limites V1

Disposition Bedrock complète (lockfile hors de `web/`), `roots/wordpress` et
`johnpbloch/wordpress` comme cœur, `vendor/composer/installed.json` sans
`composer.lock`, `package-lock.json` v1, yarn et pnpm (outil d'inventaire,
#20), drop-ins WordPress, thèmes PrestaShop, licences et hachages ne sont pas
relevés. Une extension à fichier unique prend le nom du fichier : `hello.php`
n'est pas `hello-dolly`.

### Retour à 0.4

Retirer **d'abord** `inventory` et `kind: "prestashop"` de `config.json`
(revenir à `generic` pour une boutique), puis redéployer l'agent 0.4 : sinon
l'agent 0.4 refuse la configuration (code 2), n'envoie plus de rapport, et le
site tombe en silence (`heartbeat`).

## Retrait

1. Supprimer la tâche planifiée dans le panneau du compte.
2. Sur le veilleur : `~/vigie/bin/vigie site remove site-a`. La clé, l'état des
   rapports, la référence des empreintes et les inventaires sont effacés ; les incidents
   `agent:` ouverts sont clos au `tick` suivant.
3. Sur le compte du site : `rm -r ~/vigie-agent ~/.vigie-agent`.
4. Retirer la cible de `vigie/deploy/targets.json` et, si la clé SSH était
   dédiée à l'agent, la clé publique `vigie_agent` de `~/.ssh/authorized_keys`
   du compte. Une clé partagée avec le déploiement du site reste en place.

## Tests en local

```powershell
php -d extension=sodium vigie/agent/php/tests/run.php
```

Les tests `htaccess` servent un site par `php -S` (routeur
`tests/site-router.php`, qui applique le bloc vigie et simule les pannes).
Avec `VIGIE_APACHE=/usr/sbin/apache2` (Linux, `mod_rewrite`), un test de plus
fait le même parcours sur un Apache réel.

Les tests travaillent sur des copies temporaires des arborescences de
`agent/php/tests/fixtures/` et vérifient qu'aucun fichier n'est modifié. Sous
Windows, l'antivirus peut mettre en quarantaine un fichier qui ressemble à un
webshell : le test échoue alors avec « Failed to open stream: Invalid
argument » (`Get-MpThreatDetection` le confirme). Les fixtures ne contiennent
que du PHP anodin, à garder ainsi.
