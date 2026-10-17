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
absent. Un code différent de 0 fait échouer la tâche planifiée.

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
   | `kind` | `wordpress` ou `generic` (défaut) ; ne règle que les contrôles de l'agent. Ce qui compte pour les commandes est le `runtime` déclaré dans `config.toml` **du veilleur** : un site PHP déclaré `generic` y pose `runtime = "php"`, sinon il n'admet aucune commande (`protocole-commandes.md`) |
   | `critical` | 30 chemins relatifs au plus, présence et empreinte |
   | `must_contain` | 10 règles `{"file": …, "text": …}` au plus |
   | `uploads` | Dossier à parcourir, `wp-content/uploads` par défaut pour `wordpress`, `null` pour ne rien parcourir |
   | `commands` | Facultatif : canal de commandes, voir [Commandes du veilleur](#commandes-du-veilleur) |
   | `logs` | Facultatif : logs HTTP poussés au veilleur, voir [Logs HTTP](#logs-http) |

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

## Retrait

1. Supprimer la tâche planifiée dans le panneau du compte.
2. Sur le veilleur : `~/vigie/bin/vigie site remove site-a`. La clé, l'état des
   rapports et la référence des empreintes sont effacés ; les incidents
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
