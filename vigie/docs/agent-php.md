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

L'agent ne garde aucun état : `seq` est l'heure en millisecondes. C'est le
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
   | `kind` | `wordpress` ou `generic` (défaut) |
   | `critical` | 30 chemins relatifs au plus, présence et empreinte |
   | `must_contain` | 10 règles `{"file": …, "text": …}` au plus |
   | `uploads` | Dossier à parcourir, `wp-content/uploads` par défaut pour `wordpress`, `null` pour ne rien parcourir |

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

Les tests travaillent sur des copies temporaires des arborescences de
`agent/php/tests/fixtures/` et vérifient qu'aucun fichier n'est modifié. Sous
Windows, l'antivirus peut mettre en quarantaine un fichier qui ressemble à un
webshell : le test échoue alors avec « Failed to open stream: Invalid
argument » (`Get-MpThreatDetection` le confirme). Les fixtures ne contiennent
que du PHP anodin, à garder ainsi.
