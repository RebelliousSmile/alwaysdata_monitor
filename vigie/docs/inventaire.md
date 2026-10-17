# vigie-inventory : inventaire des projets sans agent PHP (issue #20)

`vigie-inventory` lit les lockfiles d'un projet au moment du déploiement, en
produit l'inventaire CycloneDX 1.7 du veilleur (même liste blanche, mêmes purl
et mêmes bornes que l'agent PHP, F5), et le pousse à `POST /r/v1/inventory`,
signé par une **clé d'inventaire** qui ne sert qu'à cela. Il sert les sites
`node` et `static`, et tout projet déployé par une CI (Laravel, Nuxt, Rust…).

**Un inventaire de CI décrit ce qui va être déployé, pas ce qui tourne** : un
déploiement raté laisse l'ancien code en place. Quand un site a aussi l'agent
PHP, celui-ci reste la vérité du serveur ; le veilleur garde les deux sources
à part et le rapprochement (F7) dit d'où vient chaque composant.

Binaire du crate `vigie` (`src/bin/vigie-inventory.rs`, logique dans
`src/inventory/{lockfile,build,tool}.rs`), version propre `0.1.0`
(`vigie::inventory::TOOL_VERSION`). Aucun accès à `config.toml` ni à la base
du veilleur ; aucune dépendance ajoutée au crate.

## Installation

Depuis la release GitHub `inventory-vX.Y.Z` : un binaire par cible
(`x86_64-` et `aarch64-unknown-linux-musl`, statiques ; `x86_64-pc-windows-msvc` ;
`aarch64-` et `x86_64-apple-darwin`) et `SHA256SUMS`. **Vérifier l'empreinte
dans une étape à part, avant de lancer le binaire** :

```sh
curl -sSfL -o vigie-inventory "https://github.com/RebelliousSmile/alwaysdata_monitor/releases/download/inventory-v0.1.0/vigie-inventory-0.1.0-x86_64-unknown-linux-musl"
echo "<empreinte de SHA256SUMS>  vigie-inventory" | sha256sum -c -
chmod +x vigie-inventory
```

Les binaires ne sont pas signés (hors V1) : `SHA256SUMS` est publié avec la
release. Le build Linux musl est reproductible et vérifié (deux builds dans
deux dossiers, mêmes octets) ; Windows et macOS ne le sont pas garantis.

## Clé d'inventaire

Une paire Ed25519 propre au site et à cet usage : elle ne vérifie que
`vigie-inventory-v1\n` sur `/r/v1/inventory`. Sa fuite (secret de CI) ne
permet que de pousser un faux inventaire pour ce site, jamais un rapport, un
lot de logs ni un retrait de commande. **Une clé publique n'est enregistrée
qu'une fois**, toutes tables et tous sites confondus (clé d'agent ou
d'inventaire) : une clé déjà enregistrée est refusée (code 2).

1. Côté projet, dans un dossier **en 0700** (sinon `--key-file` est refusé) :

   ```sh
   mkdir -m 700 ~/vigie-cle && vigie-inventory keygen --out ~/vigie-cle/site-a.key
   ```

   La graine est écrite en création exclusive, en 0600 ; seule la clé
   publique est affichée, avec la commande à lancer sur le VPS.
2. Côté veilleur : `[sites.inventory] sources = ["ci"]` dans `config.toml`
   (ou `["agent-php", "ci"]` pour un site qui a aussi l'agent ; `ci` est admis
   quel que soit le runtime, même absent), relancer `vigie-serve`, puis
   `~/vigie/bin/vigie site inventory-key site-a add --pubkey <base64>`.
3. Mettre le contenu du fichier en secret **d'environnement de déploiement**
   `VIGIE_INVENTORY_KEY` (GitHub : environnement `production` et environnement
   dédié `vigie-inventory` ; GitLab : variable protégée et masquée), puis
   supprimer le fichier. Jamais dans le dépôt.

La graine est lue dans `VIGIE_INVENTORY_KEY` (jamais par un argument : ni
`--help` ni une erreur d'argument ne l'affiche), ou par `--key-file`
(0600, dossier 0700, sans lien, sous Unix ; sous Windows, lecture simple).
Les deux ensemble : code 2. Elle n'est jamais affichée ni journalisée, et
effacée de la mémoire après signature.

- **Rotation** : nouvelle graine (`keygen`), `vigie site inventory-key site-a
  rotate --pubkey <nouvelle>`, puis mise à jour du secret. Les envois sont
  refusés entre les deux ; `seq` repart de zéro, l'inventaire reçu reste.
- **Retrait** : `vigie site inventory-key site-a remove` (l'inventaire reçu
  reste, purgé 30 jours après son dernier envoi si `ci` n'est plus déclaré) ;
  `vigie site remove site-a` retire tout, clés et inventaires.
- `vigie site list` montre, par site, les sources d'inventaire prêtes
  (`agent`, `ci`, `agent+ci`, `—`).

## Sous-commandes

| Commande | Rôle |
| --- | --- |
| `vigie-inventory keygen --out <fichier>` | Crée une graine (0600, création exclusive) et affiche sa clé publique |
| `vigie-inventory pubkey [--key-file <fichier>]` | Clé publique de la graine fournie |
| `vigie-inventory sbom [--site S] [--output F]` | BOM CycloneDX seul, sans enveloppe, sans clé ni réseau ; stdout par défaut ; `metadata.component.name` = le site, sinon `projet` |
| `vigie-inventory push --site S --endpoint URL [--output F] [--dry-run] [--skip-without-key] [--key-file F]` | Signe et envoie ; `--dry-run` affiche l'enveloppe non signée et n'envoie rien ; `--output` écrit aussi le BOM ; `--skip-without-key` : sans clé, message et code 0 |

Options communes : `--project-dir` (défaut `.`), `--lockfile <chemin>`
(répétable, 10 au plus, relatif au projet, sans `..` ni lien sortant du
projet ; sinon les cinq noms connus à la racine du projet seulement, sans
parcours des sous-dossiers), `--cms wordpress`, `--omit-dev`.

`--endpoint` est l'URL **de base** du veilleur (`https://vigie.example.org`) :
`https` exigé, chemin vide ou `/`, ni requête, ni fragment, ni identifiants ;
l'outil ajoute `/r/v1/inventory`. Aucun proxy n'est utilisé (même si
`HTTPS_PROXY` est posé), aucune redirection n'est suivie, délai de 30 s.

**Codes de sortie** : 0 écrit ou envoyé (204) ; 1 refus du veilleur ou
réseau (404 muet : la raison est dans `journalctl -u vigie-serve`) ; 2 usage,
clé, lockfile, projet. stderr porte une ligne par fait (lockfiles lus,
composants, membres ignorés, hors registre, écartés, omis, tronqués), jamais
un nom de composant, la graine, une signature ni le corps.

## Formats lus

| Fichier | Versions admises | Portée `dev` |
| --- | --- | --- |
| `composer.lock` | `packages`, `packages-dev` | lue (`packages-dev`) |
| `package-lock.json` | `lockfileVersion` 2 et 3 | lue (`dev: true` ; `devOptional` → exécuté) |
| `pnpm-lock.yaml` | `lockfileVersion` `'6.0'` (pnpm 8) et `'9.0'` (pnpm 9 et 10) | lue en 6.0 ; inconnue en 9.0 : tout exécuté |
| `yarn.lock` | v1 (en-tête `# yarn lockfile v1` dans les commentaires de tête) ; berry `__metadata.version` 6 (yarn 3), 8 (yarn 4 jusqu'à 4.5) et 10 (yarn 4 récent) | inconnue : tout exécuté |
| `Cargo.lock` | `version = 3` et `4` | inconnue : tout exécuté |

Tout autre nom (`npm-shrinkwrap.json`, `bun.lock`, `poetry.lock`…) ou version
(`package-lock.json` v1, pnpm 5, `Cargo.lock` v1/v2…) est refusé : code 2,
rien d'écrit ni d'envoyé. De même un lockfile illisible ou corrompu, de plus de
32 Mio, à ligne de plus de 64 Kio ou à plus de 200 000 entrées.
`pnpm-lock.yaml` et `yarn.lock` sont lus par un lecteur ligne à ligne borné,
sans crate YAML : un bloc non lu est sauté quel que soit son contenu, une
ancre, un alias ou un bloc littéral sur une valeur lue est refusé.

**Un lockfile npm par dossier, sans priorité** : `package-lock.json`,
`pnpm-lock.yaml` et `yarn.lock` décrivent le même `node_modules`. Plusieurs à la
racine sans `--lockfile` → code 2 et un message qui les nomme : en désigner un
par `--lockfile`.

Règles :

- **purl** de la grammaire commune (`failles.md`) : `pkg:composer/<vendor>/<nom>`
  (minuscules), `pkg:npm/<nom>` ou `pkg:npm/%40<scope>/<nom>` (casse gardée),
  `pkg:cargo/<nom>` ; version hors grammaire ou de plus de 128 caractères :
  version vide, purl sans `@`, jamais tronquée ; nom hors grammaire : écarté et
  compté dans `skipped`.
- **Alias npm** : le purl porte le vrai paquet (champ `name` de l'entrée,
  `alias@npm:vrai@^1`, `npm:` de pnpm et berry). Yarn berry
  `patch:<nom>@npm%3A<v>#…` → `pkg:npm/<nom>@<v>` (un correctif local ne
  retire pas la faille amont). pnpm : suffixes de pairs `(…)` retirés.
- **Membres du projet** (racine, workspaces, `link:`, `workspace:`,
  `portal:`, membres Cargo sans `source`) : ni émis, ni comptés.
- **Hors registre** (git, `file:`, archive ou URL, `exec:`, Cargo d'un autre
  registre que crates.io ; Composer : registre **si et seulement si**
  `notification-url` est présent ou le nom est `wpackagist-plugin/…` ou
  `wpackagist-theme/…`) : non émis, comptés dans `skipped`, donc
  `complete = false` : l'absence d'une faille n'y est pas démontrée.
- `--cms wordpress` : `wpackagist-plugin|theme/<slug>` → `pkg:wordpress/…`, un
  par purl sans version ; sans l'option, ils restent `pkg:composer`. Les
  `prestashop-module` restent toujours `pkg:composer/prestashop/<x>`.
- **Doublons** : un composant par (purl complet, `vigie:path`) ; le même paquet
  dans deux lockfiles donne deux composants.
- **Bornes** de F5 (2 000 composants, enveloppe de 524 288 octets) : ordre
  global, tous les `required` de tous les lockfiles puis tous les `dev` ; la
  troncature retire depuis la fin (tout le développement avant le moindre
  `required`), avertit sur stderr et propose `--omit-dev`. `--omit-dev` qui
  retire un composant rend aussi l'inventaire incomplet.
- Le document est revalidé par la liste blanche du veilleur avant toute
  écriture ou tout envoi (`Generic`, ou `Wordpress` avec `--cms wordpress`) ;
  un échec est une erreur interne, jamais envoyée.

## Côté veilleur

- Source `ci` déclarée par `[sites.inventory] sources` ; la clé qui vérifie la
  signature fixe la source, répétée dans l'enveloppe (`"source": "ci"`).
- Dernier inventaire, `seq`, débit et plafond **par (site, source)** : un
  envoi de CI ne remplace ni ne rationne l'inventaire de l'agent.
- **Horloge** : `sent_at` doit être à ±5 min de l'heure du veilleur ; une
  machine de CI dont l'horloge dérive davantage voit ses envois refusés.
  `seq` est l'heure Unix en millisecondes au moment de signer : de deux
  pipelines simultanés, le second à signer gagne.
- **Débit `ci`** : 240 s pour le seul renvoi inchangé ; un inventaire nouveau
  n'est borné que par 24 par jour UTC (deux déploiements rapprochés décrivent
  deux états réels).
- **Péremption** : sans inventaire `ci` depuis 35 jours, « inventaire
  périmé » (F7). D'où le job planifié hebdomadaire des exemples, qui renvoie
  l'inventaire du **SHA du dernier déploiement réussi de production**,
  jamais celui de la branche.

## CI et scripts

Exemples dans [`examples/inventaire/`](../examples/inventaire/) :

- `vigie-inventory-push.sh` : enveloppe POSIX commune. Code 1 (veilleur
  injoignable ou refus) → avertissement (`::warning::` sous GitHub) et code 0 ;
  tout autre code transmis : une configuration fausse (code 2) arrête le job.
  Aucune option de CI qui laisse passer un échec.
- `github-actions.yml` : job de déploiement (`environment: production`,
  jamais sur une PR venue d'un fork) en deux étapes (téléchargement et
  empreinte, puis envoi) ; job planifié hebdomadaire dans l'**environnement
  dédié et obligatoire `vigie-inventory`** (même secret, sans relecteur), qui
  lit les déploiements `environment=production` (API Deployments) et sort en
  code 2 sans déploiement réussi. Jamais `production` pour ce job : il créerait
  lui-même le « dernier déploiement réussi » qu'il lit ; et un `schedule` sur un
  environnement protégé par des relecteurs attendrait une approbation chaque
  semaine.
- `gitlab-ci.yml` : même chose ; job planifié séparé, **sans
  `environment:`**, `rules: $CI_PIPELINE_SOURCE == "schedule"`, SHA lu par
  l'API des déploiements (`status=success`, `order_by=finished_at`) avec un
  jeton de projet en lecture seule (l'accès de `CI_JOB_TOKEN` n'a pas été
  vérifié).
- `composer.json` : script explicite `composer run-script vigie-inventory`,
  gardé par `command -v vigie-inventory` (sans binaire : code 0), jamais
  `post-install-cmd`. `package.json` : `npm run vigie:inventory`, jamais
  `postinstall` (lancé à chaque `npm install`, ignoré par `--ignore-scripts`).
  Shell POSIX : ne marchent pas tels quels sous Windows.

Les exemples supposent que le déploiement est enregistré par la CI elle-même
(environnement GitHub ou GitLab). Pas de plugin Composer ni de paquet npm
publié.

## Limites V1

Plugin Composer et paquet npm ; `npm-shrinkwrap.json`, `package-lock.json`
v1, pnpm 5, `Cargo.lock` v1/v2, `bun.lock`, `poetry.lock`, `go.sum` et tout
autre écosystème ; parcours récursif des sous-dossiers ; cœur WordPress
(`roots/wordpress`, `johnpbloch/wordpress`) et modules PrestaShop sur disque ;
portée de développement pour pnpm 9, yarn et Cargo ; proxy HTTP ; signature
des binaires ; lecture de l'inventaire par l'API, la console ou la CLI (F7).

## Fixtures

`tests/fixtures/inventory-tool/` : lockfiles produits par les vrais outils
(composer, npm, pnpm 8 et 9, yarn 1, 3 et 4, cargo ; `NOTICE`), suffixés
`.fixture` et copiés sous leur vrai nom par les tests : ni Dependabot ni le
graphe de dépendances de GitHub ne les prennent pour des dépendances du dépôt.
Aucun lockfile de client ; hôtes limités aux registres publics et à
`example.org` (test `fixtures_only_name_public_registries_and_example_org`).
Le job `inventory-schema` de `vigie.yml` valide le BOM de chaque fixture contre
le schéma officiel CycloneDX 1.7 (`cyclonedx-cli`).
