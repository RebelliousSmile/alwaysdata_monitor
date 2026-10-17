---
status: done
---

# Instruction: Relevé des composants par l'agent PHP (sans réseau)

## Architecture projection

```txt
.
└── vigie/agent/php/
    ├── vigie-agent.php                 ✏️ section « Inventaire » : configuration, relevés WordPress / PrestaShop / Composer / npm, purl selon la grammaire commune, CycloneDX, bornes, kind prestashop
    ├── config.example.json             ✏️ section inventory d'exemple ({"enabled": true})
    └── tests/
        ├── AgentTest.php               ✏️ tests du relevé : chaque purl attendu, vecteurs purl.json de F1, bornes, fichiers hostiles, lecture seule
        └── fixtures/
            ├── wp-inventory/           ✅ site A fictif : wp-includes/version.php, plugins (dossier, fichier unique, sans en-tête, en-tête précédé de <?php et en \r\n), mu-plugins (avec et sans Plugin Name), thèmes parent et enfant, composer.lock (packages + packages-dev, wpackagist-plugin aussi sur disque, wpackagist-theme seul, même paquet dans un second lockfile à une autre version), package-lock.json v3 (scope, majuscules, workspace, extraneous, devOptional)
            ├── ps16-inventory/         ✅ site B fictif PrestaShop 1.6 : config/settings.inc.php, modules avec littéral seul, config.xml seul, les deux en accord
            ├── ps8-inventory/          ✅ site B fictif PrestaShop 8 : app/AppKernel.php, modules dont un à config.xml périmé, composer.lock avec prestashop-module à version d'installation périmée et un absent de modules/
            ├── ps-hostile/             ✅ config.xml à DOCTYPE et entités, avec NUL, en UTF-8 invalide, mal formé (texte inerte)
            └── inventory-expected.json ✅ purl, version, scope, vigie:scope, vigie:path, vigie:config-version attendus par fixture
```

## Test Scope

```mermaid
journey
  section Happy path
    wp-inventory => cœur pkg:wordpress/core/core, extensions, fichier unique, mu-plugin, thèmes parent et enfant, Composer, npm : liste égale à inventory-expected.json: 5: agent
    ps16-inventory et ps8-inventory => noyau et modules en pkg:prestashop, version du littéral $this->version: 5: agent
    ps8 : config.xml différent du littéral => version du littéral, vigie:config-version porte celle de config.xml: 5: agent
    ps8 : prestashop-module du composer.lock => émis une fois en pkg:prestashop/module, jamais en pkg:composer ; absent de modules/ => non émis: 5: agent
    wp : wpackagist-plugin et wpackagist-theme => pkg:wordpress, un composant par purl sans version, version du disque si présent: 5: agent
    Même paquet Composer dans deux lockfiles à deux versions => deux composants (purl complet, vigie:path): 5: agent
    Document produit => uniquement les champs de la liste blanche, specVersion 1.7, serialNumber UUID v4: 5: agent
    purl.json de F1 rejoué par purl() => tous les vecteurs égaux: 5: agent
  section Edge case
    Dossier d'extension sans Plugin Name, mu-plugin sans Plugin Name => ignorés: 1: agent
    En-tête Version au-delà de 8 Kio => version vide: 1: agent
    Fichier d'en-tête de 50 Mio (créé par le test) => 8 Kio lus, temps borné: 1: agent
    Version piégée 1.0'; system(…) (créée par le test) => version vide, rien d'exécuté: 1: agent
    Version à ~ (1.0~beta) => version vide: 1: agent
    Version de 129 caractères => version vide (jamais tronquée à 128): 1: agent
    config.xml à DOCTYPE, entité, NUL ou UTF-8 invalide => ignoré, version du littéral ou vide, aucune expansion: 1: agent
    Dossier d'extension, de thème ou de module en lien symbolique (même vers l'intérieur, créé par le test) => refusé, skipped compté, complete false: 1: agent
    composer.lock en lien symbolique sortant (créé par le test) => non lu, complete false: 1: agent
    Module PrestaShop au nom contenant un point, slug hors grammaire => écarté, skipped compté, complete false: 1: agent
    Nom Composer de 215 octets (rejeté par strlen, jamais tronqué) ou motif pathologique (créé par le test) => écarté sans regex lente, compté: 1: agent
    composer.lock de 4 Mio + 1 ou JSON invalide ; package-lock.json v1 => aucun paquet, complete false: 1: agent
    Dossier plugins de 501 entrées (créé par le test) => arrêt à 500, complete false: 1: agent
    2 001 composants (créés par le test) => 2 000 gardés, complete false: 1: agent
    Corps au-delà de 512 Kio => composants retirés depuis la fin, complete false, corps ≤ 524 288 octets: 1: agent
    Délai de relevé dépassé (horloge injectée) => complete false: 1: agent
    npm : workspace et extraneous ignorés, devOptional => required, casse gardée: 1: agent
    kind generic => Composer et npm seulement ; wpackagist et prestashop-module restent pkg:composer: 1: agent
    Fixtures => aucun fichier modifié, aucun mtime changé: 1: agent
```

## Tasks to do

1. **Configuration** : `kind` admet `prestashop` (`uploads` par défaut `null`) ; `inventory_config()` sur le modèle de `logs_config()` : clés `enabled` (booléen, obligatoire), `composer`, `npm` (10 chemins relatifs au plus, sans double, par `relative_path`) ; toute autre clé refusée ; absente → désactivé. `Config` reçoit `inventory` et `inventoryEndpoint` (dérivé de `endpoint`, suffixe `/r/v1/report` exigé).
2. **Lecture bornée et motifs sûrs** : `read_head(rootReal, relative, bytes)` via `locate()` ; `list_dir(rootReal, relative)` via `locate_dir()` (qui refuse tout dossier lien symbolique) et `opendir`/`readdir` arrêté à 500 entrées, entrées triées ; chaque sous-dossier repassé par `locate_dir`. **Aucune valeur relevée n'est jamais tronquée** : toute valeur plus longue que sa borne (214 pour un nom, 128 pour une version, 200 pour un slug, 64 pour un module) est **rejetée par `strlen` avant la regex** — version → vide, nom → composant écarté et compté ; seules les **lignes d'en-tête** sont coupées à 256 caractères pour la recherche. Motifs ancrés, quantificateurs possessifs ou bornés ; un `preg_match` qui rend `false` est un rejet compté. `clean_version(raw)` : espaces retirés aux bords, `strlen` > 128 → `''`, puis `^[0-9A-Za-z.+_-]{1,128}+$`, sinon `''`. Une source refusée ou illisible (lien, hors racine, `opendir` ou lecture en échec, lockfile invalide) incrémente `skipped` et met `complete = false`.
3. **En-têtes WordPress** comme `get_file_data` : 8 Kio, `\r` normalisés en `\n`, préfixe `<?php` accepté, ligne `^[ \t\/*#@]*+Name:(.{0,256})$` (multiligne), valeur coupée.
4. **WordPress** (`kind = wordpress`) : cœur par `wordpress_version()` passé par `clean_version` (type `application`, `pkg:wordpress/core/core`) ; `wp-content/plugins/<slug>/` : `<slug>.php` d'abord puis les autres `.php` du premier niveau par nom, 20 au plus, premier qui porte `Plugin Name:` ; `plugins/<fichier>.php` à `Plugin Name:` : extension à fichier unique, slug = nom sans `.php` (limite `hello.php` ≠ `hello-dolly` documentée en phase 3) ; `wp-content/mu-plugins/*.php` de premier niveau **portant `Plugin Name:`** → `vigie:scope = mu` ; `wp-content/themes/<slug>/style.css` (un niveau) portant `Theme Name:` → thème, `Template:` dans la grammaire des slugs → `vigie:parent`. Slugs selon la grammaire commune (`[A-Za-z0-9._-]{1,200}`), tels quels.
5. **PrestaShop** (`kind = prestashop`) : noyau par `app/AppKernel.php` (`const VERSION`) puis `config/settings.inc.php` (`_PS_VERSION_`), 64 Kio, motifs bornés, `clean_version` ; **à l'implémentation, vérifier sur une archive publique de PrestaShop 9 où se trouve la version et compléter l'ordre si besoin**. `modules/<x>/` avec `<x>` dans `[A-Za-z0-9_-]{1,64}` et `<x>.php` présent : version du littéral `/\$this->version\s{0,16}=\s{0,16}['"]([0-9A-Za-z.+_-]{1,128})['"]/` sur 64 Kio ; repli `config.xml` (8 Kio) seulement s'il est UTF-8 valide (`preg_match('//u')`), sans NUL, sans `<!` hors `<![CDATA[`, version par `/<version>\s{0,16}(?:<!\[CDATA\[)?\s{0,16}([0-9A-Za-z.+_-]{1,128})\s{0,16}(?:\]\]>)?\s{0,16}<\/version>/` ; les deux lus et différents → version du littéral et `vigie:config-version`. Aucun analyseur XML.
6. **Composer** : `composer.lock` de la racine puis de `inventory.composer` ; 4 Mio, `json_decode` profondeur 32 ; `packages[]` → `required`, `packages-dev[]` → `dev` (`excluded`) ; nom de plus de 214 octets écarté et compté, sinon mis en minuscules et validé par `^[a-z0-9]++(?:[_.-][a-z0-9]++)*+/[a-z0-9]++(?:(?:[_.]|-{1,2})[a-z0-9]++)*+$`. Correspondances CMS : site `prestashop`, `type` = `prestashop-module` → non émis (le module vient de l'étape 5, nom = `extra.installer-name` sinon partie après `/`, et rien s'il n'est pas dans `modules/`) ; site `wordpress`, `wpackagist-plugin/<slug>` / `wpackagist-theme/<slug>` → `pkg:wordpress/plugin|theme/<slug>` ; site `generic` : aucune correspondance.
7. **npm** : `package-lock.json` de la racine puis de `inventory.npm` ; `lockfileVersion` 2 ou 3 seulement ; `packages` : clé `""`, clés hors `node_modules/` (workspaces), `link: true` et `extraneous: true` ignorées ; nom = champ `name` de l'entrée s'il existe (alias npm : le vrai paquet porte les failles ; même règle que F6, vecteur commun), sinon ce qui suit le dernier `node_modules/`, écarté et compté au-delà de 214 octets, casse gardée, validé par motif possessif selon la définition officielle ; `dev: true` → `dev`, `devOptional: true` → `required`.
8. **Doublons et ordre** : `wordpress`/`prestashop` : un composant par purl sans version, le disque l'emportant ; `composer`/`npm` : un par `(purl complet, vigie:path)`. Ordre de relevé : cœur, extensions, mu, thèmes, noyau PS, modules, Composer, npm ; 2 000 au plus.
9. **purl côté agent** : `purl(ecosystem, name, version)` selon la grammaire commune ; test qui rejoue **`purl.json` de F1** (chemin lu depuis le dépôt) et échoue sur tout écart.
10. **Document** : `collect_inventory(Config, deadline) -> array{components, complete, skipped, stat}` (`stat` : chemins des dossiers listés et fichiers lus, pour la phase 3) ; `build_inventory_body(Config, inventory, seq, now, serial)` : enveloppe et BOM exacts, **seulement les champs de la liste blanche** (jamais `Plugin Name`, auteur, URL ou licence lus dans un en-tête), `metadata.timestamp` = `gmdate('Y-m-d\TH:i:s\Z', now)`, `serialNumber` UUID v4 (`random_bytes`, injectable) ; taille de chaque composant encodé mesurée une fois, retrait depuis la fin tant que l'enveloppe dépasse 524 288 octets, `complete = false`. `inventory_digest(components)` : SHA-256 de la liste triée `(purl, path)` en JSON compact.
11. **Fixtures fictives** et `inventory-expected.json` ; cas hostiles qui ressemblent à du code, fichiers géants, liens symboliques, 501 entrées et 2 001 composants fabriqués par le test dans `tmp_dir()`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `inventory` mal formée (clé inconnue, `enabled` absent ou non booléen, chemin `../`, 11 chemins) → code 2 et message nommant `inventory` ; absente → aucun relevé |
| 2-8 | Chaque purl, version, `scope`, `vigie:scope` et `vigie:config-version` de `inventory-expected.json` est vérifié ; `complete` est faux dans chaque cas hostile et vrai sur les fixtures saines ; un `grep` de l'agent ne trouve ni `include`/`require` d'un chemin du site, ni `eval`, ni `simplexml`, `DOMDocument`, `XMLReader`, `LIBXML_` |
| 2 | Le nom pathologique est rejeté en moins de 50 ms ; une version de 129 caractères donne une version vide ; un nom de 215 octets est écarté et compté, jamais tronqué ; aucun `preg_last_error()` différent de `PREG_NO_ERROR` n'est ignoré |
| 9 | `purl.json` de F1 passe à l'identique côté PHP |
| 10 | Deux relevés du même site donnent le même digest ; le document ne contient que les clés de la liste blanche (comparaison récursive) ; validé une fois avec `cyclonedx-cli validate --input-version v1_7` (ou `bom-1.7.schema.json`) à l'implémentation, résultat consigné dans la PR |
| 11 | `lecture seule : la fixture garde ses fichiers et ses mtime` étendu aux nouvelles fixtures ; `php run.php` passe sous PHP 8.1 (image épinglée du CI) |
