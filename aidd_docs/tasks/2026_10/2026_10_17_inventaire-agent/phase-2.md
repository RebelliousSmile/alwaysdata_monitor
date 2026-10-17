---
status: pending
---

# Instruction: Relevé des composants par l'agent PHP (sans réseau)

## Architecture projection

```txt
.
└── vigie/agent/php/
    ├── vigie-agent.php                 ✏️ section « Inventaire » : configuration, relevés WordPress / PrestaShop / Composer / npm, purl, CycloneDX, bornes ; kind prestashop
    ├── config.example.json             ✏️ section inventory d'exemple ({"enabled": true})
    └── tests/
        ├── AgentTest.php               ✏️ tests du relevé : chaque purl attendu, bornes, fichiers hostiles, lecture seule
        └── fixtures/
            ├── wp-inventory/           ✅ site A fictif : wp-includes/version.php, plugins (dossier, fichier unique, sans en-tête), mu-plugins, thèmes parent et enfant, composer.lock (packages + packages-dev, wpackagist-plugin présent aussi sur disque, wpackagist-theme seul), package-lock.json v3 (paquet à scope et à majuscules)
            ├── ps16-inventory/         ✅ site B fictif PrestaShop 1.6 : config/settings.inc.php, modules avec config.xml et un sans
            ├── ps8-inventory/          ✅ site B fictif PrestaShop 8 : app/AppKernel.php, modules, composer.lock dont un prestashop-module à version d'installation périmée
            ├── ps-hostile/             ✅ config.xml à DOCTYPE et entités (texte inerte), config.xml mal formé
            └── inventory-expected.json ✅ purl, version, scope, vigie:scope, vigie:path attendus par fixture
```

## Test Scope

```mermaid
journey
  section Happy path
    wp-inventory => cœur, extensions, extension à fichier unique, mu-plugin, thèmes parent et enfant, Composer, npm : liste égale à inventory-expected.json: 5: agent
    ps16-inventory et ps8-inventory => noyau et modules, purl pkg:prestashop: 5: agent
    ps8 : prestashop-module du composer.lock => émis une fois en pkg:prestashop/module à la version de config.xml, jamais en pkg:composer: 5: agent
    wp : wpackagist-plugin/wpackagist-theme => pkg:wordpress, un seul composant par purl, version du disque si présent: 5: agent
    Document produit => champs du sous-ensemble CycloneDX 1.7 seulement, specVersion 1.7, serialNumber UUID v4: 5: agent
  section Edge case
    Dossier d'extension sans Plugin Name => ignoré: 1: agent
    En-tête Version au-delà de 8 Kio => version vide: 1: agent
    Fichier d'en-tête de 50 Mio (créé par le test) => 8 Kio lus, temps borné: 1: agent
    Version piégée 1.0'; system(…) (créée par le test) => version vide, rien d'exécuté: 1: agent
    config.xml à entités externes ou DOCTYPE => non analysé, repli sur $this->version: 1: agent
    Lien symbolique sortant de root (plugin, thème, composer.lock, créé par le test) => non suivi, composant absent, skipped compté: 1: agent
    Nom de dossier hors [A-Za-z0-9._-] => écarté, skipped compté: 1: agent
    composer.lock de 4 Mio + 1 ou JSON invalide => aucun paquet, complete false: 1: agent
    package-lock.json v1 => aucun paquet, sans erreur: 1: agent
    2 001 composants (créés par le test) => 2 000 gardés, complete false: 1: agent
    Corps au-delà de 512 Kio => composants retirés depuis la fin, complete false, corps ≤ 524 288 octets: 1: agent
    Délai de relevé dépassé (horloge injectée) => complete false: 1: agent
    kind generic => ni cœur ni extension, Composer et npm seulement ; wpackagist et prestashop-module restent pkg:composer: 1: agent
    prestashop-module du lockfile absent de modules/ => non émis: 1: agent
    Nom npm à majuscules => casse gardée dans name et purl: 1: agent
    Fixtures => aucun fichier modifié, aucun mtime changé: 1: agent
```

## Tasks to do

1. **Configuration** : `kind` admet `prestashop` (défaut d'`uploads` : `null` pour `prestashop`) ; `inventory_config()` sur le modèle de `logs_config()` : objet aux clés `enabled` (booléen, obligatoire), `composer`, `npm` (listes de 10 chemins relatifs au plus, sans double, par `relative_path`), toute autre clé refusée ; absente → désactivé. `Config` reçoit `inventory` (`?array{composer: list, npm: list}`) et `inventoryEndpoint` (dérivé de `endpoint` : suffixe `/r/v1/report` exigé, comme pour les logs).
2. **Lecture bornée commune** : `read_head(rootReal, relative, bytes)` via `locate()` (aucun lien hors racine) et `file_get_contents(…, 0, bytes)` ; `header_value(text, name)` sur le modèle de `get_file_data` de WordPress (`/^[ \t\/*#@]*Name:(.{0,256})$/mi`, une seule ligne) ; `clean_version(raw)` : valeur coupée, `^[0-9A-Za-z.+_~-]{1,64}$` sinon `''` ; `list_dir(rootReal, relative, max)` : entrées triées, 500 au plus, liens suivis seulement si leur cible reste dans la racine (`locate_dir`), segments validés.
3. **WordPress** (`kind = wordpress`) : cœur par `wordpress_version()` existant (type `application`, `pkg:wordpress/core/core`) ; `wp-content/plugins/<slug>/` : `<slug>.php` d'abord puis les autres `.php` du premier niveau par ordre de nom, 20 au plus, premier fichier qui porte `Plugin Name:` → composant (slug tel quel dans le purl) ; `plugins/<fichier>.php` : extension à fichier unique, slug = nom sans `.php` ; `wp-content/mu-plugins/*.php` de premier niveau : `vigie:scope = mu`, version de l'en-tête si présente, sinon vide ; `wp-content/themes/<slug>/style.css` portant `Theme Name:` → `pkg:wordpress/theme/<slug>`, `Template:` valide → `vigie:parent`.
4. **PrestaShop** (`kind = prestashop`) : noyau par `app/AppKernel.php` (`/const\s+VERSION\s*=\s*['"]([^'"]{1,64})['"]\s*;/`) puis `config/settings.inc.php` (`/define\(\s*['"]_PS_VERSION_['"]\s*,\s*['"]([^'"]{1,64})['"]\s*\)/`), sur 64 Kio, version passée par `clean_version` ; **à l'implémentation, vérifier sur une archive publique de PrestaShop 9 où se trouve la version et compléter l'ordre si besoin** ; `modules/<nom>/` avec `<nom>.php` : `config.xml` (8 Kio, refus si `<!DOCTYPE`/`<!ENTITY`, `simplexml_load_string` avec `LIBXML_NONET | LIBXML_NOCDATA`, `libxml_use_internal_errors(true)`, `<version>` lu), sinon `$this->version = '…'` sur 32 Kio de `<nom>.php`.
5. **Composer** : `composer.lock` de la racine puis des chemins `inventory.composer` ; 4 Mio au plus, `json_decode` profondeur 32 ; `packages[]` → `vigie:scope = required`, `packages-dev[]` → `dev` (CycloneDX `excluded`) ; `name` `vendor/nom` validé (`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$` après mise en minuscules), `version` brute nettoyée ; `vigie:path` = chemin du lockfile. **Correspondances CMS** : site `prestashop`, `type` = `prestashop-module` → non émis en Composer ; le module `<x>` (`extra.installer-name`, sinon partie après `/`) vient du relevé de `modules/<x>/` (version de `config.xml`), et rien n'est émis s'il n'y est pas ; site `wordpress`, `wpackagist-plugin/<slug>` → `pkg:wordpress/plugin/<slug>`, `wpackagist-theme/<slug>` → `pkg:wordpress/theme/<slug>` (version du lockfile). Puis **un composant par purl sans version**, le relevé sur disque l'emportant (ordre de priorité fixe, testé).
6. **npm** : `package-lock.json` de la racine puis des chemins `inventory.npm` ; `lockfileVersion` 2 ou 3 seulement ; `packages` : clé `""` ignorée, entrées `link: true` ignorées, nom = ce qui suit le dernier `node_modules/` (ou le champ `name` s'il est présent et valide), `dev: true` → `dev` ; nom npm validé sans changer la casse (`^(@[A-Za-z0-9-~][A-Za-z0-9-._~]*/)?[A-Za-z0-9-~][A-Za-z0-9-._~]*$`, 214 au plus).
7. **purl côté agent** : `purl(ecosystem, name, version)` avec le même encodage que `inventory/purl.rs` (phase 1 : minuscules pour Composer seulement) ; vecteurs partagés en phase 3.
8. **Document** : `collect_inventory(Config, deadline) -> array{components, complete, skipped}` dans l'ordre cœur, extensions, mu, thèmes, noyau PS, modules, Composer, npm ; 2 000 au plus ; `build_inventory_body(Config, inventory, seq, now, serial)` : enveloppe et BOM exacts, **uniquement les champs de la liste blanche** (jamais `authors`, `supplier`, `licenses`, ni le `Plugin Name`, l'auteur ou l'URL lus dans un en-tête) (`JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`), `metadata.timestamp` = `gmdate('Y-m-d\TH:i:s\Z', now)`, `serialNumber` = UUID v4 de `random_bytes` (injectable pour les fixtures) ; retrait depuis la fin tant que le corps dépasse 524 288 octets, `complete = false`. `inventory_digest(components)` : SHA-256 de la liste triée `(purl, path)` en JSON compact, sans `serialNumber` ni `timestamp`.
9. **Fixtures fictives** et `inventory-expected.json` ; les cas hostiles qui ressemblent à du code dangereux, les fichiers géants, les liens symboliques et les 2 001 composants sont fabriqués par le test dans `tmp_dir()`, jamais versionnés.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | `inventory` mal formée (clé inconnue, `enabled` absent ou non booléen, chemin `../`, 11 chemins) → code 2 et message nommant `inventory` ; absente → aucun relevé |
| 2-6 | Chaque purl, version, `scope` et `vigie:scope` de `inventory-expected.json` est vérifié ; un `grep` du code de l'agent ne trouve ni `include`/`require` de chemin du site, ni `eval`, ni `LIBXML_NOENT`, ni `LIBXML_DTDLOAD` |
| 4 | Le `config.xml` à entités ne fait lire aucun fichier (sentinelle hors racine jamais ouverte, vérifiée par `fileatime` ou par un flux enregistreur) et ne déclenche aucune expansion |
| 8 | Deux relevés successifs du même site donnent le même digest ; le document ne contient que les clés du sous-ensemble (comparaison récursive des noms de clés) ; il est validé une fois avec `cyclonedx-cli validate --input-version v1_7` (ou le schéma `bom-1.7.schema.json`) à l'implémentation, résultat consigné dans la PR |
| 9 | `lecture seule : la fixture garde ses fichiers et ses mtime` étendu aux nouvelles fixtures ; `php run.php` passe sous PHP 8.1 (image épinglée du CI) |
