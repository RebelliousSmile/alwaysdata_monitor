---
status: pending
---

# Instruction: Catalogue des robots, glob et règles

## Architecture projection

```txt
.
└── vigie/
    └── src/
        ├── analysis/
        │   ├── mod.rs        ✅ déclare catalog, glob, rules
        │   ├── catalog.rs    ✅ BotClass, Bot (nom, éditeur, finalité, robots_only, honours_robots, protected), catalogue en OnceLock, classify(user_agent) par correspondance la plus longue
        │   ├── glob.rs       ✅ glob compilé, correspondance par programmation dynamique bornée
        │   └── rules.rs      ✅ Rule déclarative, règles par défaut, validation, compilation
        ├── config.rs         ✏️ [logs] (disable, rules) et [sites.logs] (behind_proxy, exclude, rules)
        └── lib.rs            ✏️ déclare analysis
```

## Tasks to do

1. `BotClass` : `SearchEngine` (les quatre du PHP, bénéfice du doute), `OtherEngine` (Yandex, Baidu, Seznam, Sogou, 360Spider, PetalBot : +20 comme en PHP), `SocialPreview`, `AiTraining`, `AiSearch`, `AiUser`, `Seo`, `Tool`, `Browser`, `Unknown`. Métadonnées d'`AiBotCatalog.php` reprises ; `protected` pour `SearchEngine`, `OtherEngine`, `SocialPreview`, `Browser`, `AiUser`. Bytespider est `AiTraining`, pas un moteur.
2. `Glob` : préfiltre sur les littéraux fixes de tête et de queue ; motif commençant par `/`, 256 caractères, `*` (hors `/`), `**`, `?` ; `/**/` vaut aussi `/` ; table de vérité incluant `/**/x*/y` contre `/x1/z/x2/y` (vrai).
3. `Rule { id, path, methods, statuses, scope, min_count, min_ips, window_secs, severity }` ; par défaut : `spike-404`, `spike-403` (≥ 100 en 10 min par site), `errors-5xx` (≥ 10 en 10 min, critique), `sensitive-path` (`/**/.env`, `/**/.git/**`, `/**/wp-config.php.*`, `/**/*.sql`, `/**/*.bak`, `/**/phpinfo.php`, `/server-status` : information) et `sensitive-path-many` (mêmes motifs, `min_ips` 5 : avertissement), `brute-force` (POST `/wp-login.php`, `/connexion`, `/xmlrpc.php` ≥ 30 en 10 min par IP), `repeated-ip` (≥ 600 en 10 min par IP).
4. Validation : identifiants `[a-z0-9-]` uniques, fenêtre de 60 s à 1 h, seuils bornés, glob valide ; erreur de configuration sinon.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Googlebot → `SearchEngine` ; YandexBot → `OtherEngine` ; « Applebot-Extended » n'est pas lu « Applebot » ; GPTBot → `AiTraining` (OpenAI, respecte robots.txt) ; curl et UA vide → `Tool` |
| 2 | Table de vérité, fuzz du glob (motifs et chemins aléatoires, graine fixe) sans panique et sous 50 ms par correspondance |
| 3-4 | Une règle invalide est une erreur de configuration ; `disable` retire une règle par défaut ; fuzz du chargement des règles |
