---
status: pending
---

# Instruction: Catalogue des robots et règles déclaratives

## Architecture projection

```txt
.
└── vigie/
    └── src/
        ├── analysis/
        │   ├── mod.rs        ✅ déclare catalog, glob, rules
        │   ├── catalog.rs    ✅ classes de robots, catalogue en OnceLock, classify(user_agent)
        │   ├── glob.rs       ✅ glob compilé : *, **, ?, littéraux ; pas de regex
        │   └── rules.rs      ✅ Rule (déclarative), règles par défaut, validation, compilation
        ├── config.rs         ✏️ section [logs] facultative : rules, disable
        └── lib.rs            ✏️ déclare analysis
```

## Tasks to do

1. `BotClass` : `SearchEngine`, `SocialPreview`, `AiTraining`, `AiSearch`, `AiUser`, `Seo`, `Tool` (curl, python, wget…, UA vide), `Browser`, `Unknown` ; `protected()` vrai pour `SearchEngine`, `SocialPreview`, `Browser`. Catalogue repris de `AiBotCatalog.php`, `CrawlerAnalyserService.php` et `IpSuspicionScorer.php` ; ordre : moteurs, aperçus sociaux, IA, SEO, outils, navigateurs.
2. `Glob::compile(pattern)` : chemin commençant par `/`, 256 caractères au plus, `*` (hors `/`), `**` (tout), `?` ; correspondance sans backtracking exponentiel (algorithme glouton à deux pointeurs, `**` traité comme `*` traversant `/`).
3. `Rule { id, path: Option<Glob>, methods, statuses: Vec<RangeInclusive<u16>>, scope: Ip|Site, min_count, window_secs, severity, key }` ; règles par défaut : `spike-404` (≥ 100 404 en 10 min par site), `spike-403` (≥ 100 en 10 min), `errors-500` (≥ 10 5xx en 10 min, critique), `sensitive-path` (`/.env`, `/.git/**`, `/**/wp-config.php.*`, `/**/*.sql`, `/**/*.bak`, `/**/phpinfo.php`, `/server-status` ; ≥ 1, information par IP, avertissement à partir de 5 IP), `repeated-ip` (≥ 600 requêtes en 10 min par IP).
4. `[logs]` de `config.toml` : `disable = ["…"]`, `[[logs.rules]]` en plus ; identifiants uniques `[a-z0-9-]` ; seuils et fenêtres bornés (fenêtre 60 s à 1 j) ; `deny_unknown_fields`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Googlebot, Bingbot, facebookexternalhit, Firefox → classes protégées ; GPTBot → `AiTraining` ; curl et UA vide → `Tool` ; casse ignorée |
| 2 | Table de vérité des globs ; un motif `*a*a*a*…` contre 2 Kio de `a` finit en moins de 50 ms |
| 3-4 | Une règle invalide (glob, fenêtre, identifiant en double) est une erreur de configuration ; `disable` retire une règle par défaut |
