---
status: pending
---

# Instruction: Analyse → propositions, génération et validation du bloc

## Architecture projection

```txt
.
└── vigie/
    ├── src/
    │   ├── recommend/
    │   │   ├── mod.rs        ✅ Proposal (robots, user-agent, ip), recommend(analysis, site, rdns) -> Vec<Proposal>
    │   │   ├── htaccess.rs   ✅ génération du bloc, validation par liste fermée (partagée avec les tests de l'agent par des vecteurs)
    │   │   └── rdns.rs       ✅ reverse DNS borné (10 IP, 5 s en tout), classe hébergeur ou FAI
    │   ├── capability.rs     ✏️ htaccess-* disponibles ; paramètres typés
    │   ├── command/mod.rs    ✏️ params htaccess-apply {block, previous_sha256}
    │   └── main.rs           ✏️ `site recommend <site>` : propositions ; `--apply` met htaccess-apply en file
    └── tests/
        ├── recommend.rs      ✅ cas de gradation et de protection
        └── fixtures/htaccess/ ✅ golden files (blocs attendus) et vecteurs de validation (acceptés, refusés) pour Rust et PHP
```

## Tasks to do

1. `recommend` : robots qui respectent robots.txt → ligne `User-agent: X` / `Disallow: /` ; robots non protégés qui ne le respectent pas → règle d'UA ; IP élevées, hébergeur vérifié, hors protégées et hors `behind_proxy` → règle d'IP avec `%{TIME}` d'expiration ; rien d'autre.
2. Génération déterministe (ordre stable) ; golden files comparés à l'octet.
3. Validation : formes de ligne fermées ; refus de toute directive dangereuse ; vecteurs `accept/*.txt` et `refuse/*.txt` lus par Rust et par le test PHP.
4. `site recommend` : affiche robots.txt à poser à la main, le bloc, l'empreinte du `.htaccess` de référence ; `--apply` met en file `htaccess-apply` (aperçu d'abord, comme `site command`).

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Googlebot, YandexBot, facebookexternalhit, un navigateur, ChatGPT-User : aucune proposition d'UA ni d'IP ; GPTBot → robots.txt ; Bytespider → UA ; IP élevée sans reverse DNS hébergeur → rien |
| 2 | Golden files identiques |
| 3 | Chaque vecteur `refuse/` (php_value, AddHandler, SetHandler, Include, auto_prepend_file, ligne vide d'espaces bizarres, guillemet non fermé, littéral trop long, `# END vigie` imbriqué) est refusé ; chaque `accept/` passe |
