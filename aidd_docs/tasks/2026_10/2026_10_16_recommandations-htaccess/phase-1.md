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
    │   ├── command/mod.rs    ✏️ params htaccess-apply {block, previous_sha256, new_sha256} ; htaccess-rollback {expected_current_sha256, prev_sha256}
    │   └── main.rs           ✏️ `site recommend <site>` : propositions ; `--apply` met htaccess-apply en file
    └── tests/
        ├── recommend.rs      ✅ cas de gradation et de protection
        └── fixtures/htaccess/ ✅ golden files (blocs attendus), protected-uas.txt, vectors.json (vecteurs et fuzz différentiel, verdicts attendus) pour Rust et PHP
```

## Tasks to do

1. `recommend` : robots qui respectent robots.txt → ligne `User-agent: X` / `Disallow: /` ; robots non protégés qui ne le respectent pas → règle d'UA (30 j) ; IP élevées, hébergeur vérifié, hors protégées et hors `behind_proxy` → règle d'IP (24 h) ; sans fuseau du site, ni UA ni IP ; rien d'autre.
2. Génération déterministe (ordre stable, IP canoniques, littéraux échappés) ; golden files comparés à l'octet ; `%{TIME}` dans le fuseau du site.
3. Validation par groupes (plan, « Decisions ») avec `now` injecté : bornes de `%{TIME}` selon la sorte du groupe, corpus d'UA protégés, CR/tabulation/NUL/continuation refusés ; `vectors.json` généré par un test Rust (`VIGIE_WRITE_VECTORS=1`, comme `commands-vectors.json`), dont un fuzz différentiel à graine fixe (lignes mutées : un octet changé, inséré, supprimé).
3bis. Protections : IP protégées (veilleur, site, `protect_ips`), UA de Vigie et `/vigie-essai-*` exclus, littéral = jeton du catalogue, pas de règle d'UA pour `Unknown`, jetons génériques refusés.
3ter. Intégrité : `compare()` admet les empreintes attendues d'une commande `htaccess-*` `served` ou `unknown` ; la référence suit `current_sha256` seulement s'il en fait partie.
4. `site recommend` : bloc en place = dernier `htaccess-apply` `done` dont `current_sha256` égale l'empreinte du dernier rapport ; en reprend les groupes valides, retire les expirés, affiche le diff ; sans correspondance, `--apply` exige `--replace` ; affiche robots.txt à poser à la main, le bloc, `previous_sha256` (dernier rapport) et `new_sha256` ; `--apply` met en file `htaccess-apply` (aperçu d'abord, comme `site command`) ; à la réussite, la référence d'intégrité de `.htaccess` passe à `new_sha256`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Googlebot, YandexBot, facebookexternalhit, un navigateur, ChatGPT-User : aucune proposition d'UA ni d'IP ; GPTBot → robots.txt ; Bytespider → UA ; IP élevée sans reverse DNS hébergeur → rien |
| 2 | Golden files identiques |
| 3 | Refusés : php_value, AddHandler, SetHandler, Include, auto_prepend_file, ligne d'espaces bizarres, guillemet non fermé, littéral trop long, `# END vigie` imbriqué, ligne finissant par `\\`, CR, tabulation, `.` non échappé, groupe sans `%{TIME}`, `[OR]` sur la dernière condition, `%{TIME}` passé ou au-delà de la borne, littéral touchant « Googlebot » ou un navigateur du corpus ; acceptés : chaque bloc golden |
| 3bis | Le trafic du veilleur (UA `vigie/x`, IP du veilleur) et un UA de webhook : aucune proposition ; un UA `Unknown` : pas de règle d'UA |
| 4bis | Bloc en place connu : groupes valides repris, expirés retirés ; `.htaccess` modifié hors de Vigie : `--apply` sans `--replace` refusé |
| 4 | Rapport portant `new_sha256` envoyé avant le résultat `ok` : `agent:integrity/modified:.htaccess` ne s'ouvre pas ; reprise et retour arrière idem ; une empreinte hors des attendues l'ouvre |
