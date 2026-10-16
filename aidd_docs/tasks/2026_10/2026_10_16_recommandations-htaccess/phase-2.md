---
status: pending
---

# Instruction: Application par l'agent : bac à sable, bascule, retour arrière

## Architecture projection

```txt
.
└── vigie/
    ├── agent/php/
    │   ├── vigie-agent.php   ✏️ htaccess-apply et htaccess-rollback : validation par liste fermée, bac à sable, bascule atomique, smoke-test, retour automatique
    │   └── tests/AgentTest.php ✏️ vecteurs de validation, bac à sable refusé, rollback automatique, empreinte changée
    └── docs/
        ├── htaccess.md       ✅ formes de lignes admises, gradation, TTL, procédure de retour arrière
        ├── protocole-commandes.md ✏️ paramètres et résultats de htaccess-*
        └── decisions.md      ✏️ section #13
```

## Tasks to do

1. Validation PHP identique à Rust (mêmes vecteurs, même corpus d'UA protégés, `%{TIME}` vérifié à l'heure locale de l'agent).
2. Empreintes : refus si le `.htaccess` actuel n'a pas `previous_sha256`, ou si le contenu calculé n'a pas `new_sha256` ; bloc localisé par lignes exactes, bloc `sc_alwaysdata` du module laissé intact.
3. Bac à sable : dossier `vigie-essai-<hex>` (sans point initial) sous la racine, nouveau `.htaccess` + `index.html` témoin, requêtes sur l'URL du site (`config.json` : `url`, nouvelle clé) avec paramètre anti-cache : 200 pour un UA de navigateur et pour Googlebot, 403 pour un UA visé ; suppression garantie (`finally`).
4. Bascule : `.htaccess.vigie-prev` (mode de l'original), `htaccess_pending` dans l'état, compare-and-swap sur `previous_sha256` juste avant `rename` ; smoke-test de l'accueil (anti-cache, navigateur et Googlebot : statut identique à celui d'avant) ; échec → retour à `.vigie-prev` seulement si le fichier a encore `new_sha256`, résultat `failed` avec la raison ; résultat `ok` porte `new_sha256`.
5. Reprise : un `htaccess_pending` trouvé au démarrage d'un passage → smoke-test, retour arrière s'il échoue, avant le retrait.
6. `htaccess-rollback` : retour à `.vigie-prev` (compare-and-swap, smoke-test) ; sans copie → `refused`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Un bloc refusé ou une empreinte différente : aucun fichier touché (mtime et contenu identiques) |
| 3 | Un serveur de test qui répond 500 dans le bac à sable : aucune bascule, dossier supprimé |
| 4 | Un smoke-test en échec après bascule : `.htaccess` revenu à l'identique, résultat `failed` |
| 4bis | Le `.htaccess` modifié par un tiers entre la lecture et la bascule : rien d'écrit, `failed` ; modifié pendant le smoke-test : pas de retour arrière qui l'écrase |
| 5 | Agent interrompu après la bascule (état `htaccess_pending` posé à la main), site en 500 : le passage suivant remet `.vigie-prev` avant tout retrait |
| 6 | Rollback rend le contenu d'avant la dernière application |
