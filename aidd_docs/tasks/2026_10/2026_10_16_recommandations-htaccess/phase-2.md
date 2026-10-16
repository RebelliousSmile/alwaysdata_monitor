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

1. Validation PHP identique à Rust (mêmes vecteurs).
2. Empreinte : refus si le `.htaccess` actuel n'a pas `previous_sha256`.
3. Bac à sable : dossier `.vigie-essai-<aléa>` sous la racine, nouveau `.htaccess` + `index.html` témoin, requête HTTP sur l'URL du site (`config.json` : `url`, nouvelle clé) ; 200 attendu ; suppression garantie (`finally`).
4. Bascule : `.htaccess.vigie-prev`, fichier temporaire + `rename` ; smoke-test de l'accueil (statut identique à celui d'avant) ; échec → retour à `.vigie-prev`, résultat `failed` avec la raison.
5. `htaccess-rollback` : retour à `.vigie-prev` avec smoke-test ; sans copie → `refused`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Un bloc refusé ou une empreinte différente : aucun fichier touché (mtime et contenu identiques) |
| 3 | Un serveur de test qui répond 500 dans le bac à sable : aucune bascule, dossier supprimé |
| 4 | Un smoke-test en échec après bascule : `.htaccess` revenu à l'identique, résultat `failed` |
| 5 | Rollback rend le contenu d'avant la dernière application |
