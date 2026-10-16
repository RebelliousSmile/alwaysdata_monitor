---
status: pending
---

# Instruction: Application par l'agent : bac à sable, bascule, retour arrière

## Architecture projection

```txt
.
└── vigie/
    ├── agent/php/
    │   ├── vigie-agent.php   ✏️ htaccess-apply et htaccess-rollback : validation par liste fermée, bac à sable différentiel, bascule atomique, smoke-test, retour automatique, corpus en constante
    │   └── tests/AgentTest.php ✏️ vecteurs de validation, bac à sable refusé, rollback automatique, empreinte changée
    └── docs/
        ├── htaccess.md       ✅ formes de lignes admises, gradation, TTL, procédure de retour arrière
        ├── protocole-commandes.md ✏️ paramètres et résultats de htaccess-*
        └── decisions.md      ✏️ section #13
```

## Tasks to do

1. Validation PHP identique à Rust (mêmes vecteurs, même corpus d'UA protégés, `%{TIME}` vérifié à l'heure locale de l'agent).
2. Empreintes : refus si le `.htaccess` actuel n'a pas `previous_sha256`, ou si le contenu calculé n'a pas `new_sha256` ; bloc localisé par lignes exactes, bloc `sc_alwaysdata` du module laissé intact.
3. Bac à sable différentiel (plan) : dossiers `vigie-essai-<hex>-a` / `-b`, pages témoins à nonce, aucune redirection suivie, statuts égaux pour les UA protégés, 403 dans `-b` seulement pour chaque groupe d'UA, sondes d'horloge Apache ; `config.json` : `url` (https) et `tz` ; 5 s par requête, 30 s en tout ; suppression garantie (`finally`).
4. Bascule : compare-and-swap sur `previous_sha256`, puis copie privée `htaccess.prev` (dossier de l'agent, 0700) depuis les octets vérifiés, `htaccess_pending {command_id, prev_sha256, new_sha256, statuts_avant}`, puis `rename` ; smoke-test de l'accueil (anti-cache, navigateur et Googlebot : statut identique à celui d'avant) ; échec → retour à la copie privée seulement si le fichier a encore `new_sha256`, résultat `failed` avec la raison ; tout résultat porte `current_sha256`.
5. Reprise : un `htaccess_pending` trouvé en tête du rappel de `with_state` (avant `running`) → smoke-test contre `statuts_avant`, retour arrière s'il échoue ; `load_state` migre l'état 0.2.0 (`htaccess_pending: null`).
6. `htaccess-rollback {expected_current_sha256, prev_sha256}` : copie privée vérifiée, compare-and-swap, smoke-test ; sans copie ou empreinte différente → `refused`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | Un bloc refusé ou une empreinte différente : aucun fichier touché (mtime et contenu identiques) |
| 3 | Un serveur de test qui répond 500 dans le bac à sable : aucune bascule, dossiers supprimés ; 200 sans nonce → « non représentatif » ; horloge du serveur de test décalée d'une heure → refus « horloge Apache » |
| 3bis | Un `state.json` de l'agent 0.2.0 se charge et se migre |
| 4 | Un smoke-test en échec après bascule : `.htaccess` revenu à l'identique, résultat `failed` |
| 4bis | Le `.htaccess` modifié par un tiers entre la lecture et la bascule : rien d'écrit, `failed` ; modifié pendant le smoke-test : pas de retour arrière qui l'écrase |
| 5 | Agent interrompu après la bascule (état `htaccess_pending` posé à la main), site en 500 : le passage suivant remet `.vigie-prev` avant tout retrait |
| 6 | Rollback rend le contenu d'avant la dernière application |
