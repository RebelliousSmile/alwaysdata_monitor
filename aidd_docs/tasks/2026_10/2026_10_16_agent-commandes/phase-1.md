---
status: done
---

# Instruction: État sûr, retrait signé, vérification

## Architecture projection

```txt
.
└── vigie/agent/php/
    ├── vigie-agent.php       ✏️ configuration commands, état (state.json, flock), retrait signé, vérification de la réponse
    ├── config.example.json   ✏️ "commands": {"endpoint": …, "pubkey": …}
    └── tests/
        ├── AgentTest.php     ✏️ vecteurs, état, refus
        └── run.php           ✏️ aides (serveur de test qui rejoue des réponses)
```

## Tasks to do

1. Configuration : `commands` facultatif, `{endpoint, pubkey}` seulement ; `endpoint` comme `endpoint` du rapport, `pubkey` 32 octets base64 ; si présent : `config.json` en 0600 et dossier 0700, sinon `UsageError`.
2. État : `load_state`/`save_state` sous `flock(LOCK_EX)` de `state.lock`, JSON strict, écriture par `tempnam` dans le même dossier + `chmod 0600` + `rename` ; un état illisible ou en droits ouverts arrête le retrait (rapport inchangé).
3. Retrait : corps `{v, type: "pull", site, seq, sent_at, nonce, agent, result?}`, `seq` = max(dernier + 1, heure en ms), `nonce` de 24 octets aléatoires en base64url, signature `vigie-pull-v1\n` + corps ; `pull_seq` écrit avant l'envoi.
4. `verify_response($status, $headers, $body, $config, $nonce, $now)` : règles dans l'ordre du contrat, schéma strict des deux niveaux (`json_decode` avec `JSON_THROW_ON_ERROR`, clés exactes), verdicts nommés comme dans les vecteurs.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | État en 0644, dossier en 0755, lien symbolique : refus ; écriture atomique (aucun fichier partiel après une erreur simulée) |
| 3 | Le retrait signé d'un vecteur se vérifie ; sans préfixe, non |
| 4 | Chaque réponse de `commands-vectors.json` reçoit son verdict ; corps vide, JSON tronqué, champ en plus → rejet |
