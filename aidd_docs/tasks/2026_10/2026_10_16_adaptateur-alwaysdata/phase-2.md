---
status: pending
---

# Instruction: Lecture différentielle par l'agent PHP

## Architecture projection

```txt
.
└── vigie/agent/php/
    ├── vigie-agent.php       ✏️ section logs : configuration, état, lecture, coupe, filtre d'hôtes, lots, envoi
    ├── config.example.json   ✏️ "logs": {"dir": …, "hosts": […]}
    └── tests/
        ├── run.php           ✏️ cas des logs
        └── fixtures générées par le test (gzencode), hôtes *.example.org, IP RFC 5737/3849 : aucun binaire commité
```

## Tasks to do

1. Configuration : `logs.dir` absolu (lu sans suivre de lien hors de lui), `logs.hosts` (1 à 20 hôtes), facultative ; sans elle, rien ne change.
2. État `logs.json` dans le dossier d'état de l'agent (#6 : 0700, fichier 0600, écriture atomique par renommage), verrou `logs.lock` en `LOCK_NB` : `{seq, file, gen, offset, inode, head_sha256, pending}`.
3. Lecture depuis `offset` par `fgets($h, 16385)` (suite jetée jusqu'au `\n`), lignes entières seulement dans un fichier ouvert (une ligne finale incomplète part telle quelle dans un fichier clos), filtre par hôte (premier jeton, minuscules, sans port ; sans hôte → écartée), lots de 44 Kio et corps ≤ 65 536 octets, 20 lots et 20 s au plus.
4. Fichiers : liste des dossiers de l'année courante et précédente, ordre des noms, 30 jours au plus ; fichier clos (`.gz` seul, ou plus récent présent depuis 1 h) → fini puis suivant ; introuvable → suivant, `skipped_files` ; remplacé (taille, inode, empreinte des 256 premiers octets) → `gen + 1`, offset 0. Un `.gz` ouvert une fois par passage.
5. Avant l'envoi, `pending` écrit ; au passage suivant, la plage `pending` est renvoyée à l'identique d'abord ; après un 204, position avancée et `pending` effacé ; au premier refus, arrêt du passage. Repli `pending_new_secret` comme `send_report`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 2 | L'état n'est jamais écrit hors du dossier d'état, ni lisible par d'autres |
| 3-4 | Les lignes d'un autre hôte ne partent pas ; la fin du `.gz` de la veille part avant le jour ; une ligne de 100 Kio part coupée à 16 Kio ; trou de 3 jours : les 3 fichiers partent dans l'ordre ; fichier de position purgé : passage au suivant ; 31 décembre → 1er janvier ; fichier remplacé : `gen` suivante |
| 5 | Réponse perdue (serveur de test qui coupe) puis fichier qui grandit : le passage suivant renvoie exactement la plage `pending` (vérifié côté PHP) ; la déduplication est vérifiée en Rust et dans `agent_e2e.rs` |
