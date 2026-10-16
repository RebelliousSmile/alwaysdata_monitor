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
        └── fixtures/logs/    ✅ arborescence admin/logs/http/<année>/ avec un .log du jour et un .log.gz de la veille
```

## Tasks to do

1. Configuration : `logs.dir` absolu (lu sans suivre de lien hors de lui), `logs.hosts` (1 à 20 hôtes), facultative ; sans elle, rien ne change.
2. État `logs.json` dans le dossier d'état de l'agent (#6 : 0700, fichier 0600, `flock`, écriture atomique par renommage) : `{file, offset}`.
3. Lecture depuis `offset` par blocs, lignes entières seulement (une ligne sans fin de ligne attend le passage suivant), coupe à 16 Kio, filtre par hôte (premier jeton, minuscules, sans port), lots de 48 Kio, 20 lots et 20 s au plus.
4. Rotation : fichier de la position différent du fichier du jour → le finir (`.log`, sinon `.log.gz` par `gzopen`, en sautant `offset` octets), puis passer au jour ; taille inférieure à la position → `restarted`, offset 0.
5. Envoi de chaque lot ; position avancée et écrite après chaque 204 seulement ; au premier refus, arrêt du passage.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 2 | L'état n'est jamais écrit hors du dossier d'état, ni lisible par d'autres |
| 3-4 | Sur la fixture : les lignes d'un autre hôte ne partent pas ; la fin du `.gz` de la veille part avant le jour ; une ligne de 100 Kio part coupée à 16 Kio |
| 5 | Une réponse perdue (serveur de test qui coupe) : le lot est renvoyé au passage suivant, le veilleur ne le compte qu'une fois |
