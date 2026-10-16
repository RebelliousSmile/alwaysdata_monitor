---
status: pending
---

# Instruction: Vue des logs et listes paginées

## Architecture projection

```txt
.
└── vigie/app/
    ├── src-tauri/src/client.rs ✏️ logs, logs/ips, pagination, 429
    └── src/
        ├── views/Trafic.vue  ✅ robots, IP, charge, règles (maquette Trafic)
        ├── router/index.ts   ✏️ Trafic alimenté ; autres écrans « pas encore disponible » inchangés
        └── views/*.vue       ✏️ « Afficher plus » des incidents
```

## Tasks to do

1. Client : routes logs, `cursor`, erreur 429 typée.
2. Vue Trafic ; site sans source → état « pas encore disponible ».
3. Pagination des incidents clos.
4. Version 0.2.0, CHANGELOG de la console.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Test de contrat du client contre le routeur du veilleur en processus (existant) étendu aux routes logs et à la pagination |
| 2 | Un UA `<img src=x onerror=…>` s'affiche en texte ; site sans source : écran « pas encore disponible » |
| 3 | 120 incidents : trois pages, sans doublon |
