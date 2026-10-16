---
status: pending
---

# Instruction: Analyseur, fenêtres, score et constats

## Architecture projection

```txt
.
└── vigie/
    └── src/analysis/
        ├── window.rs         ✅ compteur glissant par clé (horodatages en ms), expiration par rapport à now
        ├── profile.rs        ✅ profil d'une IP sur 24 h : requêtes, statiques, facettes, sans referer, UA (bornés), pic par minute
        ├── score.rs          ✅ score de suspicion porté d'IpSuspicionScorer.php
        └── analyzer.rs       ✅ Analyzer::feed(entries, clock) ; findings(now) -> Vec<Finding>
```

## Tasks to do

1. `Analyzer` par site : règles compilées, catalogue, fenêtres, profils d'IP (10 000 au plus, éviction de la moins récemment vue), budget de 2 s par lot sur l'instant monotone.
2. Chaque entrée : classement du UA (mis en cache, 10 000 UA au plus), toutes les règles, profil de son IP. Entrée sans IP : règles de portée site seulement.
3. `findings(now)` : un constat par (règle, clé) au-dessus du seuil dans sa fenêtre ; `suspicious-ip:<ip>` (avertissement) pour un score ≥ 70, hors classes protégées ; `bots-ai-training` (information) avec les robots vus et leur volume ; `analysis-truncated` si le budget a été atteint.
4. Statiques et facettes comme le module : extensions `.js .css .png .jpg .jpeg .gif .webp .avif .woff .woff2 .svg .ico .map .ttf .eot .otf` ; facette = clé de requête `q`.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1-2 | 1 000 000 d'entrées aléatoires (graine fixe) : mémoire bornée par les plafonds, aucune panique |
| 3 | Avec une `FakeClock` : 99 404 en 10 min → rien, 100 → `spike-404` ; 11 min plus tard → résolu. Un scraper HTML seul, facettes, UA d'outil, hébergeur inconnu → score ≥ 70 ; Googlebot → jamais `suspicious-ip` |
| 4 | Les cas du test PHP `IpSuspicionScorerTest.php` portés donnent les mêmes scores (sans reverse DNS) |
