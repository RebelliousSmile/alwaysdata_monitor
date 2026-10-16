---
status: pending
---

# Instruction: Repli incrémental : agrégats, profils, score, charge

## Architecture projection

```txt
.
└── vigie/
    ├── migrations/000N.sql   ✅ log_buckets (site, rule, key, minute, count, ips plafonnées), log_profiles (site, ip, hour, compteurs, uas JSON, class ; index sur le compte), log_bots (site, hour, bot, count), log_load (site, hour, requests, refused, service_us, facets_us, bots_us), log_cursors (site, cursor, reference_ms)
    └── src/analysis/
        ├── fold.rs           ✅ replie un lot d'Entry dans les agrégats d'un site (en mémoire le temps du lot, écrits avec le curseur)
        ├── profile.rs        ✅ profil d'IP glissant sur 24 h (tranches horaires) : requêtes, statiques, facettes, pages sans referer, UA (20 au plus), pic par minute, classe du premier robot
        ├── score.rs          ✅ score porté d'IpSuspicionScorer.php
        └── load.rs           ✅ charge par heure
```

## Tasks to do

1. `fold(batch, aggregates)` : pour chaque entrée (chemins exclus ignorés ; `behind_proxy` → pas de portée IP ni de profil) : classement de l'UA (cache), toutes les règles, profil de son IP, robots, charge. Statiques : liste de `HttpLogParserService.php`, insensible à la casse ; facette : clé de requête `q` ; pages sans referer : pages non statiques seulement.
2. Lots de 500 repliés entiers ; budget vérifié entre deux lots. Plafonds : Space-Saving pour les profils et les clés de portée `ip`, compte de classement et erreur séparés des compteurs observés, score sur les seuls compteurs observés et seulement si l'erreur < requêtes observées / 10 ; le compte de classement est la somme des tranches vivantes (24 h) plus l'erreur héritée, bornée par cette somme : il baisse quand une tranche sort de la fenêtre ; seaux de portée `ip` gardés fenêtre maximale + `agent_silence` ; IP distinctes d'un seau plafonnées au plus grand `min_ips` ; seules les lignes touchées sont écrites.
3. Référence = min(dernière `timestamp_ms`, now) ; seaux de portée site de plus de 24 h et profils de plus de 48 h purgés.
4. Score : poids et seuils du PHP ; un UA signé ailleurs ajoute 15 points hors du score propre.

## Test acceptance criteria

| Task | Acceptance criteria |
| ---- | ------------------- |
| 1 | Les cas de `tests/Service/IpSuspicionScorerTest.php` portés donnent les mêmes scores ; un scraper de facettes à UA Firefox est `élevé` |
| 2 | Une IP admise après éviction n'a ni « aucune ressource statique » ni part faussée ; 50 000 IP distinctes en un jour : 10 000 profils au plus, et toute IP au-dessus de N/10 000 requêtes est gardée (garantie de Space-Saving) ; 1 000 000 d'entrées d'une seule IP : mémoire et lignes bornées |
| 3 | Un scraper actif de 23 h à 1 h garde son score à minuit ; une entrée datée à now + 20 h ne déplace pas la référence au-delà de now ; 100 404 arrivés 15 min après leur heure → `spike-404` ; 99 → rien |
| 2bis | Requêtes à chemins de 2 Kio contre les motifs par défaut : un lot de 500 en moins de 100 ms en release |
