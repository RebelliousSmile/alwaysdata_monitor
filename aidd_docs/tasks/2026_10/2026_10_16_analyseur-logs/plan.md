---
objective: "Un analyseur unique, sans code propre à une source, transforme des Entry en constats déterministes : robots classés, score de suspicion par IP, pics 403/404/500, chemins sensibles, charge, à partir de règles purement déclaratives et d'une horloge injectable, et partage entre sites les signatures de robots nuisibles."
status: pending
issue_number: 8
---

# Plan: Analyseur de logs config-driven

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Remplacer à terme la logique du module PrestaShop (classement des robots, score de suspicion, erreurs 500, charge) par un analyseur du veilleur, invariant quelle que soit la source |
| **Source** | Issue GitHub #8 ; contrat `vigie/docs/logs.md` (#7) ; `src/Service/IpSuspicionScorer.php`, `AiBotCatalog.php`, `CrawlerAnalyserService.php`, `HttpLogParserService.php` |

## Phases

| #   | Phase                                        | File                         |
| --- | -------------------------------------------- | ---------------------------- |
| 1   | Catalogue des robots et règles déclaratives  | [`phase-1.md`](./phase-1.md) |
| 2   | Analyseur, fenêtres, score et constats       | [`phase-2.md`](./phase-2.md) |
| 3   | Signatures partagées et branchement à `tick` | [`phase-3.md`](./phase-3.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Règles purement déclaratives en TOML (`[[logs.rules]]` de `config.toml`) : glob de chemin, méthodes, statuts (liste ou plage), portée (`ip` ou `site`), seuil, fenêtre, gravité, clé. Aucune expression ni regex fournie par la configuration. Des règles par défaut, codées, couvrent les constats de l'issue ; la configuration peut en désactiver ou en ajouter | Une mini-langue d'interprétation deviendrait une surface d'attaque et un piège de maintenance ; le glob (`*`, `**`, `?`) suffit aux chemins sensibles |
| Ordre : toutes les règles sont évaluées pour chaque entrée, dans l'ordre déclaré, et chacune compte de son côté ; seul le classement des robots est « première correspondance gagne », dans l'ordre du catalogue (moteurs de recherche et aperçus sociaux d'abord) | Une règle est un compteur, pas une classe : un 404 sur `/.env` doit nourrir le pic de 404 et le chemin sensible. Le classement, lui, doit rendre une seule classe, et la plus protectrice d'abord |
| Matchers compilés une fois : catalogue en `OnceLock`, globs compilés au chargement de la configuration (erreur de configuration si invalides) ; correspondance du catalogue par sous-chaîne insensible à la casse | Exigence de l'issue ; pas de dépendance `regex` |
| Fenêtres sur l'heure des entrées (`timestamp_ms`), expirées par rapport à l'horloge injectée (`Clock`, #9) ; compteurs bornés en mémoire (IP suivies plafonnées, éviction des plus anciennes) ; budget de temps par lot mesuré sur l'instant monotone de la `Clock`, au-delà le lot s'arrête et le constat `analysis-truncated` le dit | Fenêtres testables à heure fixe ; un lot hostile ne doit ni saturer la mémoire ni bloquer `tick` |
| Score de suspicion porté du module PHP, mêmes poids et mêmes seuils (élevé ≥ 70, moyen ≥ 40), sans reverse DNS en V1 (réseau « inconnu ») : un robot qui se déclare moteur de recherche reçoit le bénéfice du doute, comme le module quand le reverse DNS n'est pas résolu | Le veilleur ne fait pas de résolution DNS par IP à chaque passage ; le jamais-bloquer-un-moteur prime |
| Jamais de blocage proposé pour un moteur de recherche, un navigateur ou un aperçu de réseau social : l'analyseur marque ces classes `protected`, et #13 ne propose rien pour elles | Garde-fou du brainstorm, repris de l'issue #13 |
| L'IP vient seulement de `Entry.ip` (champ client) : aucun en-tête n'est lu, l'analyseur ne connaît pas `X-Forwarded-For` | Contrat de #7 |
| Constats sous le contrôle `logs` dans le cycle des incidents existant (`reconcile`) ; clés stables sans heure ni compte (`spike-404:site`, `sensitive-path:/.env`, `suspicious-ip:192.0.2.1`) ; le détail porte les chiffres | Mêmes règles que les constats d'agent (`protocole-agent.md`) |
| Multitenant : une IP ou une signature de user-agent jugée nuisible (score élevé) sur un site est notée dans une table partagée, 30 jours au plus ; sur les autres sites, elle ajoute 15 points et la mention « vue nuisible sur un autre site », sans ouvrir d'incident à elle seule | « Un robot nuisible repéré sur un site est connu de tous les autres » ; 30 jours comme la conservation RGPD |
| Le branchement à `tick` lit les entrées par un `LogSource` ; tant que #1 n'a pas livré l'adaptateur Alwaysdata, aucun site n'a de source et l'analyse ne tourne pas | L'analyseur ne dépend que du contrat de #7 |
