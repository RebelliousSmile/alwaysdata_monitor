---
objective: "À partir de la dernière analyse d'un site (#8), Vigie propose des actions graduées (robots.txt, puis user-agent, puis IP à durée limitée), jamais contre un moteur, un navigateur ou un aperçu social ; une proposition validée par l'exploitant part par le canal de commandes (#10) sous forme d'un bloc `# BEGIN vigie` que l'agent revalide par sa propre liste fermée, essaie en bac à sable, bascule atomiquement avec copie précédente, et défait seul si le site ne répond plus."
status: pending
issue_number: 13
---

# Plan: Recommandations htaccess et actions dérivées des logs

## Overview

| Field      | Value |
| ---------- | ----- |
| **Goal**   | Rendre les constats de #8 actionnables sans ouvrir de porte : proposer, faire valider, appliquer par une commande explicite, défaire en une commande |
| **Source** | Issue GitHub #13 ; `vigie/docs/decisions.md` (trois temps ; aucun accès FTP stocké) ; `protocole-commandes.md` ; `src/Service/HtaccessService.php` et `RobotsTxtService.php` (module actuel) |

## Phases

| #   | Phase                                              | File                         |
| --- | -------------------------------------------------- | ---------------------------- |
| 1   | Analyse → propositions, génération et validation du bloc | [`phase-1.md`](./phase-1.md) |
| 2   | Application par l'agent : bac à sable, bascule, retour arrière | [`phase-2.md`](./phase-2.md) |

## Decisions

| Decision | Why |
| -------- | --- |
| Séparer l'**analyse** (déterministe : `Analysis` de #8 → `Vec<Proposal>`, testée par cas) de la **génération** de texte (`Proposal` → bloc `.htaccess`), testée par fichiers de référence (golden files) | Exigence de l'issue ; le texte est la partie fragile |
| Gradation : un robot qui respecte robots.txt (`honours_robots`) → proposition robots.txt seulement ; un robot qui ne le respecte pas, de classe non protégée → règle d'UA ; une IP → règle d'IP seulement si son score propre est élevé, que son reverse DNS, résolu au moment de proposer, la classe hébergeur, et jamais pour une IP d'une classe protégée ni d'un site `behind_proxy` ; jamais rien contre `SearchEngine`, `OtherEngine`, `SocialPreview`, `Browser`, `AiUser`, ni un jeton robots-only (Google-Extended) en règle d'UA | Garde-fous de l'issue et protections décidées dans #8 |
| Une règle d'IP porte son expiration dans Apache lui-même : `RewriteCond %{TIME} <AAAAMMJJhhmmss` (24 h par défaut), l'IP vient de `Entry.ip` (champ client), jamais d'un en-tête | TTL exigé sans écriture automatique au moment de l'expiration ; jamais d'IP tirée de `X-Forwarded-For` |
| robots.txt reste une **proposition à appliquer à la main** (texte affiché par la CLI) : la liste fermée des commandes ne s'étend pas à robots.txt dans cette issue | Plus petite surface ; robots.txt n'exécute rien |
| Le bloc est délimité `# BEGIN vigie` … `# END vigie` et n'admet qu'une **liste fermée de formes de lignes**, vérifiée par le veilleur à la génération **et par l'agent** avant toute écriture : commentaire `# …` imprimable sans `BEGIN`/`END` ; `RewriteEngine On` ; `RewriteCond %{HTTP_USER_AGENT} "<littéral>" [NC]` ou `[NC,OR]` (littéral `[A-Za-z0-9 ._/+-]{3,64}`) ; `RewriteCond %{REMOTE_ADDR} ^<IPv4 ou IPv6 échappée>$` ; `RewriteCond %{TIME} <\d{14}` ; `RewriteRule ^ - [F,L]` ; 200 lignes et 16 Kio au plus. Toute autre ligne (`php_value`, `php_flag`, `AddHandler`, `SetHandler`, `AddType`, `Action`, `Include`, `auto_prepend_file`, `allow_url_include`, `Options`, `<Files>`…) fait refuser le bloc entier | Un `.htaccess` libre donne l'exécution de code ; la validation doit tenir même si le veilleur est compromis |
| Paramètres de `htaccess-apply` : `{block, previous_sha256}` ; l'agent refuse si le `.htaccess` actuel n'a plus l'empreinte sur laquelle la proposition a été faite (`site recommend` lit l'empreinte dans le dernier rapport, fichier critique `.htaccess`) | Pas d'écriture sur un fichier modifié entre la proposition et l'application |
| Application par l'agent, sous le verrou de son état : (1) validation du bloc par sa liste ; (2) nouveau contenu = contenu actuel dont le bloc `vigie` est remplacé, ou ajouté en tête ; (3) **bac à sable** : un dossier temporaire aléatoire sous la racine, avec le nouveau `.htaccess` et une page témoin, interrogé en HTTP sur l'URL du site ; 200 attendu, sinon refus ; dossier supprimé dans tous les cas ; (4) copie `.htaccess.vigie-prev` (0644 comme l'original), écriture du nouveau par fichier temporaire et `rename` ; (5) **smoke-test** de la page d'accueil du site : même statut qu'avant la bascule, sinon retour automatique à `.vigie-prev` et résultat `failed` | Garde-fous de l'issue : dry-run, `.prev`, rollback automatique |
| `htaccess-rollback` remet `.vigie-prev` (avec smoke-test) ; une seule copie précédente, celle d'avant la dernière application | Retour arrière en une commande |
| L'écriture passe par le canal de commandes de l'agent, pas par FTP : l'issue demandait un accès « demandé au moment d'agir, jamais stocké » ; le canal n'en stocke aucun (décision du 2026-10-16) | Le canal de #10 remplace le besoin d'un accès FTP |
| `htaccess-apply` et `htaccess-rollback` deviennent disponibles (`CommandKind::available`) dans le même changement que la validation côté agent | Jamais l'un sans l'autre |
