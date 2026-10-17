# Recommandations htaccess (issue #13)

Vigie rend actionnables les constats de l'analyse de logs (#8) sans ouvrir de
porte. Trois temps, comme toute action sur un site (`decisions.md`) : Vigie
**propose** (`vigie site recommend`), l'exploitant **valide**, l'application
part par une **commande explicite** (`--apply`) sur le canal signé
([`protocole-commandes.md`](./protocole-commandes.md)). Rien n'est automatique,
et aucun accès FTP n'est demandé ni stocké : le canal de #10 le remplace.

Code : `src/recommend/` (veilleur), section « .htaccess » de
`agent/php/vigie-agent.php` (agent).

## Gradation

À partir de la dernière analyse du site (`Analysis`, résumé et verdicts) :

| Constat | Proposition |
| --- | --- |
| Robot du catalogue qui respecte robots.txt (`honours_robots`), dont les jetons robots.txt seuls (`Google-Extended`) | `User-agent: <robot>` / `Disallow: /`, **à poser à la main** (robots.txt n'exécute rien ; la liste fermée des commandes ne s'y étend pas) |
| Robot qui ne respecte pas robots.txt, de classe non protégée, ni `Unknown` ni `Tool` | règle d'UA de **30 jours** |
| IP au score **propre** élevé (≥ 70), de classe non protégée, que son reverse DNS, résolu au moment de proposer (10 IP au plus, 5 s en tout), classe **hébergeur** | règle d'IP de **24 h** |

Jamais rien contre `SearchEngine`, `OtherEngine`, `SocialPreview`, `Browser`
ni `AiUser`. Sans fuseau du site (`[sites.logs] tz`), ni règle d'UA ni règle
d'IP : seulement robots.txt. Un site `behind_proxy` n'a pas de règle d'IP.

### Ce que Vigie ne bloque jamais

- **IP protégées** : `[logs] protect_ips` (IP sortantes du veilleur),
  `[sites.logs] protect_ips` (tâches planifiées, webhooks, bureau), et les
  adresses source des retraits signés de l'agent, relevées par `serve` (pair
  TCP ; `X-Forwarded-For` seulement quand le pair est la boucle locale, Caddy)
  et gardées 30 jours (`agent_sources`).
- **Trafic de Vigie**, retiré de l'analyse : UA `vigie/…` et
  `vigie-agent-php/…`, chemins `/vigie-essai-*` (bac à sable). Sans cela, le
  veilleur (UA d'outil, IP d'hébergeur, sans statiques) atteindrait le niveau
  élevé du score.
- **Littéral d'UA** : c'est **le jeton du catalogue** du robot, jamais une
  sous-chaîne lue dans un log. La classe `Unknown` n'a pas de règle d'UA ; les
  jetons génériques (`curl`, `python-requests`, `Java`, `Go-http-client`,
  `wget`…) sont refusés : ils touchent le corpus protégé.
- **Corpus d'UA protégés** (`tests/fixtures/htaccess/protected-uas.txt`,
  constante `PROTECTED_UAS` de l'agent, égale par un test) : moteurs, aperçus
  sociaux, navigateurs courants, assistants IA pour une personne, UA de
  Vigie, webhooks de paiement, bouclages de CMS (`WordPress/`, PrestaShop),
  clients de tâches planifiées. Une condition d'UA qui en touche un seul fait
  refuser le bloc entier, au veilleur comme à l'agent.

## Le bloc

Délimité par deux lignes exactes, au plus une paire, localisées par
opérations de chaînes :

```apache
# BEGIN vigie
# Gere par Vigie (vigie site recommend) : ne pas modifier a la main.
RewriteEngine On
# ua jusqu'au 2026-07-15 12:00:00
RewriteCond %{HTTP_USER_AGENT} "Bytespider" [NC,OR]
RewriteCond %{HTTP_USER_AGENT} "Screaming Frog" [NC]
RewriteCond %{TIME} <20260715120000
RewriteRule ^ - [F,L]
# ip jusqu'au 2026-06-16 12:00:00
RewriteCond %{REMOTE_ADDR} "^203\.0\.113\.7$"
RewriteCond %{TIME} <20260616120000
RewriteRule ^ - [F,L]
# END vigie
```

### Lignes admises

| Ligne | Règle |
| --- | --- |
| `RewriteEngine On` | une fois, en tête |
| `RewriteCond %{HTTP_USER_AGENT} "<motif>" [NC,OR]` / `[NC]` | groupe d'UA : `[NC,OR]` sur chaque ligne sauf la dernière |
| `RewriteCond %{REMOTE_ADDR} "^<ip>$"` | groupe d'IP : une seule ligne |
| `RewriteCond %{TIME} <AAAAMMJJhhmmss` | exactement une par groupe, après les conditions |
| `RewriteRule ^ - [F,L]` | exactement une par groupe, en dernier |
| `# …` | commentaire en colonne 0, ASCII imprimable, sans `\`, sans `BEGIN` ni `END` |

Tout le reste (`php_value`, `php_flag`, `AddHandler`, `SetHandler`,
`AddType`, `Action`, `Include`, `auto_prepend_file`, `allow_url_include`,
`Options`, `<Files>`, une autre `RewriteRule`…) fait refuser le bloc entier :
un `.htaccess` libre donne l'exécution de code. Fins de ligne LF seules ;
aucun CR, tabulation ni NUL ; aucune ligne finissant par `\` (continuation
Apache) ; 200 lignes et 16 Kio au plus.

- **Motif d'UA = expression régulière** pour Apache : le littéral source
  n'admet que `[A-Za-z0-9][A-Za-z0-9 _/.+-]{2,63}` (un motif commençant par
  `-` serait lu comme un opérateur) et s'écrit échappé (`.` → `\.`,
  `+` → `\+`) ; la grammaire n'admet dans le motif que `[A-Za-z0-9 _/-]`,
  `\.` et `\+`. Une condition d'UA vaut donc « contient, sans casse ».
- **IP** : celle de `Entry.ip` (le client vu par le serveur), jamais d'un
  en-tête ; forme canonique (IPv4 décimale, IPv6 compressée en minuscules,
  RFC 5952) et échappée (`^…$`, points et deux-points). Les IPv4 mappées et
  `::/96` sont refusées. Elle est comparée à `%{REMOTE_ADDR}` : une IPv4
  mappée `::ffff:` côté serveur ou l'IP d'un proxy rendent la règle inerte.

### Expiration dans Apache

Chaque groupe porte sa `RewriteCond %{TIME} <…` : une règle oubliée ne
bloque pas indéfiniment, sans aucune écriture à l'expiration.

| Sorte | Par défaut | Borne vérifiée |
| --- | --- | --- |
| IP | 24 h | (now, now + 25 h] |
| UA | 30 jours | (now, now + 31 jours] |

`%{TIME}` est l'heure **locale** du serveur web. Le veilleur l'écrit dans le
fuseau du site (`[sites.logs] tz`) ; l'agent vérifie la borne dans le fuseau
explicite de sa configuration (`config.json` : `tz`, appliqué par
`date_default_timezone_set`, jamais celui de `php.ini`). Le bac à sable sonde
l'**horloge réelle d'Apache** (voir plus bas). Au recul d'heure, une heure
répétée peut porter une règle de 24 h à 25 h : c'est dans la borne. Les heures
ambiguës ou inexistantes se lisent en mode « compatible » (la plus tôt des
deux ; après le trou).

### Bloc cumulatif

Le rapport ne porte que des empreintes. Le **bloc en place** est donc celui du
dernier `htaccess-apply` `done` dont `current_sha256` égale l'empreinte
`.htaccess` du dernier rapport. Un nouveau bloc en reprend les groupes encore
valides (expirant dans plus d'une heure), retire les expirés, et
`site recommend` affiche le diff (`=` repris, `-` retiré, `+` nouveau). Sans
cette correspondance (fichier modifié hors de Vigie, retour arrière, première
application), les règles en place sont inconnues : `--apply` exige
`--replace`.

Le bloc `# BEGIN sc_alwaysdata protection` du module PrestaShop reste intact,
au-dessus ou au-dessous du bloc vigie ; `HtaccessDoctor::removeUaRules` laisse
le bloc vigie intact (test du module).

## `vigie site recommend`

```console
$ vigie site recommend site-a                     # aperçu : robots.txt, bloc, diff, empreintes
$ vigie site recommend site-a --apply [--replace] # 1) calcul de l'empreinte par l'agent
$ vigie site recommend site-a --apply [--replace] # 2) après son résultat : application
$ vigie site command site-a htaccess-rollback --apply
```

Le veilleur ne connaît du `.htaccess` que des empreintes : il ne peut pas
calculer `new_sha256` (SHA-256 n'est pas composable, et le reste du fichier
lui est inconnu). Le premier `--apply` met donc en file un `htaccess-apply`
en **calcul seul** (`new_sha256: null`) : l'agent revalide le bloc, vérifie
`previous_sha256` et rend l'empreinte du contenu qu'il écrirait, sans rien
écrire. Le second `--apply` reprend ce bloc préparé (s'il est encore valide
et que l'empreinte du dernier rapport n'a pas changé) avec `new_sha256`, et
le met en file. `--recompute` ignore un calcul préparé. Un bloc préparé plus
tôt garde ses heures d'expiration : une règle d'IP préparée la veille dure
d'autant moins.

## Application par l'agent

`config.json` porte `url` (adresse https de la racine du site) et `tz`.
Sous le verrou de l'état :

1. **Validation** du bloc par la grammaire fermée de l'agent, `now` réel et
   fuseau `tz` ; paramètres stricts.
2. **Empreintes** : refus si le `.htaccess` n'a pas `previous_sha256`
   (`null` : absent ; il est alors créé), ou si le contenu calculé (bloc vigie
   remplacé, ou ajouté en tête) n'a pas `new_sha256`.
3. **Bac à sable différentiel** : `vigie-essai-<hex>-a` (ancien contenu) et
   `-b` (nouveau, plus deux groupes sondes), chacun avec une page témoin à
   nonce, aucune redirection suivie. Un `.htaccess` enfant avec
   `RewriteEngine On` n'hérite pas des réécritures du parent : on compare donc
   les deux dossiers, jamais à un 200 absolu.
   - navigateur dans `-a` : 200 avec le nonce, sinon « non représentatif » ;
     un 200 sans le nonce est toujours « non représentatif » ;
   - navigateur, Googlebot et un échantillon du corpus : même statut dans les
     deux dossiers ;
   - chaque groupe d'UA : 403 dans `-b`, et pas 403 dans `-a` s'il est neuf
     (un groupe repris est déjà actif dans l'ancien contenu) ;
   - sondes d'horloge dans `-b` seulement : `vigie-probe-<hex>a`,
     `%{TIME} <` now + 30 min → 403 attendu ; `vigie-probe-<hex>b`,
     `%{TIME} <` now − 30 min → 200 attendu ; sinon « horloge Apache ≠ horloge
     agent ».
   Les dossiers sont supprimés dans tous les cas. Le bac à sable vérifie la
   syntaxe et le bloc ; l'effet à la racine relève du smoke-test.
4. **Compare-and-swap** : relecture du `.htaccess`, refus s'il n'a plus
   `previous_sha256`. Puis copie privée **dans le dossier de l'agent** (0700) :
   `htaccess.prev` (0600, fichier temporaire puis `rename`, depuis les octets
   vérifiés ; `htaccess.prev.absent` si le fichier n'existait pas), la copie
   précédente gardée en `.old` jusqu'à la réussite de la bascule ; état
   `htaccess_pending` écrit ; puis `.htaccess` par fichier temporaire
   `.htaccess.vigie-*.tmp` (refusé par Apache comme tout `.ht*`), mode de
   l'original, et `rename`. Une fenêtre résiduelle entre la relecture et le
   `rename` reste : un tiers qui écrit à cet instant est écrasé.
5. **Smoke-test** de l'accueil (anti-cache `?vigie-essai=…`), UA de
   navigateur et Googlebot : même statut qu'avant la bascule. Sinon retour à
   la copie privée **seulement si** le `.htaccess` a encore `new_sha256` ;
   sinon `failed` « modifié pendant l'application », rien n'est écrasé.
6. `htaccess_pending` effacé. Tout résultat porte `data.current_sha256`.

Requêtes de l'agent : 5 s chacune, 30 s en tout pour le smoke-test d'avant et
le bac à sable ; le smoke-test d'après garde au moins 10 s, pour ne jamais
laisser une bascule sans contrôle faute de budget.

### Reprise

Un passage qui trouve `htaccess_pending` (bascule interrompue) le traite en
tête, avant tout retrait, d'après l'empreinte actuelle : `new_sha256` →
smoke-test contre les statuts d'avant, puis `ok` ou retour arrière et
`failed` ; `prev_sha256` → `failed` « bascule non faite » ; autre → `failed`
« modifié pendant l'application » (rien d'écrit dans ces deux cas). Le
résultat remplace celui de la commande interrompue. Un `state.json` d'agent
0.2.0 ou 0.3.0 est migré (`htaccess_pending: null`).

### Retour arrière

`htaccess-rollback {expected_current_sha256, prev_sha256}` remet la copie
privée, refusé si elle n'a pas `prev_sha256` ou si le `.htaccess` n'a pas
`expected_current_sha256` (compare-and-swap), puis smoke-test (un échec est
signalé, la copie remise reste). Une seule copie précédente : un second
retour arrière ne remonte pas plus loin. Une copie d'un fichier absent le
supprime. `vigie site command site-a htaccess-rollback` tire les deux
empreintes du dernier rapport et du dernier `htaccess-apply` en place.

À la main, sans le veilleur : `cp ~/.vigie-agent/htaccess.prev ~/www/.htaccess`
(puis `vigie site accept site-a`).

## Intégrité

Le rapport part avant le retrait qui porte le résultat : sans précaution, le
rapport qui porte le nouveau `.htaccess` ouvrirait `modified:.htaccess` avant
le résultat `ok`. Tant qu'une commande `htaccess-*` est `served` ou
`unknown`, `compare()` admet pour `.htaccess` ses empreintes attendues
(`new_sha256` et `previous_sha256` d'une application ; `prev_sha256` et
`expected_current_sha256` d'un retour arrière ; rien pour un calcul seul), sans
constat ni changement de référence. La référence suit `current_sha256` du
résultat **seulement** s'il fait partie de ces empreintes. Une empreinte hors
des attendues ouvre l'incident comme toujours.

## Tests

- `tests/htaccess.rs` : fichiers de référence (`tests/fixtures/htaccess/*.htaccess`),
  cas de refus, et `vectors.json` (blocs écrits à la main et fuzz
  différentiel à graine fixe, verdicts du validateur Rust) ;
  `VIGIE_WRITE_VECTORS=1` régénère. `AgentTest.php` rejoue chaque vecteur et
  rend le même code de refus.
- `tests/recommend.rs`, `tests/recommend_cli.rs`, `tests/commands.rs` :
  gradation, protections, bloc cumulatif, CLI, intégrité, adresse source.
- `AgentTest.php` : bac à sable sur un site `php -S` dont le routeur
  (`agent/php/tests/site-router.php`) applique le bloc vigie et simule les
  pannes (500, 200 sans nonce, horloge décalée, accueil cassé, tiers) ;
  avec `VIGIE_APACHE=/usr/sbin/apache2`, le même parcours sur un **Apache
  réel** (mod_rewrite, `AllowOverride All`), dont une horloge Apache en UTC
  contre un agent à l'heure de Paris.
- `VIGIE_E2E_PHP=php cargo test --test agent_e2e -- --ignored` : calcul,
  application et retour arrière de bout en bout, veilleur réel.
