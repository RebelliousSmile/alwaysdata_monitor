# Protocole des commandes, version 1

Le veilleur peut demander à l'agent d'un site d'agir. C'est la seule voie
d'écriture de Vigie vers un site, et elle est fermée par défaut. Ce document est
le contrat ; il fixe dès l'issue #2 ce que le canal de l'issue #10 transportera,
pour que les agents déployés n'aient jamais à changer de contrat.

Décision du 2026-10-16 (`decisions.md`) : agir suit toujours trois temps.
Vigie propose, l'exploitant valide, puis l'application se fait par une commande
explicite (`--apply`). Rien n'est automatique.

## Liste fermée

La liste est codée en dur (`src/capability.rs`). Ajouter une commande est un
changement de code relu, jamais une valeur de configuration.

| Commande | Effet | Runtimes admis |
| --- | --- | --- |
| `ping` | aller-retour sans effet : prouve que le canal fonctionne | `php` |
| `rotate-key` | l'agent crée une nouvelle paire de clés de rapport et rend la clé publique | `php` |
| `htaccess-apply` | remplace le bloc `# BEGIN vigie` … `# END vigie` du `.htaccess` (#13) | `php` |
| `htaccess-rollback` | remet le `.htaccess` précédent (#13) | `php` |

Aucune commande n'admet `node` tant qu'aucun agent Node n'existe, ni `static`,
qui n'a pas d'agent.

## Typologie : deux axes

| Axe | Clé de `config.toml` | Valeurs | Filtre |
| --- | --- | --- | --- |
| CMS | `kind` | `generic` (défaut), `wordpress`, `prestashop` | les contrôles (`CheckKind::cms`) |
| Runtime | `runtime` | `php`, `node`, `static` | les commandes (`CommandKind::runtimes`) |

- `wordpress` et `prestashop` impliquent `php` ; un autre runtime pour eux est
  une erreur de configuration.
- Un site `generic` sans `runtime` n'en a aucun et n'admet **aucune**
  commande. Un site PHP déclaré `generic` doit poser `runtime = "php"`.
- Le runtime vient **seulement** de `config.toml` sur le veilleur : jamais d'un
  rapport de l'agent, jamais d'une détection du contenu du site. Un site ne
  peut pas se déclarer lui-même `php`.
- Une valeur inconnue (`runtime = "python"`) fait refuser la configuration.

Dans le contrat des commandes, le champ s'appelle `runtime`, et non `kind`
comme dans le texte de l'issue #2 : `kind` désigne déjà le CMS.

## Enveloppe d'une commande

Le corps d'une réponse du veilleur qui porte une commande contient cet objet :

```json
{
  "v": 1,
  "site": "site-a",
  "id": "0192f5a8-7c3e-7d41-9b2a-5c1e8f0a4b6d",
  "seq": 3,
  "name": "ping",
  "runtime": "php",
  "params": {},
  "issued_at": 1792108800,
  "expires_at": 1792195200
}
```

| Champ | Règle |
| --- | --- |
| `v` | `1` ; l'agent refuse toute autre version |
| `site` | identifiant du site destinataire ; l'agent refuse un site qui n'est pas le sien. La clé de commandes est commune à tous les sites : sans ce champ, une commande pour le site A vaudrait pour le site B |
| `id` | UUIDv7 tiré par le veilleur |
| `seq` | entier strictement croissant par site ; l'agent refuse un `seq` déjà vu ou plus petit |
| `name` | une commande de la liste fermée ; l'agent refuse un nom absent de **sa propre** liste codée en dur |
| `runtime` | obligatoire ; l'agent refuse un runtime qui n'est pas le sien |
| `params` | objet propre à la commande, schéma strict (#10) |
| `issued_at`, `expires_at` | secondes Unix ; l'agent refuse une commande expirée |

- Le schéma est strict : tout champ inconnu fait refuser la commande.
- La signature (#10) porte sur **les octets exacts du corps**, tels que reçus,
  sans réencodage du JSON, comme pour les rapports (`protocole-agent.md`). Elle
  est faite par la clé de commandes du veilleur, distincte de toute clé
  d'agent. L'agent l'a épinglée à son installation.
- Le veilleur vérifie que la commande est admise (`permit`) à sa création, **et
  de nouveau à sa délivrance** : la configuration a pu changer entre-temps.

La requête de retrait, l'anti-rejeu, les états d'une commande et le journal
d'audit sont décrits par #10, dans ce même document.
