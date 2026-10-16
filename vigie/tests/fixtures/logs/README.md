# Fixtures de logs

Lignes **synthétiques** au format réel des logs HTTP d'Alwaysdata (combined
Apache précédé de `{request_hostname}` ; format « Advanced » : protocole et
durée en queue) et d'Apache. Aucune ne vient de production : le dépôt est
public (`.claude/rules/07-quality/7-public-repo-data.md`).

- IP : plages de documentation RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) et `2001:db8::/32`.
- Hôtes : `site-a.example.org`, `site-b.example.org`.
- User-agents : chaînes publiques de navigateurs, d'outils et de robots
  (celle de Googlebot cite son URL publique), pas des données de clients.

| Fichier | Ce qu'il couvre |
| --- | --- |
| `alwaysdata-standard.log` | IPv4, IPv6, HTTP/0.9, taille `-`, requête TLS sur le port HTTP, robot, `/.env`, POST en 500, ligne du journal d'erreurs (rejetée), statut 999 (rejeté) |
| `alwaysdata-advanced.log` | Protocole et durée en queue ; dernière ligne coupée à 16 Kio au milieu de l'UA, comme le fait l'agent (`docs/logs.md`) |
| `apache-combined.log` | Sans hôte en tête ; utilisateur `john doe` avec une espace ; horodatage sans décalage, lu dans le fuseau de la source |
| `alwaysdata-rotated.log.gz` | Fichier de la veille, compressé |
| `hostile-bytes.log` | Octets UTF-8 invalides dans le chemin et l'UA, guillemets échappés, IP illisible (rejetée) |
| `hostile-clock.log` | Horodatages qui reculent (rotation), date future (rejetée), date avant 1970 (rejetée) |

`expected.json` donne, pour chaque fichier, le fuseau de la source, le nombre
de lignes, d'acceptées et de rejets par motif à l'heure `reference_now_ms`
(2026-10-16T00:00:00Z). `tests/logs_contract.rs` le vérifie avec
`logs::combined::split` et `logs::normalize` ; un nouvel adaptateur y ajoute
sa fixture. Les fixtures de 1 Mo sont générées par les tests, pas committées.
