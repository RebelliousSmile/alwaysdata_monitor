-- Analyse de logs (#8) : agrégats repliés d'un passage de `tick` à l'autre.
-- Les heures sont des tranches `timestamp_ms / 3 600 000`, les minutes
-- `timestamp_ms / 60 000`, toujours en heure des données (UTC).

-- Comptes par minute de chaque règle. Portée `site` : `key` vide, `ips` les
-- IP distinctes de la minute en JSON, plafonnées au plus grand `min_ips`.
-- Portée `ip` : `key` est l'IP, `ips` reste vide ; supprimés avec l'IP
-- évincée des profils.
CREATE TABLE log_buckets (
    site TEXT NOT NULL,
    rule TEXT NOT NULL,
    key TEXT NOT NULL,
    minute INTEGER NOT NULL,
    count INTEGER NOT NULL,
    ips TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (site, rule, key, minute)
) WITHOUT ROWID;
CREATE INDEX log_buckets_minute ON log_buckets (site, minute);
CREATE INDEX log_buckets_key ON log_buckets (site, key);

-- Profil d'une IP par tranche horaire. `error` : borne d'erreur héritée de
-- l'IP évincée à l'admission (Space-Saving), datée de la tranche
-- d'admission ; jamais additionnée aux compteurs observés. `uas` : UA
-- distincts en JSON, 20 au plus. `class` et `bot` : premier robot vu.
CREATE TABLE log_profiles (
    site TEXT NOT NULL,
    ip TEXT NOT NULL,
    hour INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    static INTEGER NOT NULL,
    facets INTEGER NOT NULL,
    refused INTEGER NOT NULL,
    empty_referer_pages INTEGER NOT NULL,
    peak_minute INTEGER NOT NULL,
    error INTEGER NOT NULL DEFAULT 0,
    uas TEXT NOT NULL DEFAULT '[]',
    class TEXT,
    bot TEXT,
    PRIMARY KEY (site, ip, hour)
) WITHOUT ROWID;
-- Index couvrant du compte de classement (requêtes et erreur des tranches
-- vivantes) : l'éviction le relit sans toucher aux UA.
CREATE INDEX log_profiles_rank ON log_profiles (site, hour, ip, requests, error);

-- Requêtes des robots du catalogue, par heure.
CREATE TABLE log_bots (
    site TEXT NOT NULL,
    hour INTEGER NOT NULL,
    bot TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (site, hour, bot)
) WITHOUT ROWID;

-- Charge par heure : volume, refus (403), temps de service en µs des
-- requêtes qui en portent un (`timed`), part des facettes et des robots.
CREATE TABLE log_load (
    site TEXT NOT NULL,
    hour INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    refused INTEGER NOT NULL,
    timed INTEGER NOT NULL,
    service_us INTEGER NOT NULL,
    facets INTEGER NOT NULL,
    facets_us INTEGER NOT NULL,
    bots INTEGER NOT NULL,
    bots_us INTEGER NOT NULL,
    PRIMARY KEY (site, hour)
) WITHOUT ROWID;

-- Curseur opaque du `LogSource` d'un site et heure de référence :
-- min(dernière `timestamp_ms` repliée, heure du veilleur), en ms.
CREATE TABLE log_cursors (
    site TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    reference_ms INTEGER,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
