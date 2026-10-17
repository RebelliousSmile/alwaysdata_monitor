-- Priorisation des failles (#18) : tables d'enrichissement CISA KEV et FIRST
-- EPSS, jointes par CVE aux alias des failles. Les sources `kev` et `epss`
-- ont leur ligne dans `vuln_sources` (créée au premier passage) et sont
-- remplacées par générations sous bail, comme les failles ; les lecteurs ne
-- voient que la génération active. `WITHOUT ROWID` : la clé primaire est
-- l'index de lecture. Métadonnées du jeu une fois par génération
-- (`vuln_dataset`, KEV : `catalogVersion` et `dateReleased` ; EPSS :
-- `model_version` et `score_date`), dates RFC 3339 en UTC. Scores EPSS en
-- millionièmes entiers.
CREATE TABLE vuln_kev (
    generation INTEGER NOT NULL,
    cve TEXT NOT NULL CHECK (length(cve) BETWEEN 13 AND 28),
    date_added TEXT NOT NULL
        CHECK (date_added GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    due_date TEXT NOT NULL CHECK (due_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    known_ransomware INTEGER NOT NULL CHECK (known_ransomware IN (0, 1)),
    name TEXT NOT NULL CHECK (length(name) <= 200),
    PRIMARY KEY (generation, cve)
) WITHOUT ROWID;
CREATE TABLE vuln_epss (
    generation INTEGER NOT NULL,
    cve TEXT NOT NULL CHECK (length(cve) BETWEEN 13 AND 28),
    epss_ppm INTEGER NOT NULL CHECK (epss_ppm BETWEEN 0 AND 1000000),
    percentile_ppm INTEGER NOT NULL CHECK (percentile_ppm BETWEEN 0 AND 1000000),
    PRIMARY KEY (generation, cve)
) WITHOUT ROWID;
CREATE TABLE vuln_dataset (
    source TEXT NOT NULL CHECK (source IN ('kev', 'epss')),
    generation INTEGER NOT NULL,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 32),
    released TEXT NOT NULL CHECK (length(released) BETWEEN 1 AND 64),
    rows INTEGER NOT NULL CHECK (rows >= 0),
    PRIMARY KEY (source, generation)
);
-- URL demandée qui a servi l'ETag ou le `Last-Modified` gardés : KEV a deux
-- hôtes, un validateur ne vaut que pour son URL. Les validateurs déjà gardés
-- (sources OSV de #16) l'ont été par l'URL de la source.
ALTER TABLE vuln_sources ADD COLUMN validator_url TEXT
    CHECK (validator_url IS NULL OR length(validator_url) BETWEEN 1 AND 2048);
UPDATE vuln_sources SET validator_url = url
    WHERE (etag IS NOT NULL OR http_last_modified IS NOT NULL) AND length(url) BETWEEN 1 AND 2048;
-- Synchronisations réussies sans charger un jeu plus ancien que l'actif
-- (KEV : miroir en retard sur cisa.gov).
ALTER TABLE vuln_sources ADD COLUMN stale_count INTEGER NOT NULL DEFAULT 0
    CHECK (stale_count >= 0);
