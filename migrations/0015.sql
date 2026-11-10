-- Failles connues (#15) : une ligne par source (export OSV d'un écosystème,
-- Wordfence, Friends-Of-Presta), et ses failles par génération. Une source
-- est remplacée en bloc : la synchronisation réserve une génération
-- (`next_generation`, jamais réutilisée) sous bail (`loading_generation`,
-- `loading_since`), l'écrit par lots, puis bascule `active_generation` en
-- compare-and-swap. Les lecteurs ne voient que la génération active. Pas de
-- clé étrangère en cascade : la purge retire enfants puis parents par lots.
-- Dates en secondes Unix ; scores en dixièmes (98 pour 9,8).
CREATE TABLE vuln_sources (
    id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    url TEXT NOT NULL DEFAULT '' CHECK (length(url) <= 2048),
    license TEXT NOT NULL DEFAULT '' CHECK (length(license) <= 64),
    attribution TEXT NOT NULL DEFAULT '' CHECK (length(attribution) <= 2000),
    active_generation INTEGER NOT NULL DEFAULT 0 CHECK (active_generation >= 0),
    next_generation INTEGER NOT NULL DEFAULT 1,
    loading_generation INTEGER,
    loading_since INTEGER,
    last_success_at INTEGER,
    last_attempt_at INTEGER,
    dump_sha256 TEXT CHECK (dump_sha256 IS NULL OR length(dump_sha256) = 64),
    entries INTEGER NOT NULL DEFAULT 0 CHECK (entries >= 0),
    dropped INTEGER NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    dropped_detail TEXT NOT NULL DEFAULT '{}' CHECK (length(dropped_detail) <= 4096),
    out_of_scope INTEGER NOT NULL DEFAULT 0 CHECK (out_of_scope >= 0),
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 2048),
    CHECK (next_generation > active_generation),
    CHECK ((loading_generation IS NULL) = (loading_since IS NULL)),
    CHECK (loading_generation IS NULL OR loading_generation < next_generation)
);
CREATE TABLE vuln_advisories (
    source TEXT NOT NULL,
    generation INTEGER NOT NULL,
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 64),
    aliases TEXT NOT NULL DEFAULT '[]' CHECK (length(aliases) <= 4096),
    summary TEXT NOT NULL DEFAULT '' CHECK (length(summary) <= 500),
    severity TEXT NOT NULL DEFAULT '[]' CHECK (length(severity) <= 2048),
    score INTEGER CHECK (score IS NULL OR score BETWEEN 0 AND 100),
    score_origin TEXT CHECK (
        score_origin IS NULL
        OR score_origin IN ('wordfence', 'friends_of_presta', 'cvss_v31', 'ghsa_severity')
    ),
    informational INTEGER NOT NULL DEFAULT 0 CHECK (informational IN (0, 1)),
    malicious INTEGER NOT NULL DEFAULT 0 CHECK (malicious IN (0, 1)),
    license TEXT NOT NULL CHECK (length(license) BETWEEN 1 AND 64),
    attribution TEXT NOT NULL CHECK (length(attribution) <= 2000),
    cwe TEXT NOT NULL DEFAULT '[]' CHECK (length(cwe) <= 256),
    published INTEGER,
    modified INTEGER NOT NULL,
    refs TEXT NOT NULL DEFAULT '[]' CHECK (length(refs) <= 32768),
    source_url TEXT NOT NULL CHECK (length(source_url) <= 2048),
    CHECK ((score IS NULL) = (score_origin IS NULL)),
    UNIQUE (source, generation, id)
);
CREATE INDEX vuln_advisories_id ON vuln_advisories (id);
CREATE TABLE vuln_aliases (
    source TEXT NOT NULL,
    generation INTEGER NOT NULL,
    advisory_id TEXT NOT NULL,
    alias TEXT NOT NULL CHECK (length(alias) BETWEEN 1 AND 64)
);
CREATE INDEX vuln_aliases_advisory ON vuln_aliases (source, generation, advisory_id);
CREATE INDEX vuln_aliases_alias ON vuln_aliases (alias);
CREATE TABLE vuln_affected (
    source TEXT NOT NULL,
    generation INTEGER NOT NULL,
    advisory_id TEXT NOT NULL,
    purl_type TEXT NOT NULL CHECK (
        purl_type IN ('composer', 'npm', 'cargo', 'wordpress', 'prestashop')
    ),
    purl_namespace TEXT NOT NULL DEFAULT '' CHECK (length(purl_namespace) <= 214),
    purl_name TEXT NOT NULL CHECK (length(purl_name) BETWEEN 1 AND 214),
    scheme TEXT NOT NULL CHECK (scheme IN ('semver', 'composer', 'php')),
    ranges TEXT NOT NULL DEFAULT '[]',
    versions TEXT NOT NULL DEFAULT '[]',
    last_known TEXT,
    unevaluable INTEGER NOT NULL DEFAULT 0 CHECK (unevaluable IN (0, 1))
);
CREATE INDEX vuln_affected_advisory ON vuln_affected (source, generation, advisory_id);
CREATE INDEX vuln_affected_purl
    ON vuln_affected (purl_type, purl_namespace, purl_name, source, generation);
