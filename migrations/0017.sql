-- Synchronisation des failles (#16) : validateurs HTTP du dump actif,
-- écrits avec la bascule de génération ou par `finish_unchanged`, jamais
-- seuls ; mesures et issue de la dernière tentative ; version du lecteur
-- qui a produit la génération active ; débit par source (dernière requête,
-- `Retry-After`) ; failles retenues des 7 derniers chargements réussis
-- (garde contre le rétrécissement, tableau JSON) ; révision de l'archive
-- Friends-Of-Presta (F3). Dates en secondes Unix.
ALTER TABLE vuln_sources ADD COLUMN etag TEXT
    CHECK (etag IS NULL OR length(etag) BETWEEN 1 AND 256);
ALTER TABLE vuln_sources ADD COLUMN http_last_modified TEXT
    CHECK (http_last_modified IS NULL OR length(http_last_modified) BETWEEN 1 AND 64);
ALTER TABLE vuln_sources ADD COLUMN dump_bytes INTEGER CHECK (dump_bytes IS NULL OR dump_bytes >= 0);
ALTER TABLE vuln_sources ADD COLUMN unpacked_bytes INTEGER
    CHECK (unpacked_bytes IS NULL OR unpacked_bytes >= 0);
ALTER TABLE vuln_sources ADD COLUMN last_duration_ms INTEGER
    CHECK (last_duration_ms IS NULL OR last_duration_ms >= 0);
ALTER TABLE vuln_sources ADD COLUMN last_outcome TEXT CHECK (
    last_outcome IS NULL
    OR last_outcome IN (
        'loaded', 'unchanged', 'not_modified', 'failed', 'busy', 'refused_shrink', 'rate_limited'
    )
);
ALTER TABLE vuln_sources ADD COLUMN loader_version INTEGER;
ALTER TABLE vuln_sources ADD COLUMN last_request_at INTEGER;
ALTER TABLE vuln_sources ADD COLUMN retry_after_until INTEGER;
ALTER TABLE vuln_sources ADD COLUMN recent_entries TEXT NOT NULL DEFAULT '[]'
    CHECK (length(recent_entries) <= 256);
ALTER TABLE vuln_sources ADD COLUMN revision TEXT
    CHECK (revision IS NULL OR length(revision) BETWEEN 1 AND 128);
