-- Corrections de plage auditées (#17) : pour une plage libre de
-- Friends-Of-Presta non reconnue, la plage machine saisie par l'exploitant,
-- valable pour tous les sites. Hors des générations : jamais purgée par la
-- synchronisation. En ajout seul (déclencheurs) : la ligne la plus récente
-- d'une clé (source, advisory_id, purl) fait foi, `ranges` NULL vaut retrait.
-- Chaque ligne a son entrée dans la chaîne d'audit signée du pseudo-site
-- `_veilleur` (`audit_hash`), écrite dans la même transaction.
CREATE TABLE vuln_range_corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 64),
    advisory_id TEXT NOT NULL CHECK (length(advisory_id) BETWEEN 1 AND 64),
    purl TEXT NOT NULL CHECK (length(purl) BETWEEN 1 AND 1024),
    ranges TEXT CHECK (ranges IS NULL OR length(ranges) <= 4096),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    operator TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 256),
    at INTEGER NOT NULL,
    audit_hash TEXT NOT NULL CHECK (length(audit_hash) = 64)
);
CREATE INDEX vuln_range_corrections_key
    ON vuln_range_corrections (source, advisory_id, purl, id);
CREATE TRIGGER vuln_range_corrections_no_update BEFORE UPDATE ON vuln_range_corrections
BEGIN
    SELECT RAISE(ABORT, 'corrections de plage en ajout seul');
END;
CREATE TRIGGER vuln_range_corrections_no_delete BEFORE DELETE ON vuln_range_corrections
BEGIN
    SELECT RAISE(ABORT, 'corrections de plage en ajout seul');
END;
