CREATE TABLE command_sites (
    site TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    last_pull_seq INTEGER NOT NULL DEFAULT 0,
    last_pull_at INTEGER,
    last_command_seq INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE commands (
    id TEXT PRIMARY KEY,
    site TEXT NOT NULL,
    seq INTEGER NOT NULL,
    name TEXT NOT NULL,
    runtime TEXT NOT NULL,
    params TEXT NOT NULL,
    typology TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    served_at INTEGER,
    closed_at INTEGER,
    result TEXT,
    UNIQUE (site, seq)
);
CREATE UNIQUE INDEX commands_one_open ON commands (site) WHERE state IN ('pending', 'served');
CREATE TABLE command_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    entry TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL
);
CREATE INDEX command_audit_site ON command_audit (site, id);
CREATE TRIGGER command_audit_no_update BEFORE UPDATE ON command_audit
BEGIN
    SELECT RAISE(ABORT, 'journal d''audit en ajout seul');
END;
CREATE TRIGGER command_audit_no_delete BEFORE DELETE ON command_audit
BEGIN
    SELECT RAISE(ABORT, 'journal d''audit en ajout seul');
END;
CREATE TABLE audit_notified (
    site TEXT PRIMARY KEY,
    last_hash TEXT NOT NULL,
    notified_at INTEGER NOT NULL
) WITHOUT ROWID;
