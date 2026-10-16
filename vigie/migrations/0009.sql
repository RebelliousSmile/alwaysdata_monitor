ALTER TABLE site_keys ADD COLUMN last_logs_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE log_marks (
    site TEXT NOT NULL,
    file TEXT NOT NULL,
    gen INTEGER NOT NULL,
    high INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (site, file, gen)
) WITHOUT ROWID;
CREATE TABLE log_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    file TEXT NOT NULL,
    gen INTEGER NOT NULL,
    range_start INTEGER NOT NULL,
    range_end INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    gap INTEGER NOT NULL,
    skipped_files INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    rejected TEXT NOT NULL
);
CREATE INDEX log_batches_site ON log_batches (site, received_at);
CREATE INDEX log_batches_received ON log_batches (received_at);
CREATE TABLE log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    batch INTEGER NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    host TEXT,
    ip TEXT,
    method TEXT,
    path TEXT NOT NULL,
    query_keys TEXT NOT NULL,
    status INTEGER NOT NULL,
    size INTEGER,
    referer_present INTEGER NOT NULL,
    referer_host TEXT,
    user_agent TEXT NOT NULL,
    duration_us INTEGER
);
CREATE INDEX log_entries_site ON log_entries (site, id);
CREATE INDEX log_entries_time ON log_entries (timestamp_ms);
CREATE INDEX log_marks_received ON log_marks (received_at);
