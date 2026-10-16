CREATE TABLE check_runs (
        site TEXT NOT NULL,
        check_name TEXT NOT NULL,
        last_run INTEGER NOT NULL,
        PRIMARY KEY (site, check_name)
    );
    CREATE TABLE incidents (
        id INTEGER PRIMARY KEY,
        key TEXT NOT NULL,
        site TEXT NOT NULL,
        check_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        detail TEXT NOT NULL,
        opened_at INTEGER NOT NULL,
        closed_at INTEGER,
        acked_at INTEGER,
        open_notified_at INTEGER,
        close_notified_at INTEGER,
        last_reminder_at INTEGER
    );
    CREATE UNIQUE INDEX incidents_open_key ON incidents(key) WHERE closed_at IS NULL;
    CREATE INDEX incidents_site_check ON incidents(site, check_name);