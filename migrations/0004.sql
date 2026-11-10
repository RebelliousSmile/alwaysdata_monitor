ALTER TABLE reports ADD COLUMN files TEXT NOT NULL DEFAULT '{}';
    CREATE TABLE baselines (
        site TEXT PRIMARY KEY,
        files TEXT NOT NULL,
        set_at INTEGER NOT NULL
    );