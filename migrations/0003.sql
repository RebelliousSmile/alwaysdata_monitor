CREATE TABLE site_keys (
        site TEXT PRIMARY KEY,
        pubkey BLOB NOT NULL CHECK (length(pubkey) = 32),
        added_at INTEGER NOT NULL,
        rotated_at INTEGER
    );
    CREATE TABLE reports (
        site TEXT PRIMARY KEY,
        last_seq INTEGER NOT NULL,
        last_valid_at INTEGER NOT NULL,
        agent TEXT NOT NULL,
        facts TEXT NOT NULL
    );