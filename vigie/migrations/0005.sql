CREATE TABLE devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
        created_at INTEGER NOT NULL,
        seen_at INTEGER,
        revoked_at INTEGER
    );
    CREATE TABLE pairings (
        id INTEGER PRIMARY KEY,
        code_hash BLOB NOT NULL UNIQUE CHECK (length(code_hash) = 32),
        name TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER,
        device_id INTEGER REFERENCES devices(id)
    );