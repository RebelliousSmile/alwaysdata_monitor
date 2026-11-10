CREATE TABLE ticks (
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL
    );
    CREATE INDEX ticks_at ON ticks(at);