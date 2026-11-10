ALTER TABLE check_runs ADD COLUMN result TEXT;
    ALTER TABLE check_runs ADD COLUMN severity TEXT;
    ALTER TABLE check_runs ADD COLUMN detail TEXT;
    ALTER TABLE check_runs ADD COLUMN duration_ms INTEGER;
    ALTER TABLE check_runs ADD COLUMN observed TEXT;