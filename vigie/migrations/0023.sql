-- Erreurs des sites (#52) : `seq` propre aux lots d'erreurs, à côté de la
-- clé, et les groupes d'erreurs de chaque site et de chaque jour UTC. Un lot
-- porte l'état d'un jour : il remplace les groupes de ce (site, jour). Seuls
-- des messages déjà normalisés (ni IP, ni requête, ni identifiant) sont
-- gardés, jamais une ligne brute ; conservation de 14 jours. `day` est
-- `AAAA-MM-JJ` (UTC), `fingerprint` le SHA-256 hexadécimal du message
-- normalisé, dates en secondes Unix.
ALTER TABLE site_keys ADD COLUMN last_errors_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE error_groups (
    site TEXT NOT NULL,
    day TEXT NOT NULL CHECK (length(day) = 10),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 200),
    count INTEGER NOT NULL CHECK (count >= 1),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL CHECK (last_seen >= first_seen),
    PRIMARY KEY (site, day, fingerprint)
);
CREATE INDEX error_groups_day ON error_groups (day);
