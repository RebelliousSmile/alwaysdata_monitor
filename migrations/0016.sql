-- Inventaire des composants des sites (#19) : `seq` propre aux inventaires,
-- à côté de la clé ; un inventaire par contenu reçu (le dernier et 30 jours
-- d'historique, sur `seen_at`), et ses composants validés. Le corps reçu
-- n'est jamais stocké. Les composants s'insèrent dans l'ordre canonique
-- (purl, path) et ne sont jamais réécrits : l'ordre du rowid est celui de la
-- clé, et sert de curseur de lecture par lots. Dates en secondes Unix.
ALTER TABLE site_keys ADD COLUMN last_inventory_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE site_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    spec_version TEXT NOT NULL CHECK (spec_version IN ('1.6', '1.7')),
    serial TEXT NOT NULL CHECK (length(serial) = 45),
    generated_at INTEGER NOT NULL,
    agent TEXT NOT NULL CHECK (length(agent) BETWEEN 1 AND 256),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    skipped INTEGER NOT NULL CHECK (skipped BETWEEN 0 AND 100000),
    dropped INTEGER NOT NULL CHECK (dropped >= 0),
    components INTEGER NOT NULL CHECK (components BETWEEN 0 AND 2000),
    received_at INTEGER NOT NULL,
    seen_at INTEGER NOT NULL
);
CREATE INDEX site_inventory_site ON site_inventory (site, id);
CREATE INDEX site_inventory_received ON site_inventory (site, received_at);
CREATE TABLE site_inventory_components (
    inventory INTEGER NOT NULL REFERENCES site_inventory (id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL CHECK (
        ecosystem IN ('wordpress', 'prestashop', 'composer', 'npm', 'cargo')
    ),
    base TEXT NOT NULL CHECK (length(base) BETWEEN 1 AND 1024),
    purl TEXT NOT NULL CHECK (length(purl) BETWEEN 1 AND 1024),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 1024),
    version TEXT NOT NULL DEFAULT '' CHECK (length(version) <= 128),
    scope TEXT NOT NULL CHECK (scope IN ('required', 'dev', 'mu')),
    type TEXT NOT NULL CHECK (type IN ('application', 'library')),
    path TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 200),
    parent TEXT CHECK (parent IS NULL OR length(parent) BETWEEN 1 AND 200),
    config_version TEXT CHECK (config_version IS NULL OR length(config_version) BETWEEN 1 AND 128),
    PRIMARY KEY (inventory, purl, path)
);
CREATE INDEX site_inventory_components_base ON site_inventory_components (base);
CREATE INDEX site_inventory_components_inventory ON site_inventory_components (inventory);
