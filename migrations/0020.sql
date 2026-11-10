-- Outil d'inventaire (#20) : clé d'inventaire de chaque site, distincte de
-- la clé de rapport (`site_keys`) et unique toutes tables confondues (garde
-- `store::pubkey_in_use`, `UNIQUE` ici en filet), avec le `seq` des
-- inventaires de la source `ci` ; source de chaque inventaire reçu (`agent`
-- pour les lignes existantes) et index du dernier inventaire par
-- (site, source). Aucun index unique sur `site_keys` : une base existante
-- peut déjà porter deux fois la même clé d'agent. Dates en secondes Unix.
-- Numéro : prochain libre à la fusion (F2 #16 prend 0017, F3 0018, F4 0019).
CREATE TABLE site_inventory_keys (
    site TEXT PRIMARY KEY,
    pubkey BLOB NOT NULL UNIQUE CHECK (length(pubkey) = 32),
    last_seq INTEGER NOT NULL DEFAULT 0,
    added_at INTEGER NOT NULL,
    rotated_at INTEGER
);
ALTER TABLE site_inventory ADD COLUMN source TEXT NOT NULL DEFAULT 'agent'
    CHECK (source IN ('agent', 'ci'));
CREATE INDEX site_inventory_site_source ON site_inventory (site, source, id);
