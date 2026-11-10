-- Recommandations htaccess (#13) : adresses source des retraits signés de
-- l'agent, relevées par `serve` (pair TCP, ou X-Forwarded-For du seul proxy
-- local). Jamais bloquées par une règle d'IP : l'agent sonde son propre site
-- depuis son hébergement. Gardées 30 jours après le dernier retrait.
CREATE TABLE agent_sources (
    site TEXT NOT NULL,
    ip TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (site, ip)
) WITHOUT ROWID;
