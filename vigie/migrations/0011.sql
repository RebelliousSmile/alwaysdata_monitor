-- Analyse de logs (#8), phase 3 : signatures partagées entre sites et
-- instantanés de l'analyse. Dates en secondes Unix (heure du veilleur),
-- références en ms (heure des données).

-- Signatures d'UA de robots notées par un site : UA normalisé (minuscules,
-- versions retirées) et score propre qui l'a notée. Jamais d'IP. 100 par
-- site au plus ; expirent 30 jours après la dernière note.
CREATE TABLE log_signatures (
    ua TEXT NOT NULL,
    site TEXT NOT NULL,
    score INTEGER NOT NULL,
    seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (ua, site)
) WITHOUT ROWID;
CREATE INDEX log_signatures_site ON log_signatures (site, seen_at);
CREATE INDEX log_signatures_expires ON log_signatures (expires_at);

-- Résumé d'une analyse (robots, règles, charge) en JSON, sans IP : gardé
-- 30 jours. Le dernier d'un site est toujours gardé ; les précédents partent
-- dès qu'ils ont plus de 15 minutes de moins que lui.
CREATE TABLE log_analysis (
    site TEXT NOT NULL,
    generated_at INTEGER NOT NULL,
    reference_ms INTEGER NOT NULL,
    summary TEXT NOT NULL,
    PRIMARY KEY (site, generated_at)
) WITHOUT ROWID;

-- Verdicts d'IP d'un instantané, niveaux moyen et élevé seulement : purgés
-- 48 heures après `generated_at` (minimisation). `reasons` en JSON.
CREATE TABLE log_verdicts (
    site TEXT NOT NULL,
    generated_at INTEGER NOT NULL,
    ip TEXT NOT NULL,
    score INTEGER NOT NULL,
    own_score INTEGER NOT NULL,
    level TEXT NOT NULL,
    class TEXT NOT NULL,
    bot TEXT,
    requests INTEGER NOT NULL,
    shared INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    PRIMARY KEY (site, generated_at, ip)
) WITHOUT ROWID;
CREATE INDEX log_verdicts_score ON log_verdicts (site, generated_at, score DESC, ip);
CREATE INDEX log_verdicts_generated ON log_verdicts (generated_at);
