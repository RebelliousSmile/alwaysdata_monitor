-- Registre des capacités (#4) : constats d'un rapport d'agent écartés hors du
-- registre (famille inconnue ou non admise pour le CMS du site), et raison de
-- la clôture d'un incident. NULL : rétabli ; 'unwatched' : contrôle plus
-- surveillé (site, typologie ou clé d'agent changés), jamais « rétabli ».
ALTER TABLE reports ADD COLUMN dropped INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN close_reason TEXT
    CHECK (close_reason IS NULL OR close_reason = 'unwatched');
