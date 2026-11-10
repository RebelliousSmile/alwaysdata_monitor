-- Rapprochement inventaire × failles (#21, F7, `vulns/matching/`), toutes
-- clés par source d'inventaire (`agent`, `ci`). Dates en secondes Unix.
--
-- `vuln_match_runs` : séquence globale des runs (AUTOINCREMENT : un id n'est
-- jamais redonné, deux `tick` ne réservent jamais le même). Un run est
-- écrit par lots, puis basculé en compare-and-swap dans `vuln_match_state` :
-- un lecteur ne lit que l'`active_run`, jamais un run partiel.
CREATE TABLE vuln_match_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('agent', 'ci')),
    started_at INTEGER NOT NULL
);
-- État comparé de chaque (site, source) : ce qui a été rapproché, et ce
-- qui rend le site dû quand il change. Les champs de site (sources
-- déclarées, époque des dérogations, échéances) sont répétés sur chaque
-- source du site.
CREATE TABLE vuln_match_state (
    site TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('agent', 'ci')),
    inventory_id INTEGER,
    seen_at INTEGER,
    declared_sources TEXT NOT NULL DEFAULT '',
    match_epoch TEXT,
    enrich_epoch TEXT,
    waiver_epoch TEXT,
    next_stale_check INTEGER,
    next_waiver_check INTEGER,
    active_run INTEGER,
    pending_run INTEGER,
    pending_inventory_id INTEGER,
    pending_match_epoch TEXT,
    pending_enrich_epoch TEXT,
    cursor_rowid INTEGER NOT NULL DEFAULT 0,
    due_since INTEGER,
    error_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (site, source)
) WITHOUT ROWID;
-- Composants d'un run : purl sans version (`base`), chemin, version vue,
-- reporté depuis le run précédent (`carried`), au moins une faille candidate
-- (`candidates`), première et dernière vue, gravité la plus haute et son
-- rang (0 sans faille, 1 information, 2 avertissement, 3 critique).
CREATE TABLE vuln_match_components (
    site TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('agent', 'ci')),
    run INTEGER NOT NULL,
    base TEXT NOT NULL,
    path TEXT NOT NULL,
    version TEXT,
    ecosystem TEXT NOT NULL,
    scope TEXT NOT NULL,
    carried INTEGER NOT NULL DEFAULT 0,
    candidates INTEGER NOT NULL DEFAULT 0,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    severity TEXT CHECK (severity IS NULL OR severity IN ('info', 'warning', 'critical')),
    rank INTEGER NOT NULL DEFAULT 0 CHECK (rank BETWEEN 0 AND 3),
    groups INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (site, source, run, base, path)
) WITHOUT ROWID;
CREATE INDEX vuln_match_components_page
    ON vuln_match_components (site, run, rank, base, path);
-- Groupes touchés ou inconnus d'un composant : membres (identifiant,
-- source, plage corrigée ; jamais d'attribution), faits gardés pour la
-- réévaluation sans plage (`facts`, JSON), identifiants couverts.
CREATE TABLE vuln_match_items (
    site TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('agent', 'ci')),
    run INTEGER NOT NULL,
    base TEXT NOT NULL,
    path TEXT NOT NULL,
    group_key TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('affected', 'unknown')),
    reason TEXT CHECK (reason IS NULL OR reason IN ('version_unknown', 'range_unknown')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    rank INTEGER NOT NULL CHECK (rank BETWEEN 1 AND 3),
    rule TEXT NOT NULL,
    fixed TEXT,
    members TEXT NOT NULL,
    facts TEXT NOT NULL,
    covered_ids TEXT NOT NULL,
    kev INTEGER NOT NULL DEFAULT 0,
    epss_ppm INTEGER,
    score_tenths INTEGER,
    redistribution TEXT NOT NULL CHECK (redistribution IN ('internal', 'facts_only', 'free')),
    PRIMARY KEY (site, source, run, base, path, group_key)
) WITHOUT ROWID;
CREATE INDEX vuln_match_items_page
    ON vuln_match_items (site, run, rank, base, path, group_key);
-- Provenance d'un purl sans version ayant au moins une faille candidate :
-- les sources qui l'ont vu. Survit à la disparition du composant ; purgée à
-- la clôture de l'incident, à la péremption ou par `site remove`.
CREATE TABLE vuln_match_seen (
    site TEXT NOT NULL,
    key TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('agent', 'ci')),
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (site, key, source)
) WITHOUT ROWID;
-- Date où un incident ouvert a perdu sa dernière vue (aucun run actif ne
-- voit plus le composant) ; posée par `site remove` à la date du retrait.
CREATE TABLE vuln_match_keys (
    site TEXT NOT NULL,
    key TEXT NOT NULL,
    lost_view_at INTEGER,
    PRIMARY KEY (site, key)
) WITHOUT ROWID;
-- Dérogations : par site, source, purl sans version, faille et version ;
-- motif de 1 à 500 caractères, 90 jours au plus ; audit par empreinte du
-- motif dans la chaîne du site (`audit_hash` : tête après l'entrée).
CREATE TABLE vuln_waivers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('agent', 'ci')),
    base TEXT NOT NULL CHECK (length(base) BETWEEN 1 AND 256),
    advisory_ref TEXT NOT NULL CHECK (length(advisory_ref) BETWEEN 1 AND 64),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 256),
    covered_ids TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    until INTEGER NOT NULL,
    operator TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoke_reason TEXT CHECK (revoke_reason IS NULL OR length(revoke_reason) BETWEEN 1 AND 500),
    audit_hash TEXT NOT NULL,
    CHECK (until > created_at AND until - created_at <= 90 * 86400)
);
CREATE INDEX vuln_waivers_site ON vuln_waivers (site, base);
