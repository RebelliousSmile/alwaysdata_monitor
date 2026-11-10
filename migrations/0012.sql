-- Pagination par clé des incidents clos d'un site (`/api/v1`, issue #5) :
-- `ORDER BY closed_at DESC, id DESC` à partir d'un curseur, sans tri.
CREATE INDEX incidents_site_closed ON incidents (site, closed_at, id);
