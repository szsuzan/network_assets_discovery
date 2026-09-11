-- CVE catalog (offline NVD import) + per-port CPE capture.
-- Findings engine matches fingerprinted port CPEs against this catalog to
-- produce known_vulnerability findings without any network call at analysis
-- time.

ALTER TABLE ports ADD COLUMN IF NOT EXISTS cpes TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS cve_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL UNIQUE,
    title TEXT,
    description TEXT,
    severity TEXT,
    cwe TEXT,
    cvss_score DOUBLE PRECISION,
    cvss_vector TEXT,
    reference_urls JSONB NOT NULL DEFAULT '[]',
    source TEXT,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_catalog_cpe (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id UUID REFERENCES cve_catalog(id) ON DELETE CASCADE NOT NULL,
    part TEXT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    version_start_including TEXT,
    version_end_including TEXT,
    version_start_excluding TEXT,
    version_end_excluding TEXT,
    match_all BOOLEAN NOT NULL DEFAULT false,
    cpe23 TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_catalog_cpe_match
    ON cve_catalog_cpe (part, vendor, product);
CREATE INDEX IF NOT EXISTS idx_cve_catalog_cve
    ON cve_catalog_cpe (cve_id);