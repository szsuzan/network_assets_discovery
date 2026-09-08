-- 002_findings_workflow.sql
-- Findings workflow + NSE evidence fields. Idempotent; safe to re-run.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_vector text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score double precision;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS notes text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence jsonb;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_status ON findings(scan_id, status);

-- Audit trail for analyst changes to findings (status, report inclusion,
-- severity / CVSS overrides). Inserted by the PATCH endpoint.
CREATE TABLE IF NOT EXISTS finding_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id uuid REFERENCES users(id),
    action text NOT NULL,
    field text,
    old_value text,
    new_value text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_audit_finding ON finding_audit(finding_id, created_at);