-- 003: Per-scan risk rule overrides (enable/disable + severity tuning).
-- The catalog itself is code-defined (app/services/risk_rules.py); this column
-- stores only the overrides the operator has applied for a given scan.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS risk_rules jsonb NOT NULL DEFAULT '{}'::jsonb;