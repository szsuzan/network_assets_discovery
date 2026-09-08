-- Per-pass history (initial discover + re-verify passes) so the UI can show
-- the value differences between passes (hosts / ports / duration per pass).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS pass_history jsonb NOT NULL DEFAULT '[]'::jsonb;