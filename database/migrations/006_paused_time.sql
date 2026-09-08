-- Total idle (paused) seconds accumulated between re-verify passes, so the
-- UI can show active run time (total - paused) instead of wall-clock time.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS total_paused_seconds integer NOT NULL DEFAULT 0;