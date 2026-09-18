-- Scan name: optional human-friendly label for a scan, used in the scans list
-- and the scan-comparison pickers (falls back to profile + date when empty).

ALTER TABLE scans ADD COLUMN IF NOT EXISTS name TEXT;