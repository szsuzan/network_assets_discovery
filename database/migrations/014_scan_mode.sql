-- Scan mode: standard (full port scan + fingerprint + findings) vs discovery
-- (ARP + passive + mDNS host inventory only, no port scan / findings / report).

ALTER TABLE scans ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'standard';
