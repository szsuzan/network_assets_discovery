-- Align the users.role column default with the scanner rename.
-- 017 migrates existing rows; this fixes the DEFAULT for both fresh installs
-- (which replay 001 with the historical default and then reach here) and
-- existing databases that still carry DEFAULT 'pentester' from 001.

ALTER TABLE users ALTER COLUMN role SET DEFAULT 'scanner';