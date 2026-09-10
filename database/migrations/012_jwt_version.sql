-- Token revocation: bumping a user's jwt_version invalidates every JWT issued
-- against an older version (used after a password change).
ALTER TABLE users ADD COLUMN IF NOT EXISTS jwt_version INTEGER NOT NULL DEFAULT 0;