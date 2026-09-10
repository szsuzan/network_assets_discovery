-- Password-change enforcement: after a forced password change on first login,
-- the flag flips to false so normal API access resumes.
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- Existing installs already hold the auto-seeded demo account, so it must also
-- be forced through the change-password flow on its next login.
UPDATE users SET must_change_password = true WHERE email = 'demo@pentest.local';