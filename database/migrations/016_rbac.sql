-- RBAC hardening:
--   * users.active flag -> admins can disable an account without deleting it
--     (disabled accounts can no longer log in or use a bearer token).
--   * deletion_requests -> admin-approval queue used by scanners who want an
--     engagement or scan removed.

ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS deletion_requests (
    id UUID PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id UUID NOT NULL,
    target_label TEXT NOT NULL,
    parent_label TEXT,
    reason TEXT,
    requested_by UUID NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id),
    resolver_comment TEXT
);