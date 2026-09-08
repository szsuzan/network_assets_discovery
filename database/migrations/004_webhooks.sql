-- 004: Webhook integrations for alerting on finding lifecycle events.
-- Delivery is best-effort: each webhook records its last trigger/error so the
-- Integrations page can surface failures.
CREATE TABLE IF NOT EXISTS webhooks (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name               text NOT NULL,
    url                text NOT NULL,
    secret             text,
    events             text[] NOT NULL DEFAULT ARRAY['finding_created', 'finding_updated'],
    enabled            boolean NOT NULL DEFAULT true,
    created_by         uuid REFERENCES users(id),
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_triggered_at  timestamptz,
    last_status        integer,
    last_error         text
);