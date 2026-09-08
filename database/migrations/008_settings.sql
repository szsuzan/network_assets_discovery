-- Global application Settings (scan defaults, agent delegation, re-scan
-- behaviour, Nmap/NSE/SNMP knobs) editable from the Settings page.
-- Every key is defined in backend/app/services/settings.py; the values seeded
-- here match the runtime defaults that were previously hardcoded constants.
-- Applied automatically in order by the migration runner at backend startup.
CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value) VALUES
    ('scan.default_profile',             '"quick"'::jsonb),
    ('scan.default_port_range',          '"1-10000"'::jsonb),
    ('scan.default_protocol',            '"tcp"'::jsonb),
    ('execution.phase2_concurrency',     '10'::jsonb),
    ('execution.phase2_min_rate',        '500'::jsonb),
    ('execution.phase2_host_timeout',    '75'::jsonb),
    ('execution.fingerprint_host_timeout', '300'::jsonb),
    ('execution.tcp_probe_timeout',      '1.0'::jsonb),
    ('agent.delegation_enabled',         'true'::jsonb),
    ('agent.online_window_seconds',      '90'::jsonb),
    ('agent.workers',                    '5'::jsonb),
    ('reverify.recheck_down_hosts',      'true'::jsonb),
    ('reverify.sweep_remaining_ports',   'true'::jsonb),
    ('reverify.min_interval_seconds',    '0'::jsonb),
    ('nmap.port_scripts',                '{}'::jsonb),
    ('nmap.snmp_community',              '"public"'::jsonb),
    ('nmap.snmp_timeout',                '3.0'::jsonb)
ON CONFLICT (key) DO NOTHING;