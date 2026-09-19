-- 001_init.sql — SubNex final v1 schema (single-file, squashed from 001-018).
--
-- This is the ONE migration a fresh install needs. It creates every table in
-- its final state (later ALTERs from the historical migration chain are folded
-- in) plus the default runtime settings. Idempotent: every object is guarded
-- with IF NOT EXISTS so re-running is safe.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-------------------------------------------------------------- users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'scanner',
    created_at TIMESTAMPTZ DEFAULT now(),
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    jwt_version INTEGER NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-------------------------------------------------------------- engagements
CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_name TEXT NOT NULL,
    engagement_name TEXT NOT NULL,
    authorized_scope TEXT[] NOT NULL,
    start_date DATE,
    end_date DATE,
    status TEXT NOT NULL DEFAULT 'active',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT now()
);

-------------------------------------------------------------- scans
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) NOT NULL,
    targets TEXT[] NOT NULL,
    profile TEXT NOT NULL,
    port_range TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    status TEXT NOT NULL DEFAULT 'queued',
    kind TEXT NOT NULL DEFAULT 'discover',
    mode TEXT NOT NULL DEFAULT 'standard',
    name TEXT,
    risk_rules jsonb NOT NULL DEFAULT '{}'::jsonb,
    reverify_started_at timestamptz,
    total_paused_seconds integer NOT NULL DEFAULT 0,
    pass_history jsonb NOT NULL DEFAULT '[]'::jsonb,
    hosts_total_in_scope INT DEFAULT 0,
    hosts_discovered INT DEFAULT 0,
    progress_pct INT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    started_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT now()
);

-------------------------------------------------------------- hosts
CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    ip INET NOT NULL,
    mac MACADDR,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,
    os_guess TEXT,
    os_confidence INT,
    status TEXT NOT NULL,
    discovery_method TEXT[],
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    notes TEXT DEFAULT '',
    tags TEXT[] DEFAULT '{}',
    secondary_ips INET[] NOT NULL DEFAULT '{}',
    macs TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE(scan_id, ip)
);

-------------------------------------------------------------- ports
CREATE TABLE IF NOT EXISTS ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE NOT NULL,
    port INT NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT,
    cpes TEXT[] NOT NULL DEFAULT '{}'
);

-------------------------------------------------------------- snmp_info
CREATE TABLE IF NOT EXISTS snmp_info (
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE PRIMARY KEY,
    sys_descr TEXT,
    sys_name TEXT,
    sys_location TEXT,
    sys_objectid TEXT,
    sys_uptime TEXT,
    default_community_found BOOLEAN DEFAULT false
);

-------------------------------------------------------------- findings
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    cve_refs TEXT[],
    port INT,
    included_in_report BOOLEAN DEFAULT true,
    status TEXT NOT NULL DEFAULT 'open',
    cvss_vector text,
    cvss_score double precision,
    cwe text,
    notes text,
    evidence jsonb,
    updated_at timestamptz
);

-------------------------------------------------------------- finding_audit
CREATE TABLE IF NOT EXISTS finding_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id uuid REFERENCES users(id),
    action text NOT NULL,
    field text,
    old_value text,
    new_value text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-------------------------------------------------------------- topology_edges
CREATE TABLE IF NOT EXISTS topology_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    source_ip INET NOT NULL,
    target_ip INET NOT NULL,
    edge_type TEXT NOT NULL
);

-------------------------------------------------------------- audit_log
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    engagement_id UUID REFERENCES engagements(id),
    scan_id UUID REFERENCES scans(id),
    action TEXT NOT NULL,
    detail JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

-------------------------------------------------------------- webhooks
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

-------------------------------------------------------------- system_settings
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

-------------------------------------------------------------- agents
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    api_key_hash TEXT NOT NULL,
    created_by UUID REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'offline',
    last_seen TIMESTAMPTZ,
    version TEXT,
    hostname TEXT,
    os TEXT,
    subnets TEXT[] DEFAULT '{}',
    capabilities TEXT[] DEFAULT '{}',
    notes TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT now()
);

-------------------------------------------------------------- agent_tasks
CREATE TABLE IF NOT EXISTS agent_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    agent_id UUID REFERENCES agents(id) NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    targets TEXT[] DEFAULT '{}',
    claimed_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT,
    result JSON,
    created_at TIMESTAMPTZ DEFAULT now()
);

-------------------------------------------------------------- cve_catalog
CREATE TABLE IF NOT EXISTS cve_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT NOT NULL UNIQUE,
    title TEXT,
    description TEXT,
    severity TEXT,
    cwe TEXT,
    cvss_score DOUBLE PRECISION,
    cvss_vector TEXT,
    reference_urls JSONB NOT NULL DEFAULT '[]',
    source TEXT,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_catalog_cpe (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id UUID REFERENCES cve_catalog(id) ON DELETE CASCADE NOT NULL,
    part TEXT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    version_start_including TEXT,
    version_end_including TEXT,
    version_start_excluding TEXT,
    version_end_excluding TEXT,
    match_all BOOLEAN NOT NULL DEFAULT false,
    cpe23 TEXT
);

-------------------------------------------------------------- deletion_requests
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

-------------------------------------------------------------- indexes
CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_status ON findings(scan_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_audit_finding ON finding_audit(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_topology_scan_id ON topology_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_engagement_id ON audit_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_scan_id ON audit_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_scan ON agent_tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_cve_catalog_cpe_match ON cve_catalog_cpe (part, vendor, product);
CREATE INDEX IF NOT EXISTS idx_cve_catalog_cve ON cve_catalog_cpe (cve_id);