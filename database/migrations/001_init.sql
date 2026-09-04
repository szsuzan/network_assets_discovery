CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'pentester',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE engagements (
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

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) NOT NULL,
    targets TEXT[] NOT NULL,
    profile TEXT NOT NULL,
    port_range TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    status TEXT NOT NULL DEFAULT 'queued',
    kind TEXT NOT NULL DEFAULT 'discover',
    hosts_total_in_scope INT DEFAULT 0,
    hosts_discovered INT DEFAULT 0,
    progress_pct INT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    started_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE hosts (
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
    UNIQUE(scan_id, ip)
);

CREATE TABLE ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE NOT NULL,
    port INT NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT
);

CREATE TABLE snmp_info (
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE PRIMARY KEY,
    sys_descr TEXT,
    sys_name TEXT,
    sys_location TEXT,
    sys_objectid TEXT,
    sys_uptime TEXT,
    default_community_found BOOLEAN DEFAULT false
);

CREATE TABLE findings (
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
    included_in_report BOOLEAN DEFAULT true
);

CREATE TABLE topology_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    source_ip INET NOT NULL,
    target_ip INET NOT NULL,
    edge_type TEXT NOT NULL
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    engagement_id UUID REFERENCES engagements(id),
    scan_id UUID REFERENCES scans(id),
    action TEXT NOT NULL,
    detail JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX idx_ports_host_id ON ports(host_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_topology_scan_id ON topology_edges(scan_id);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_engagement_id ON audit_log(engagement_id);
CREATE INDEX idx_audit_log_scan_id ON audit_log(scan_id);
