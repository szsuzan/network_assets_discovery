-- Scanner agents + agent task queue. Executed by scanner agents placed on a
-- target LAN (ARP -> MAC/vendor, SYN + -O -> exact OS); results are submitted
-- back to the API. Previously these tables were only created by create_all.
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

CREATE INDEX IF NOT EXISTS idx_agent_tasks_scan ON agent_tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent_id, status);