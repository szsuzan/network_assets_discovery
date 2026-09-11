from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime, date
import uuid
import re

PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    must_change_password: bool = False

class LoginRequest(BaseModel):
    email: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True

class EngagementCreate(BaseModel):
    client_name: str
    engagement_name: str
    authorized_scope: List[str]
    start_date: Optional[date] = None
    end_date: Optional[date] = None

class EngagementUpdate(BaseModel):
    client_name: Optional[str] = None
    engagement_name: Optional[str] = None
    authorized_scope: Optional[List[str]] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None

class EngagementOut(BaseModel):
    id: uuid.UUID
    client_name: str
    engagement_name: str
    authorized_scope: List[str]
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: str
    created_by: Optional[uuid.UUID] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ScanCreate(BaseModel):
    targets: List[str]
    profile: Optional[str] = Field(default=None, pattern="^(quick|full|stealth|passive_only)$")
    port_range: Optional[str] = None
    protocol: Optional[str] = Field(default=None, pattern="^(tcp|udp)$")

    @field_validator("port_range")
    @classmethod
    def _port_range_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = "".join(v.split()) if isinstance(v, str) else v
        if not PORT_RANGE_RE.match(v):
            raise ValueError("port_range must be nmap-style ranges, e.g. '1-1000' or '22,80,443-445'")
        for part in v.split(","):
            lo, _, hi = part.partition("-")
            lo_v = int(lo)
            if not (0 < lo_v <= 65535):
                raise ValueError("port numbers must be between 1 and 65535")
            if hi:
                hi_v = int(hi)
                if not (0 < hi_v <= 65535) or hi_v < lo_v:
                    raise ValueError("invalid port range bounds")
        return v

    @field_validator("targets")
    @classmethod
    def _targets_nonempty(cls, v: List[str]) -> List[str]:
        cleaned = [t.strip() for t in v if t and t.strip()]
        if not cleaned:
            raise ValueError("At least one target (IP or CIDR) is required")
        return cleaned

class ReverifyIn(BaseModel):
    """Optional controls for a re-verify scan of a previously-completed scan.

    If port_range is omitted, the residual sweep covers all TCP ports the
    original scan did not already check (computed from the stored scan range).
    """
    port_range: Optional[str] = None
    recheck_down_hosts: Optional[bool] = None
    sweep_remaining_ports: Optional[bool] = None

    @field_validator("port_range")
    @classmethod
    def _port_range_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = "".join(v.split()) if isinstance(v, str) else v
        if not PORT_RANGE_RE.match(v):
            raise ValueError("port_range must be nmap-style ranges, e.g. '1-1000' or '22,80,443-445'")
        for part in v.split(","):
            lo, _, hi = part.partition("-")
            lo_v = int(lo)
            if not (0 < lo_v <= 65535):
                raise ValueError("port numbers must be between 1 and 65535")
            if hi:
                hi_v = int(hi)
                if not (0 < hi_v <= 65535) or hi_v < lo_v:
                    raise ValueError("invalid port range bounds")
        return v

class SettingOut(BaseModel):
    key: str
    category: str
    category_label: str
    label: str
    description: str
    type: str
    value: object
    default: object
    options: Optional[List[str]] = None

class ScanOut(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    targets: List[str]
    profile: str
    port_range: str
    protocol: str
    status: str
    kind: str = "discover"
    hosts_total_in_scope: int
    hosts_discovered: int
    progress_pct: int
    started_at: Optional[datetime] = None
    reverify_started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_paused_seconds: int = 0
    open_ports_count: int = 0
    pass_history: List[dict] = []
    started_by: Optional[uuid.UUID] = None
    verified_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class HostOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    ip: object
    secondary_ips: Optional[List[str]] = None
    mac: Optional[str] = None
    macs: Optional[List[str]] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    os_confidence: Optional[int] = None
    status: str
    discovery_method: Optional[List[str]] = None
    first_seen: datetime
    last_seen: datetime
    notes: str
    tags: Optional[List[str]] = None

    @field_validator("secondary_ips", "macs", mode="before")
    @classmethod
    def _stringify_array(cls, v):
        if v is None:
            return None
        return [str(x) for x in v]

    class Config:
        from_attributes = True

class PortOut(BaseModel):
    id: uuid.UUID
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    class Config:
        from_attributes = True

class HostDetail(HostOut):
    ports: List[PortOut] = []
    snmp: Optional[dict] = None

class HostPatch(BaseModel):
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    os_confidence: Optional[int] = None

class TopologyOut(BaseModel):
    nodes: List[dict]
    edges: List[dict]

class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    host_id: Optional[uuid.UUID] = None
    host_ip: Optional[str] = None
    host_hostname: Optional[str] = None
    host_device_type: Optional[str] = None
    host_mac: Optional[str] = None
    severity: str
    type: str
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    cve_refs: Optional[List[str]] = None
    port: Optional[int] = None
    included_in_report: bool
    status: str
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    notes: Optional[str] = None
    evidence: Optional[dict] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class FindingPatch(BaseModel):
    included_in_report: Optional[bool] = None
    recommendation: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    notes: Optional[str] = None

class FindingAuditOut(BaseModel):
    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    action: str
    field: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class RiskRuleOut(BaseModel):
    key: str
    label: str
    description: Optional[str] = None
    kind: str
    default_severity: str
    enabled: bool
    severity: Optional[str] = None  # operator override, or None for default

class RiskRulePatch(BaseModel):
    key: str
    enabled: Optional[bool] = None
    severity: Optional[str] = None  # null / "" resets to rule default

class WebhookOut(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    events: List[str]
    enabled: bool
    created_at: datetime
    last_triggered_at: Optional[datetime] = None
    last_status: Optional[int] = None
    last_error: Optional[str] = None

    class Config:
        from_attributes = True

class WebhookCreate(BaseModel):
    name: str
    url: str
    secret: Optional[str] = None
    events: List[str] = ["finding_created", "finding_updated"]
    enabled: bool = True

class WebhookPatch(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    secret: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None

class AuditLogOut(BaseModel):
    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    engagement_id: Optional[uuid.UUID] = None
    scan_id: Optional[uuid.UUID] = None
    action: str
    detail: Optional[dict] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ChangedFindings(BaseModel):
    new: List[dict]
    resolved: List[dict]

class DiffResult(BaseModel):
    new_hosts: List[dict]
    missing_hosts: List[dict]
    changed_ports: List[dict]
    changed_findings: ChangedFindings

# --------------------------------------------------------------------------- #
# Scanner agents
# --------------------------------------------------------------------------- #
class AgentCreate(BaseModel):
    name: str
    subnets: List[str] = []
    notes: str = ""

class AgentOut(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    last_seen: Optional[datetime] = None
    version: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    subnets: List[str] = []
    capabilities: List[str] = []
    notes: str = ""
    created_at: datetime

    class Config:
        from_attributes = True

class AgentKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    api_key: str

class AgentHeartbeatIn(BaseModel):
    version: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    subnets: List[str] = []
    capabilities: List[str] = []

class AgentTaskOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    status: str
    targets: List[str]
    profile: str
    port_range: str
    protocol: str
    kind: str = "discover"
    reverify: Optional[dict] = None
    workers: Optional[int] = None

class AgentLogIn(BaseModel):
    line: str
    level: str = "info"

class AgentPortIn(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

class AgentSnmpIn(BaseModel):
    sys_descr: Optional[str] = None
    sys_name: Optional[str] = None
    sys_location: Optional[str] = None
    sys_objectid: Optional[str] = None
    default_community_found: bool = False

class AgentHostIn(BaseModel):
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    os_confidence: Optional[int] = None
    status: str = "up"
    ports: List[AgentPortIn] = []
    snmp: Optional[AgentSnmpIn] = None

class AgentResultIn(BaseModel):
    status: str = "completed"  # completed|failed|partial
    error: Optional[str] = None
    hosts: List[AgentHostIn] = []
    notes: str = ""
    # Exact phase-based progress (0-100) reported by the agent so the backend
    # never recomputes it from a single batch (which made it regress, 30% -> 20%).
    progress: Optional[float] = None
