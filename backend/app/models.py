from sqlalchemy import Column, String, DateTime, Boolean, Integer, Uuid, ForeignKey, Text, func, JSON, Float
from sqlalchemy.dialects.postgresql import ARRAY, INET, MACADDR, JSONB
from sqlalchemy.orm import relationship
from .database import Base
import uuid

class User(Base):
    __tablename__ = "users"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    email = Column(Text, unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role = Column(Text, nullable=False, default="pentester")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Engagement(Base):
    __tablename__ = "engagements"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    client_name = Column(Text, nullable=False)
    engagement_name = Column(Text, nullable=False)
    authorized_scope = Column(ARRAY(Text), nullable=False)
    start_date = Column(DateTime(timezone=True))
    end_date = Column(DateTime(timezone=True))
    status = Column(Text, nullable=False, default="active")
    created_by = Column(Uuid, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="engagement", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    engagement_id = Column(Uuid, ForeignKey("engagements.id"), nullable=False)
    targets = Column(ARRAY(Text), nullable=False)
    profile = Column(Text, nullable=False)
    port_range = Column(Text, nullable=False)
    protocol = Column(Text, nullable=False, default="tcp")
    status = Column(Text, nullable=False, default="queued")
    kind = Column(Text, nullable=False, default="discover")  # discover|reverify
    risk_rules = Column(JSONB, nullable=False, default=dict, server_default="{}")
    hosts_total_in_scope = Column(Integer, default=0)
    hosts_discovered = Column(Integer, default=0)
    progress_pct = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True))
    reverify_started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    total_paused_seconds = Column(Integer, nullable=False, default=0)
    # Per-pass history for the UI (initial + re-verify passes with their own
    # started/completed, duration, and committed host/port counts).
    pass_history = Column(JSONB, nullable=False, default=list, server_default="[]")
    verified_at = Column(DateTime(timezone=True))
    started_by = Column(Uuid, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    engagement = relationship("Engagement", back_populates="scans")
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    topology_edges = relationship("TopologyEdge", back_populates="scan", cascade="all, delete-orphan")

class Host(Base):
    __tablename__ = "hosts"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id = Column(Uuid, ForeignKey("scans.id"), nullable=False)
    ip = Column(INET, nullable=False)
    mac = Column(MACADDR)
    vendor = Column(Text)
    hostname = Column(Text)
    device_type = Column(Text)
    os_guess = Column(Text)
    os_confidence = Column(Integer)
    status = Column(Text, nullable=False)
    discovery_method = Column(ARRAY(Text))
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text, default="")
    tags = Column(ARRAY(Text), default=[])

    scan = relationship("Scan", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    snmp = relationship("SNMPInfo", back_populates="host", uselist=False, cascade="all, delete-orphan")

class Port(Base):
    __tablename__ = "ports"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    host_id = Column(Uuid, ForeignKey("hosts.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(Text, nullable=False)
    state = Column(Text, nullable=False)
    service = Column(Text)
    version = Column(Text)
    banner = Column(Text)

    host = relationship("Host", back_populates="ports")

class SNMPInfo(Base):
    __tablename__ = "snmp_info"
    host_id = Column(Uuid, ForeignKey("hosts.id"), nullable=False, primary_key=True)
    sys_descr = Column(Text)
    sys_name = Column(Text)
    sys_location = Column(Text)
    sys_objectid = Column(Text)
    sys_uptime = Column(Text)
    default_community_found = Column(Boolean, default=False)

    host = relationship("Host", back_populates="snmp")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id = Column(Uuid, ForeignKey("scans.id"), nullable=False)
    host_id = Column(Uuid, ForeignKey("hosts.id"))
    severity = Column(Text, nullable=False)
    type = Column(Text, nullable=False)
    title = Column(Text, nullable=False)
    description = Column(Text)
    recommendation = Column(Text)
    cve_refs = Column(ARRAY(Text))
    port = Column(Integer)
    included_in_report = Column(Boolean, default=True)
    # -- findings workflow ------------------------------------------------
    status = Column(Text, nullable=False, default="open")
    cvss_vector = Column(Text)
    cvss_score = Column(Float)
    cwe = Column(Text)
    notes = Column(Text)
    evidence = Column(JSON)
    updated_at = Column(DateTime(timezone=True))

    scan = relationship("Scan", back_populates="findings")

class FindingAudit(Base):
    __tablename__ = "finding_audit"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    finding_id = Column(Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Uuid, ForeignKey("users.id"))
    action = Column(Text, nullable=False)
    field = Column(Text)
    old_value = Column(Text)
    new_value = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Webhook(Base):
    __tablename__ = "webhooks"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False)
    url = Column(Text, nullable=False)
    secret = Column(Text)
    events = Column(ARRAY(Text), nullable=False, default=["finding_created", "finding_updated"])
    enabled = Column(Boolean, nullable=False, default=True)
    created_by = Column(Uuid, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_triggered_at = Column(DateTime(timezone=True))
    last_status = Column(Integer)
    last_error = Column(Text)

class TopologyEdge(Base):
    __tablename__ = "topology_edges"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id = Column(Uuid, ForeignKey("scans.id"), nullable=False)
    source_ip = Column(INET, nullable=False)
    target_ip = Column(INET, nullable=False)
    edge_type = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="topology_edges")

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id"))
    engagement_id = Column(Uuid, ForeignKey("engagements.id"))
    scan_id = Column(Uuid, ForeignKey("scans.id"))
    action = Column(Text, nullable=False)
    detail = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Agent(Base):
    """A scanner agent: a process placed on a machine with Layer-2 access to a
    target LAN. Runs discovery/ports/fingerprint locally (ARP -> MAC/vendor,
    SYN + -O -> exact OS) and reports results back to the server over HTTPS.

    This replaces the SSH host-nmap bridge as the primary L2 executor so the
    app no longer depends on a remote shell on a specific machine.
    """
    __tablename__ = "agents"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    name = Column(Text, nullable=False, unique=True)
    api_key_hash = Column(Text, nullable=False)
    created_by = Column(Uuid, ForeignKey("users.id"))
    status = Column(Text, nullable=False, default="offline")  # online|offline|disabled
    last_seen = Column(DateTime(timezone=True))
    version = Column(Text)
    hostname = Column(Text)
    os = Column(Text)
    subnets = Column(ARRAY(Text), default=[])  # locally-attached subnets it can ARP
    capabilities = Column(ARRAY(Text), default=[])  # e.g. ["arp","syn","nse","snmp"]
    notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class SystemSetting(Base):
    """Global application settings (scan defaults, agent delegation, re-scan
    behaviour, Nmap/NSE/SNMP knobs) editable from the Settings page.

    Every key is defined in the settings catalog (services/settings.py) with a
    default; rows here override the catalog default at runtime.
    """
    __tablename__ = "system_settings"
    key = Column(Text, primary_key=True)
    value = Column(JSONB, nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class AgentTask(Base):
    """A scan job claimed and executed by a scanner agent."""
    __tablename__ = "agent_tasks"
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id = Column(Uuid, ForeignKey("scans.id"), nullable=False)
    agent_id = Column(Uuid, ForeignKey("agents.id"), nullable=False)
    status = Column(Text, nullable=False, default="queued")  # queued|claimed|running|succeeded|failed
    targets = Column(ARRAY(Text), default=[])
    claimed_at = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error = Column(Text)
    result = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan")
    agent = relationship("Agent")
