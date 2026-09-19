"""Best-effort webhook delivery for scan lifecycle events.

Delivers JSON payloads to every enabled webhook subscribed to the event, signed
with the webhook's shared secret via an HMAC-SHA256 signature header when one is
configured. Failures never propagate to callers — each webhook's last delivery
result is persisted for the Integrations UI.
"""
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Host, Port, Webhook

logger = logging.getLogger(__name__)

EVENT_CREATED = "finding_created"
EVENT_UPDATED = "finding_updated"
EVENT_SCAN_COMPLETED = "scan_completed"
EVENT_HOST_DISCOVERED = "host_discovered"


class _ValidatingRedirectHandler(HTTPRedirectHandler):
    """Reject any redirect hop that would smuggle the request onto a
    private/loopback address (SSRF via redirect chains)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        target = newurl
        location = headers.get("Location")
        if location:
            from urllib.parse import urljoin
            target = urljoin(req.full_url, location)
        try:
            validate_webhook_url(target)
        except ValueError as e:
            self.parent.error = getattr(self.parent, "error", None)
            raise URLError(f"redirect {code} to {target} blocked: {e}") from None
        return super().redirect_request(req, fp, code, msg, headers, target)


def _webhook_opener():
    return build_opener(_ValidatingRedirectHandler())


def validate_webhook_url(url: str) -> str:
    """Reject webhook URLs that could be used for SSRF.

    Only http/https schemes are accepted, and the host must resolve to a public
    (non-private, non-loopback, non-link-local, non-multicast) address on every
    resolved IP. Loopback/localhost is deliberately rejected too, so webhooks
    cannot be pointed at services running on the SubNex host itself. Redirect
    targets are re-validated at delivery time (_ValidatingRedirectHandler).
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https")
    host = parsed.hostname
    if not host:
        raise ValueError("Webhook URL must include a host")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        raise ValueError("Webhook URL host could not be resolved") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_unspecified or ip.is_reserved):
            raise ValueError("Webhook URL must point to a public address")
    return url


def engagement_brief(engagement) -> dict:
    return {
        "id": str(engagement.id) if engagement else None,
        "client_name": getattr(engagement, "client_name", None),
        "engagement_name": getattr(engagement, "engagement_name", None),
    }


def scan_brief(scan) -> dict:
    return {
        "id": str(scan.id) if scan else None,
        "kind": getattr(scan, "kind", None),
        "profile": getattr(scan, "profile", None),
        "mode": getattr(scan, "mode", None),
        "protocol": getattr(scan, "protocol", None),
        "targets": getattr(scan, "targets", None) or [],
        "port_range": getattr(scan, "port_range", None),
    }


def host_brief(host) -> dict:
    return {
        "ip": str(host.ip),
        "mac": str(host.mac) if getattr(host, "mac", None) else None,
        "macs": list(getattr(host, "macs", None) or []),
        "vendor": host.vendor,
        "hostname": host.hostname,
        "device_type": host.device_type,
        "os_guess": host.os_guess,
        "status": host.status,
        "discovery_method": list(host.discovery_method or []),
    }


def finding_payload(finding, host=None, scan=None, engagement=None, actor=None) -> dict:
    return {
        "finding": {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "type": finding.type,
            "port": finding.port,
            "cwe": finding.cwe,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "cve_refs": finding.cve_refs or [],
            "included_in_report": finding.included_in_report,
            "notes": finding.notes,
        },
        "host": {
            "ip": str(host.ip) if host else None,
            "mac": str(host.mac) if host and host.mac else None,
            "vendor": host.vendor if host else None,
            "hostname": host.hostname if host else None,
            "device_type": host.device_type if host else None,
            "os_guess": host.os_guess if host else None,
        } if host else None,
        "scan": scan_brief(scan) if scan else None,
        "engagement": engagement_brief(engagement) if engagement else None,
        "actor": {"email": actor.email, "role": actor.role} if actor else None,
    }


def scan_completed_payload(db: Session, scan, engagement=None) -> dict:
    """Summary payload emitted when a scan (or re-verify pass) finishes."""
    n_hosts = n_up = n_ports = 0
    try:
        base = select(func.count()).select_from(Host).where(Host.scan_id == scan.id)
        n_hosts = db.execute(base).scalar_one()
        n_up = db.execute(base.where(Host.status == "up")).scalar_one()
        n_ports = db.execute(
            select(func.count())
            .select_from(Port)
            .join(Host, Host.id == Port.host_id)
            .where(Host.scan_id == scan.id)
        ).scalar_one()
    except Exception:
        logger.exception("scan_completed summary query failed")
    started = getattr(scan, "started_at", None) or getattr(scan, "reverify_started_at", None)
    completed = getattr(scan, "completed_at", None)
    duration = int(max((completed - started).total_seconds(), 0)) if started and completed else None
    return {
        "scan": scan_brief(scan),
        "summary": {
            "status": scan.status,
            "started_at": started.isoformat() if started else None,
            "completed_at": completed.isoformat() if completed else None,
            "duration_seconds": duration,
            "progress_pct": getattr(scan, "progress_pct", None),
            "hosts_total_in_scope": getattr(scan, "hosts_total_in_scope", 0),
            "hosts_discovered": getattr(scan, "hosts_discovered", 0),
            "hosts": n_hosts,
            "hosts_up": n_up,
            "open_ports": n_ports,
        },
        "engagement": engagement_brief(engagement) if engagement else None,
    }


def host_discovered_payload(host, scan=None, engagement=None) -> dict:
    return {
        "host": host_brief(host),
        "scan": scan_brief(scan) if scan else None,
        "engagement": engagement_brief(engagement) if engagement else None,
    }


def _deliver(webhook: Webhook, event: str, payload: dict) -> int:
    validate_webhook_url(webhook.url)
    body = json.dumps(payload, default=str).encode("utf-8")
    req = Request(
        webhook.url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Asset-Discovery-Integrations/1.0",
            "X-Asset-Discovery-Event": event,
        },
        method="POST",
    )
    if webhook.secret:
        sig = "sha256=" + hmac.new(webhook.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        req.add_header("X-Asset-Discovery-Signature", sig)
    with _webhook_opener().open(req, timeout=5) as resp:  # noqa: S310 (config-provided webhooks, redirects re-validated)
        return resp.status


def deliver_test(db: Session, webhook: Webhook, event: str, payload: dict) -> Webhook:
    """Deliver a single payload and record the outcome on the webhook row."""
    try:
        code = _deliver(webhook, event, payload)
        webhook.last_status = code
        webhook.last_error = None
    except Exception as e:  # noqa: BLE001
        webhook.last_status = None
        webhook.last_error = str(e)[:500]
    webhook.last_triggered_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(webhook)
    return webhook


def _subscribers(db: Session, event: str):
    rows = []
    for wh in db.execute(
        select(Webhook).where(Webhook.enabled.is_(True))
    ).scalars().all():
        if event in (wh.events or []):
            rows.append(wh)
    return rows


def has_subscribers(db: Session, event: str) -> bool:
    return bool(_subscribers(db, event))


def deliver_event(db: Session, event: str, payload: dict):
    """Deliver to all enabled, subscribed webhooks and record outcomes."""
    try:
        rows = db.execute(
            select(Webhook).where(Webhook.enabled.is_(True))
        ).scalars().all()
    except Exception:
        logger.exception("webhook query failed")
        return
    for wh in rows:
        if event not in (wh.events or []):
            continue
        try:
            code = _deliver(wh, event, payload)
            wh.last_status = code
            wh.last_error = None
        except HTTPError as e:
            wh.last_status = e.code
            wh.last_error = f"HTTP {e.code}: {e.reason}"
        except (URLError, TimeoutError) as e:
            wh.last_status = None
            wh.last_error = str(e)[:500]
        except Exception as e:  # noqa: BLE001
            wh.last_status = None
            wh.last_error = repr(e)[:500]
        wh.last_triggered_at = datetime.now(timezone.utc)
        logger.info("webhook '%s' %s -> %s (%s)", wh.name, event, wh.url, wh.last_status)
    try:
        db.commit()
    except Exception:
        db.rollback()


def deliver_finding_created(db: Session, finding, host=None, scan=None, engagement=None, actor=None):
    deliver_event(db, EVENT_CREATED, finding_payload(finding, host, scan, engagement, actor))


def deliver_finding_updated(db: Session, finding, host=None, scan=None, engagement=None, actor=None, changes=None):
    payload = finding_payload(finding, host, scan, engagement, actor)
    payload["changes"] = changes or []
    deliver_event(db, EVENT_UPDATED, payload)


def deliver_scan_completed(db: Session, scan, engagement=None):
    deliver_event(db, EVENT_SCAN_COMPLETED, scan_completed_payload(db, scan, engagement))


def deliver_host_discovered(db: Session, host, scan=None, engagement=None):
    deliver_event(db, EVENT_HOST_DISCOVERED, host_discovered_payload(host, scan, engagement))