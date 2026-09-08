"""Best-effort webhook delivery for finding lifecycle events.

Delivers JSON payloads to every enabled webhook subscribed to the event, signed
with the webhook's shared secret via an HMAC-SHA256 signature header when one is
configured. Failures never propagate to callers — each webhook's last delivery
result is persisted for the Integrations UI.
"""
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Webhook

logger = logging.getLogger(__name__)

EVENT_CREATED = "finding_created"
EVENT_UPDATED = "finding_updated"


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
        "scan": {
            "id": str(scan.id) if scan else None,
            "kind": scan.kind if scan else None,
            "profile": scan.profile if scan else None,
            "targets": scan.targets if scan else None,
        } if scan else None,
        "engagement": {
            "id": str(engagement.id) if engagement else None,
            "client_name": getattr(engagement, "client_name", None),
            "engagement_name": getattr(engagement, "engagement_name", None),
        } if engagement else None,
        "actor": {"email": actor.email, "role": actor.role} if actor else None,
    }


def _deliver(webhook: Webhook, event: str, payload: dict) -> int:
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
    with urlopen(req, timeout=5) as resp:  # noqa: S310 (config-provided internal webhooks)
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