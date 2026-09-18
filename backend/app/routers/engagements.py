from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import List
import uuid

from ..database import get_db
from ..models import User, Engagement, Scan, AuditLog, AgentTask
from ..schemas import EngagementCreate, EngagementUpdate, EngagementOut, ScanOut
from ..auth import get_current_user
from ..scope_utils import validate_scope

router = APIRouter(prefix="/api/engagements", tags=["engagements"])

ACTIVE_SCAN_STATUSES = ("queued", "discovering", "scanning", "fingerprinting",
                        "analyzing", "paused", "agent_running", "reverifying")


async def _ensure_engagement_writable(db: AsyncSession, engagement: Engagement, actor: User):
    """Admins may mutate an archived engagement (delete/restore); everyone else
    is limited to reading it. Used by scan-level mutations through a shared
    helper in scans.py."""
    if engagement.status == "archived" and actor.role != "admin":
        raise HTTPException(
            status_code=409,
            detail="This engagement is archived and read-only; unarchive it before making changes",
        )
    return engagement

@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    data: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot create engagements")
    scope = [s.strip() for s in (data.authorized_scope or []) if s and s.strip()]
    try:
        validate_scope(scope)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    engagement = Engagement(
        client_name=data.client_name,
        engagement_name=data.engagement_name,
        authorized_scope=scope,
        start_date=data.start_date,
        end_date=data.end_date,
        created_by=current_user.id
    )
    db.add(engagement)
    
    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=engagement.id,
        action="engagement_created",
        detail={"client_name": data.client_name, "scope": scope}
    ))
    
    await db.commit()
    await db.refresh(engagement)
    return engagement

@router.patch("/{engagement_id}", response_model=EngagementOut)
async def update_engagement(
    engagement_id: uuid.UUID,
    data: EngagementUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Partially edit an engagement (name, dates, authorized scope).

    Only the creator (pentester) or an admin may edit. Scope entries are
    validated so typos such as ``192.168.1.0./24`` are caught here instead of
    silently rejecting scan targets later.
    """
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if current_user.role not in ("admin", "pentester"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    if current_user.role != "admin" and engagement.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="No access to this engagement")

    # Archiving is the one "edit" that happens while the engagement is archived:
    # requesting anything else on an archived engagement is rejected unless the
    # engagement is being unarchived in the same call.
    becomes_archived = data.status == "archived" and data.status != engagement.status
    unarchiving = data.status == "active" and engagement.status == "archived"
    if data.status is not None and data.status not in ("active", "archived"):
        raise HTTPException(status_code=422, detail="status must be 'active' or 'archived'")
    if engagement.status == "archived" and not unarchiving:
        non_status_fields = [f for f in ("client_name", "engagement_name", "start_date", "end_date", "authorized_scope")
                             if getattr(data, f) is not None]
        if non_status_fields:
            raise HTTPException(status_code=409,
                                detail="This engagement is archived and read-only; unarchive it before editing")

    if becomes_archived and current_user.role != "admin":
        running = (await db.execute(
            select(Scan.id).where(Scan.engagement_id == engagement_id,
                                  Scan.status.in_(ACTIVE_SCAN_STATUSES)).limit(1))).first()
        if running:
            raise HTTPException(status_code=409,
                                detail="Stop or complete all scans before archiving this engagement")

    changes = {}
    if data.client_name is not None and data.client_name != engagement.client_name:
        engagement.client_name = data.client_name
        changes["client_name"] = data.client_name
    if data.engagement_name is not None and data.engagement_name != engagement.engagement_name:
        engagement.engagement_name = data.engagement_name
        changes["engagement_name"] = data.engagement_name
    if data.start_date is not None and str(data.start_date) != (str(engagement.start_date) if engagement.start_date else None):
        engagement.start_date = data.start_date
        changes["start_date"] = str(data.start_date)
    if data.end_date is not None and str(data.end_date) != (str(engagement.end_date) if engagement.end_date else None):
        engagement.end_date = data.end_date
        changes["end_date"] = str(data.end_date)
    if data.authorized_scope is not None:
        scope = [s.strip() for s in data.authorized_scope if s and s.strip()]
        try:
            validate_scope(scope)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if scope != engagement.authorized_scope:
            engagement.authorized_scope = scope
            changes["scope"] = scope
    if data.status is not None and data.status != engagement.status:
        engagement.status = data.status
        changes["status"] = data.status

    if changes:
        db.add(AuditLog(
            user_id=current_user.id,
            engagement_id=engagement.id,
            action="engagement_updated",
            detail=changes
        ))
        await db.commit()
        await db.refresh(engagement)
    return engagement

@router.get("", response_model=List[EngagementOut])
async def list_engagements(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Engagement).order_by(Engagement.created_at.desc()))
    return result.scalars().all()

@router.get("/{engagement_id}", response_model=EngagementOut)
async def get_engagement(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement

@router.get("/{engagement_id}/scans", response_model=List[ScanOut])
async def get_engagement_scans(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(Scan).where(Scan.engagement_id == engagement_id).order_by(Scan.created_at.desc())
    )
    return result.scalars().all()

async def _perform_delete_engagement(db: AsyncSession, engagement: Engagement) -> None:
    """Cascade-delete an engagement and all rows that reference it.

    Removes scans (with their hosts/ports/findings), audit trail rows and agent
    tasks in the right FK order. Used by the admin DELETE endpoint and by the
    deletion-request approval flow.
    """
    engagement_id = engagement.id
    scan_result = await db.execute(select(Scan).where(Scan.engagement_id == engagement_id))
    scans = scan_result.scalars().all()
    scan_ids = [s.id for s in scans]

    # Delete audit log rows referencing the engagement OR any of its scans first,
    # since audit_log.scan_id is a hard FK that would otherwise block scan deletes.
    await db.execute(
        AuditLog.__table__.delete().where(or_(AuditLog.engagement_id == engagement_id,
                                              AuditLog.scan_id.in_(scan_ids)))
    )

    # agent_tasks references scans via a hard FK with no ORM cascade from Scan,
    # so remove them explicitly before deleting the scans.
    await db.execute(
        AgentTask.__table__.delete().where(AgentTask.scan_id.in_(scan_ids))
    )

    for scan in scans:
        await db.delete(scan)

    await db.delete(engagement)
    await db.commit()


@router.delete("/{engagement_id}", status_code=204)
async def delete_engagement(
    engagement_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403,
                            detail="Only admins can delete engagements. Pentesters should submit a deletion request instead.")

    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    await _perform_delete_engagement(db, engagement)
