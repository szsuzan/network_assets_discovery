"""Deletion-request approval queue.

Admins delete engagements/scans directly (DELETE endpoints). Everyone else with
ownership submits a request here with a reason; an admin approves or rejects it.
Approval performs the hard delete via the same helpers the admin endpoints use,
so a scanner can only remove data with explicit admin sign-off.
"""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models import User, Engagement, Scan, DeletionRequest
from ..schemas import DeletionRequestCreate, DeletionRequestOut
from ..auth import require_roles
from .scans import _load_scan_for_user, _perform_delete_scan
from .engagements import _perform_delete_engagement

router = APIRouter(prefix="/api/deletion-requests", tags=["deletion-requests"])


def _ok(req: DeletionRequest, requested_by_email: Optional[str] = None) -> DeletionRequestOut:
    out = DeletionRequestOut(
        id=req.id,
        target_type=req.target_type,
        target_id=req.target_id,
        target_label=req.target_label,
        parent_label=req.parent_label,
        reason=req.reason,
        requested_by=req.requested_by,
        requested_by_email=requested_by_email,
        status=req.status,
        created_at=req.created_at,
        resolved_at=req.resolved_at,
        resolved_by=req.resolved_by,
        resolver_comment=req.resolver_comment,
    )
    return out


async def _load_request(db: AsyncSession, request_id) -> DeletionRequest:
    req = (await db.execute(select(DeletionRequest).where(DeletionRequest.id == request_id))).scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="Deletion request not found")
    return req


def _confirm_users_engagement(db: AsyncSession, user: User, engagement: Engagement):
    if user.role == "admin":
        return
    if engagement.created_by != user.id:
        raise HTTPException(status_code=403, detail="No access to this engagement")


@router.post("", response_model=DeletionRequestOut, status_code=status.HTTP_201_CREATED)
async def create_deletion_request(
    data: DeletionRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "scanner")),
):
    """Request deletion of an engagement or scan. Admins don't need this — their
    DELETE endpoints work directly."""
    if current_user.role == "admin":
        raise HTTPException(status_code=400, detail="Admins delete directly; no request needed")

    if data.target_type == "engagement":
        engagement = (await db.execute(
            select(Engagement).where(Engagement.id == data.target_id))).scalar_one_or_none()
        if not engagement:
            raise HTTPException(status_code=404, detail="Engagement not found")
        _confirm_users_engagement(db, current_user, engagement)
        req = DeletionRequest(
            target_type="engagement",
            target_id=engagement.id,
            target_label=f"{engagement.client_name} / {engagement.engagement_name}",
            reason=data.reason,
            requested_by=current_user.id,
        )
    else:
        scan = await _load_scan_for_user(db, data.target_id, current_user)
        engagement = (await db.execute(
            select(Engagement).where(Engagement.id == scan.engagement_id))).scalar_one_or_none()
        label = scan.name or scan.profile
        req = DeletionRequest(
            target_type="scan",
            target_id=scan.id,
            target_label=label,
            parent_label=f"{engagement.client_name} / {engagement.engagement_name}" if engagement else None,
            reason=data.reason,
            requested_by=current_user.id,
        )

    # Avoid duplicate pending requests for the same target.
    dup = (await db.execute(
        select(DeletionRequest).where(
            DeletionRequest.target_type == data.target_type,
            DeletionRequest.target_id == data.target_id,
            DeletionRequest.status == "pending",
        ))).scalars().all()
    if dup:
        raise HTTPException(status_code=409, detail="A pending deletion request for this target already exists")

    db.add(req)
    await db.commit()
    await db.refresh(req)
    return _ok(req, current_user.email)


@router.get("", response_model=List[DeletionRequestOut])
async def list_deletion_requests(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "scanner")),
):
    """Admins see the whole queue; scanners see only requests they filed."""
    if current_user.role == "admin":
        result = await db.execute(
            select(DeletionRequest).order_by(DeletionRequest.created_at.desc()))
    else:
        result = await db.execute(
            select(DeletionRequest).where(DeletionRequest.requested_by == current_user.id)
            .order_by(DeletionRequest.created_at.desc()))

    reqs = result.scalars().all()
    emails = {}
    if reqs:
        ids = [r.requested_by for r in reqs]
        users_result = await db.execute(select(User).where(User.id.in_(ids)))
        emails = {u.id: u.email for u in users_result.scalars()}
    return [_ok(r, emails.get(r.requested_by)) for r in reqs]


@router.post("/{request_id}/approve", response_model=DeletionRequestOut)
async def approve_deletion_request(
    request_id,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    """Approve and perform the requested deletion."""
    req = await _load_request(db, request_id)
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {req.status}")

    if req.target_type == "engagement":
        engagement = (await db.execute(
            select(Engagement).where(Engagement.id == req.target_id))).scalar_one_or_none()
        if engagement:
            await _perform_delete_engagement(db, engagement)
    else:
        scan = (await db.execute(select(Scan).where(Scan.id == req.target_id))).scalar_one_or_none()
        if scan:
            await _perform_delete_scan(db, scan)

    req.status = "approved"
    req.resolved_at = datetime.now(timezone.utc)
    req.resolved_by = current_user.id
    req.resolver_comment = "Approved by admin"
    await db.commit()
    await db.refresh(req)
    return _ok(req)


@router.post("/{request_id}/reject", response_model=DeletionRequestOut)
async def reject_deletion_request(
    request_id,
    reason: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    req = await _load_request(db, request_id)
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {req.status}")

    req.status = "rejected"
    req.resolved_at = datetime.now(timezone.utc)
    req.resolved_by = current_user.id
    req.resolver_comment = reason or "Rejected by admin"
    await db.commit()
    await db.refresh(req)
    return _ok(req)


@router.post("/{request_id}/cancel", response_model=DeletionRequestOut)
async def cancel_deletion_request(
    request_id,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "scanner")),
):
    """The requester withdraws their own open request."""
    req = await _load_request(db, request_id)
    if req.requested_by != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You can only cancel your own deletion requests")
    if req.status != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {req.status}")

    req.status = "cancelled"
    req.resolved_at = datetime.now(timezone.utc)
    req.resolved_by = None
    req.resolver_comment = "Cancelled by requester"
    await db.commit()
    await db.refresh(req)
    return _ok(req)