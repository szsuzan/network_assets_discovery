from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, Webhook
from ..schemas import WebhookOut, WebhookCreate, WebhookPatch
from ..auth import get_current_user

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

MANAGER_ROLES = {"admin", "pentester"}


async def _require_manager(user: User):
    if user.role not in MANAGER_ROLES:
        raise HTTPException(status_code=403, detail="Only admins/pentesters can manage webhooks")


@router.get("", response_model=List[WebhookOut])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Webhook).order_by(Webhook.created_at.asc()))
    return result.scalars().all()


@router.post("", response_model=WebhookOut, status_code=201)
async def create_webhook(
    data: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    await _require_manager(current_user)
    wh = Webhook(
        name=data.name.strip(),
        url=data.url.strip(),
        secret=data.secret,
        events=data.events or ["finding_created", "finding_updated"],
        enabled=data.enabled,
        created_by=current_user.id,
    )
    db.add(wh)
    await db.commit()
    await db.refresh(wh)
    return wh


@router.patch("/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: uuid.UUID,
    data: WebhookPatch,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    await _require_manager(current_user)
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    patch = data.model_dump(exclude_unset=True)
    for key, value in patch.items():
        setattr(wh, key, value)
    await db.commit()
    await db.refresh(wh)
    return wh


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    await _require_manager(current_user)
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(wh)
    await db.commit()


@router.post("/{webhook_id}/test", response_model=WebhookOut)
async def test_webhook(
    webhook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    await _require_manager(current_user)
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    from ..services.db import SessionLocal
    from ..services.webhook import deliver_test
    with SessionLocal() as s:
        w = s.get(Webhook, wh.id)
        deliver_test(s, w, "finding_updated", {
            "event": "test",
            "message": "Test delivery from SubNex",
            "sent_by": current_user.email,
        })
        return w