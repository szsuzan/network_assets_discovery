"""Global Settings API.

GET  /api/settings   -> the full catalog merged with stored overrides.
PUT  /api/settings   -> upsert a subset of keys ({key: value}); unknown/invalid
                        keys are rejected with a 422-style HTTPException.
"""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User
from ..schemas import SettingOut
from ..auth import get_current_user
from ..services import settings as settings_svc

router = APIRouter(prefix="/api/settings", tags=["settings"])

MANAGER_ROLES = {"admin", "pentester"}


async def _require_manager(user: User):
    if user.role not in MANAGER_ROLES:
        raise HTTPException(status_code=403, detail="Only admins/pentesters can change settings")


@router.get("", response_model=List[SettingOut])
async def list_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await settings_svc.asnapshot(db)


@router.put("", response_model=List[SettingOut])
async def update_settings(
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _require_manager(current_user)
    unknown = [k for k in payload if k not in settings_svc.CATALOG_BY_KEY]
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown setting(s): {', '.join(unknown)}",
        )
    try:
        await settings_svc.set_values(db, payload)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return await settings_svc.asnapshot(db)