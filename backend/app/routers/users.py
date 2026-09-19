"""User administration API (admin only).

Admins manage accounts: create users, change roles, enable/disable accounts
and reset passwords. Only the bcrypt hash is ever stored; a reset forces the
user to pick a new password on next login and revokes any outstanding tokens.

Guards:
  * an admin can never change their own role or disable themselves;
  * the last active admin can neither be demoted nor disabled (lockout-proof).
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..database import get_db
from ..models import User, AuditLog
from ..passwords import hash_password
from ..schemas import UserOut, UserCreate, UserUpdate, ResetPasswordRequest
from ..auth import require_roles
from .auth import normalize_email

router = APIRouter(prefix="/api/users", tags=["users"])


async def _count_active_admins(db: AsyncSession) -> int:
    return await db.scalar(select(func.count(User.id)).where(
        User.role == "admin", User.active.is_(True)
    ))


@router.get("", response_model=List[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    """Create an account. The user must change their password on first login;
    the supplied password is salted + bcrypt-hashed before it touches the DB.
    A bare username (no '@') gets the default domain appended."""
    email = normalize_email(data.email)
    if not email:
        raise HTTPException(status_code=422, detail="Email is required")
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="A user with this email already exists")

    user = User(
        email=email,
        password_hash=hash_password(data.password),
        role=data.role,
        active=data.active,
        must_change_password=True,
    )
    db.add(user)
    await db.flush()
    db.add(AuditLog(
        user_id=current_user.id,
        action="user_created",
        detail={"email": email, "role": data.role},
    ))
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id,
    data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    if str(user_id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="You cannot change your own role or disable your own account")

    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if data.role is not None and data.role != target.role:
        if target.role == "admin" and target.active:
            if await _count_active_admins(db) <= 1:
                raise HTTPException(status_code=400, detail="Cannot demote the last active admin")
        changes["role"] = (target.role, data.role)
        target.role = data.role

    if data.active is not None and data.active != target.active:
        if target.active and target.role == "admin" and not data.active:
            if await _count_active_admins(db) <= 1:
                raise HTTPException(status_code=400, detail="Cannot disable the last active admin")
        changes["active"] = (target.active, data.active)
        # Revoke outstanding tokens when disabling an account.
        if not data.active:
            target.jwt_version += 1
        target.active = data.active

    if changes:
        db.add(AuditLog(
            user_id=current_user.id,
            action="user_updated",
            detail={"user": target.email, "changes": {k: {"old": o, "new": n} for k, (o, n) in changes.items()}},
        ))
    await db.commit()
    await db.refresh(target)
    return target


@router.post("/{user_id}/reset-password", response_model=UserOut)
async def reset_password(
    user_id,
    data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
    """Force a new password. Only the hash is stored; the user must change it
    on next login and all existing tokens are revoked."""
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.password_hash = hash_password(data.password)
    target.must_change_password = True
    target.jwt_version += 1
    db.add(AuditLog(
        user_id=current_user.id,
        action="user_password_reset",
        detail={"user": target.email},
    ))
    await db.commit()
    await db.refresh(target)
    return target