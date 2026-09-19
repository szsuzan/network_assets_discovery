import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models import User
from ..passwords import hash_password, verify_password
from ..schemas import LoginRequest, TokenResponse, UserOut, ChangePasswordRequest
from ..auth import create_access_token, get_current_user_unchecked

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Accounts inside this platform live under one e-mail domain. Letting users log
# in and admins create accounts with the bare username ("demo" instead of
# "demo@pentest.local") matches the self-hosted LAN persona of the tool.
DEFAULT_EMAIL_DOMAIN = "pentest.local"


def normalize_email(value: str) -> str:
    """Append the default domain when a bare username (no '@') is supplied."""
    v = (value or "").strip()
    if not v:
        return v
    return v if "@" in v else f"{v}@{DEFAULT_EMAIL_DOMAIN}"

# Simple in-memory brute-force guard keyed by client IP: failed logins are
# remembered for 15 minutes, and after 10 failed attempts from one IP further
# logins from it are refused until the window slides. Docker NAT means several
# LAN clients share the backend source IP, so the limit is generous enough that
# it never blocks a single legitimate user, but still throttles a distributed
# password-spray.
_FAIL_WINDOW_SEC = 900
_FAIL_LIMIT = 10
_login_failures: dict = {}  # ip -> deque[unix_time]

def _prune(ip: str) -> deque:
    now = time.time()
    q = _login_failures.setdefault(ip, deque())
    while q and now - q[0] > _FAIL_WINDOW_SEC:
        q.popleft()
    return q

@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if len(_prune(client_ip)) >= _FAIL_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts; please wait and try again"
        )
    identifier = (data.email or "").strip()
    if not identifier:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if "@" in identifier:
        result = await db.execute(select(User).where(User.email == identifier))
        user = result.scalar_one_or_none()
    else:
        # Bare username: prefer accounts under the default domain, then any
        # user whose username part matches (@other-domain accounts).
        result = await db.execute(select(User).where(User.email == f"{identifier}@{DEFAULT_EMAIL_DOMAIN}"))
        user = result.scalar_one_or_none()
        if user is None:
            result = await db.execute(select(User).where(User.email.ilike(f"{identifier}@%")))
            user = result.scalars().first()
    if not user or not verify_password(data.password, user.password_hash):
        _login_failures[client_ip].append(time.time())
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    if not getattr(user, "active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    token = create_access_token(user)
    return TokenResponse(access_token=token, role=user.role, must_change_password=user.must_change_password,
                         id=user.id)

@router.post("/change-password")
async def change_password(
    data: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_unchecked),
):
    """Change the current user's password.

    Runs even while `must_change_password` is still set (the one operation
    available to an otherwise locked account), then clears the flag so normal
    API access resumes. The client must re-authenticate afterwards.
    """
    if not verify_password(data.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if data.new_password == data.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current password")
    stripped = data.new_password.strip()
    if len(stripped) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters")
    if stripped.lower() in ("password123", "changeme", "password"):
        raise HTTPException(status_code=400, detail="That password is too weak; choose a stronger one")

    current_user.password_hash = hash_password(data.new_password)
    current_user.must_change_password = False
    current_user.jwt_version += 1
    await db.commit()
    return {"status": "ok", "detail": "Password updated - log in with your new password"}

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token():
    # In production this would validate a refresh token
    raise HTTPException(status_code=501, detail="Refresh token flow not yet implemented")

@router.get("/me", response_model=UserOut)
async def me(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_unchecked),
):
    """Return the current user's identity (id, email, role, active status).

    Uses the unchecked dependency so an account that is still flagged
    ``must_change_password`` can fetch its own profile.
    """
    return current_user
