"""Password hashing helpers shared by auth and user-management.

Centralised so admin user creation/reset and the login/change-password flows
use exactly the same bcrypt policy.
"""
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=13)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)