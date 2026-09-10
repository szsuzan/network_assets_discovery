from pydantic_settings import BaseSettings
from functools import lru_cache

_JWT_PLACEHOLDERS = {"change-me-in-production", "changeme", "change_me", "secret"}

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://pentest:secret@localhost:5432/subnex"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60

    def model_post_init(self, __context) -> None:
        secret = (self.JWT_SECRET or "").strip()
        if not secret or secret.lower() in _JWT_PLACEHOLDERS or len(secret) < 16:
            raise ValueError(
                "JWT_SECRET must be a strong, unique random value (>= 16 chars). "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\" "
                "and set it in your .env file."
            )

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
