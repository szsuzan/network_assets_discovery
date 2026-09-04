from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ..config import get_settings

settings = get_settings()

# Sync engine for Celery worker tasks
sync_engine = create_engine(
    settings.DATABASE_URL.replace("+asyncpg", "+psycopg2").replace("?async_fallback", ""),
    pool_pre_ping=True
)
SessionLocal = sessionmaker(bind=sync_engine, expire_on_commit=False)
