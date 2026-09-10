import asyncio
from app.database import AsyncSessionLocal, engine
from app.models import User
from sqlalchemy import func, select
from app.routers.auth import hash_password

async def seed_users() -> None:
    """Create the demo admin user if no users exist yet.

    Safe to run on every startup: it is a no-op once the first user exists.
    """
    async with AsyncSessionLocal() as db:
        count = await db.scalar(select(func.count(User.id)))
        if count:
            return
        db.add(User(
            email="demo@pentest.local",
            password_hash=hash_password("password123"),
            role="admin",
            must_change_password=True,
        ))
        await db.commit()
        print("Seeded default admin user demo@pentest.local - a password change is required on first login.")


async def seed():
    await seed_users()
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed())