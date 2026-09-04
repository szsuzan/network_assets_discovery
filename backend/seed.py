import asyncio
from app.database import AsyncSessionLocal, engine
from app.models import Base, User
from sqlalchemy import select
from app.routers.auth import hash_password

async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == "demo@pentest.local"))
        if not result.scalar_one_or_none():
            user = User(
                email="demo@pentest.local",
                password_hash=hash_password("password123"),
                role="admin"
            )
            db.add(user)
            await db.commit()
            print("Created demo user: demo@pentest.local / password123")
        else:
            print("Demo user already exists")
    
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed())
