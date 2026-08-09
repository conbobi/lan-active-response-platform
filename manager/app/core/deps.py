# manager/app/core/deps.py
from app.core.database import async_session
from sqlalchemy.ext.asyncio import AsyncSession

async def get_db():
    async with async_session() as session:
        yield session