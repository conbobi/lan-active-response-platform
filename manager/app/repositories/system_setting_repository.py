from typing import Optional, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.system_setting import SystemSetting
from app.repositories.base import SqlAlchemyRepository


class SystemSettingRepository(SqlAlchemyRepository[SystemSetting]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, SystemSetting)

    async def get_by_key(self, key: str) -> Optional[SystemSetting]:
        stmt = select(SystemSetting).where(SystemSetting.key == key)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def set_key(self, key: str, value: Any) -> SystemSetting:
        existing = await self.get_by_key(key)
        val_dict = value if isinstance(value, dict) else {"data": value}

        if existing:
            existing.value = val_dict
            await self.session.flush()
            return existing
        else:
            setting = SystemSetting(key=key, value=val_dict)
            await self.add(setting)
            await self.session.flush()
            return setting
