from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.notification import NotificationConfig, NotificationLog
from app.repositories.base import SqlAlchemyRepository


class NotificationRepository(SqlAlchemyRepository[NotificationConfig]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, NotificationConfig)

    async def get_enabled_configs(self, channel: str = "telegram") -> List[NotificationConfig]:
        """Fetch all enabled notification configurations for a specific channel."""
        stmt = select(NotificationConfig).where(
            NotificationConfig.enabled == True,
            NotificationConfig.channel == channel
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def add_log(self, log: NotificationLog) -> NotificationLog:
        """Add a notification execution log entry."""
        self.session.add(log)
        await self.session.flush()
        await self.session.refresh(log)
        return log

    async def list_logs(self, skip: int = 0, limit: int = 100) -> List[NotificationLog]:
        """List historical notification logs."""
        stmt = select(NotificationLog).offset(skip).limit(limit).order_by(NotificationLog.created_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
