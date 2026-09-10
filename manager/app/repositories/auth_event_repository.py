from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.auth_event import AuthEvent
from app.repositories.base import SqlAlchemyRepository


class AuthEventRepository(SqlAlchemyRepository[AuthEvent]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, AuthEvent)

    async def count_failed_attempts(
        self,
        agent_id: str,
        source_ip: Optional[str] = None,
        window_seconds: int = 60
    ) -> int:
        """Count failed authentication attempts within a sliding time window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        stmt = select(func.coalesce(func.sum(AuthEvent.count), 0)).where(
            AuthEvent.agent_id == agent_id,
            AuthEvent.status == "failed",
            AuthEvent.timestamp >= cutoff
        )
        if source_ip and source_ip != "unknown":
            stmt = stmt.where(AuthEvent.source_ip == source_ip)

        result = await self.session.execute(stmt)
        return int(result.scalar() or 0)

    async def get_recent_by_agent(self, agent_id: str, limit: int = 50) -> List[AuthEvent]:
        stmt = select(AuthEvent).where(AuthEvent.agent_id == agent_id).order_by(AuthEvent.timestamp.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
