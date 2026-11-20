from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.web_access_log import WebAccessLog
from app.repositories.base import SqlAlchemyRepository


class WebAccessLogRepository(SqlAlchemyRepository[WebAccessLog]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, WebAccessLog)

    async def count_recent_login_requests(
        self,
        agent_id: str,
        src_ip: Optional[str] = None,
        window_seconds: int = 10,
        path_pattern: str = "%login%"
    ) -> int:
        """Count POST requests to /login endpoints within sliding window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        stmt = select(func.count(WebAccessLog.id)).where(
            WebAccessLog.agent_id == agent_id,
            WebAccessLog.method == "POST",
            WebAccessLog.path.ilike(path_pattern),
            WebAccessLog.timestamp >= cutoff
        )
        if src_ip and src_ip != "unknown":
            stmt = stmt.where(WebAccessLog.src_ip == src_ip)

        result = await self.session.execute(stmt)
        return int(result.scalar() or 0)

    async def count_recent_requests_by_ip(
        self,
        agent_id: str,
        src_ip: str,
        window_seconds: int = 10
    ) -> int:
        """Count all requests from a specific IP within sliding window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        stmt = select(func.count(WebAccessLog.id)).where(
            WebAccessLog.agent_id == agent_id,
            WebAccessLog.src_ip == src_ip,
            WebAccessLog.timestamp >= cutoff
        )
        result = await self.session.execute(stmt)
        return int(result.scalar() or 0)

    async def get_recent_by_agent(self, agent_id: str, limit: int = 50) -> List[WebAccessLog]:
        stmt = (
            select(WebAccessLog)
            .where(WebAccessLog.agent_id == agent_id)
            .order_by(WebAccessLog.timestamp.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

