from datetime import datetime
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.response_action import ResponseAction
from app.repositories.base import SqlAlchemyRepository


class ResponseActionRepository(SqlAlchemyRepository[ResponseAction]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ResponseAction)

    async def get_for_update(self, action_id: str) -> Optional[ResponseAction]:
        """Lấy action và lock row với with_for_update() để chống race condition."""
        stmt = (
            select(ResponseAction)
            .where(ResponseAction.id == action_id)
            .with_for_update()
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_agent(self, agent_id: str, limit: int = 50, offset: int = 0) -> List[ResponseAction]:
        stmt = (
            select(ResponseAction)
            .where(ResponseAction.agent_id == agent_id)
            .order_by(ResponseAction.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_incident(self, incident_id: str) -> List[ResponseAction]:
        stmt = (
            select(ResponseAction)
            .where(ResponseAction.incident_id == incident_id)
            .order_by(ResponseAction.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_active_applied_by_incident(self, incident_id: str) -> List[ResponseAction]:
        stmt = (
            select(ResponseAction)
            .where(
                ResponseAction.incident_id == incident_id,
                ResponseAction.status == "applied"
            )
            .order_by(ResponseAction.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_active_applied_by_agent(self, agent_id: str) -> List[ResponseAction]:
        stmt = (
            select(ResponseAction)
            .where(
                ResponseAction.agent_id == agent_id,
                ResponseAction.status == "applied"
            )
            .order_by(ResponseAction.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_active_applied_by_agents(self, agent_ids: List[str]) -> List[ResponseAction]:
        """Lấy tất cả các response action đang applied trên một danh sách agent (dùng cho group rollback)."""
        if not agent_ids:
            return []
        stmt = (
            select(ResponseAction)
            .where(
                ResponseAction.agent_id.in_(agent_ids),
                ResponseAction.status == "applied"
            )
            .order_by(ResponseAction.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_expired_actions(self, current_time: datetime) -> List[ResponseAction]:
        """Lấy các action đang applied đã quá hạn auto_rollback_at."""
        stmt = (
            select(ResponseAction)
            .where(
                ResponseAction.status == "applied",
                ResponseAction.auto_rollback_at.isnot(None),
                ResponseAction.auto_rollback_at <= current_time
            )
            .order_by(ResponseAction.auto_rollback_at.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_active_cooldown(self, agent_id: str, action_type: str, current_time: datetime) -> Optional[ResponseAction]:
        """Kiểm tra xem agent có đang trong thời gian cooldown chống flapping cho loại action này không."""
        stmt = (
            select(ResponseAction)
            .where(
                ResponseAction.agent_id == agent_id,
                ResponseAction.action_type == action_type,
                ResponseAction.cooldown_until.isnot(None),
                ResponseAction.cooldown_until > current_time
            )
            .order_by(ResponseAction.cooldown_until.desc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()
