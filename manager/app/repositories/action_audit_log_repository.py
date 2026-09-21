from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.action_audit_log import ActionAuditLog
from app.repositories.base import SqlAlchemyRepository


class ActionAuditLogRepository(SqlAlchemyRepository[ActionAuditLog]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ActionAuditLog)

    async def create_log(
        self,
        action_id: str,
        event: str,
        actor: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ActionAuditLog:
        log = ActionAuditLog(
            id=str(uuid.uuid4()),
            action_id=action_id,
            event=event,
            actor=actor,
            reason=reason,
            metadata_=metadata or {},
            created_at=datetime.now(timezone.utc)
        )
        self.session.add(log)
        await self.session.flush()
        return log

    async def get_by_action(self, action_id: str) -> List[ActionAuditLog]:
        stmt = (
            select(ActionAuditLog)
            .where(ActionAuditLog.action_id == action_id)
            .order_by(ActionAuditLog.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
