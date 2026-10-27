import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.action_audit_log import ActionAuditLog
from app.repositories.action_audit_log_repository import ActionAuditLogRepository

logger = logging.getLogger(__name__)


class ActionAuditLogService:
    """
    Service quản lý ghi và truy vấn Audit Log cho mọi sự kiện Response Action.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.audit_repo = ActionAuditLogRepository(session)

    async def record_event(
        self,
        action_id: str,
        event: str,
        actor: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ActionAuditLog:
        """Ghi nhận sự kiện audit log."""
        log = await self.audit_repo.create_log(
            action_id=action_id,
            event=event,
            actor=actor,
            reason=reason,
            metadata=metadata or {}
        )
        logger.info(f"Audit log recorded: Action '{action_id}', Event '{event}', Actor '{actor}'.")
        return log

    async def get_logs_for_action(self, action_id: str) -> List[ActionAuditLog]:
        """Lấy toàn bộ lịch sử audit log của 1 action."""
        return await self.audit_repo.get_by_action(action_id)
