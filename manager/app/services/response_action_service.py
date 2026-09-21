import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.response_action import ResponseAction
from app.models.command import Command
from app.schemas.enums import CommandStatus, AgentStatus
from app.repositories.response_action_repository import ResponseActionRepository
from app.repositories.agent_repository import AgentRepository
from app.repositories.command_repository import CommandRepository
from app.services.command_dispatcher import command_dispatcher
from app.services.snapshot_service import SnapshotService
from app.services.action_audit_log_service import ActionAuditLogService
from app.services.setting_service import SettingService
from app.core.exceptions import (
    NotFoundError,
    BadRequestError,
    FlappingCooldownError
)

logger = logging.getLogger(__name__)


class ResponseActionService:
    """
    Service quản lý toàn bộ vòng đời của Response Action:
    Capture snapshot -> Apply Action -> Dispatch Command -> Audit Log.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.action_repo = ResponseActionRepository(session)
        self.agent_repo = AgentRepository(session)
        self.cmd_repo = CommandRepository(session)
        self.snapshot_service = SnapshotService(session)
        self.audit_service = ActionAuditLogService(session)
        self.setting_service = SettingService(session)

    async def create_and_apply_action(
        self,
        agent_id: str,
        action_type: str,
        action_params: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
        actor: str = "analyst",
        auto_rollback_seconds: Optional[int] = None
    ) -> ResponseAction:
        """
        Tạo và áp dụng response action với snapshot bảo toàn trạng thái.
        """
        action_params = action_params or {}
        now = datetime.now(timezone.utc)

        # 1. Kiểm tra Agent tồn tại
        agent = await self.agent_repo.get(agent_id)
        if not agent:
            raise NotFoundError(f"Agent with ID '{agent_id}' was not found.")

        # 2. Kiểm tra Anti-Flapping Cooldown
        cooldown_action = await self.action_repo.get_active_cooldown(agent_id, action_type, now)
        if cooldown_action and cooldown_action.cooldown_until:
            diff_secs = int((cooldown_action.cooldown_until - now).total_seconds())
            raise FlappingCooldownError(
                f"Agent '{agent_id}' is in response cooldown for '{action_type}' "
                f"until {cooldown_action.cooldown_until.isoformat()} ({diff_secs}s remaining). "
                "Action rejected to prevent flapping."
            )

        # 3. Chụp Snapshot trạng thái agent trước khi can thiệp
        snapshot = await self.snapshot_service.capture_snapshot(agent_id, action_type, action_params)

        # 4. Tính toán thời điểm Auto-Rollback
        settings = await self.setting_service.get_auto_rollback_settings()
        auto_rollback_at: Optional[datetime] = None

        if auto_rollback_seconds is not None:
            if auto_rollback_seconds > 0:
                auto_rollback_at = now + timedelta(seconds=auto_rollback_seconds)
        elif settings.get("enabled", True):
            timeout_secs = settings.get("timeout_seconds", 300)
            if timeout_secs > 0:
                auto_rollback_at = now + timedelta(seconds=timeout_secs)

        # 5. Tạo bản ghi ResponseAction
        action_id = f"act_{uuid.uuid4().hex[:12]}"
        action = ResponseAction(
            id=action_id,
            incident_id=incident_id,
            agent_id=agent_id,
            action_type=action_type,
            action_params=action_params,
            status="pending",
            snapshot=snapshot,
            auto_rollback_at=auto_rollback_at,
            created_at=now,
            updated_at=now
        )
        await self.action_repo.add(action)

        # Ghi audit log tạo action
        await self.audit_service.record_event(
            action_id=action_id,
            event="created",
            actor=actor,
            reason=action_params.get("reason", f"Initiated {action_type} response"),
            metadata={"action_type": action_type, "auto_rollback_at": auto_rollback_at.isoformat() if auto_rollback_at else None}
        )

        # 6. Dispatch command xuống agent & cập nhật agent state
        cmd_action = action_type
        if action_type == "auto_isolate":
            cmd_action = "isolate"

        # Cập nhật state agent
        if cmd_action == "isolate":
            agent.isolate()
        elif cmd_action == "quarantine":
            agent.status = AgentStatus.QUARANTINE

        cmd_id = f"cmd_{uuid.uuid4().hex[:12]}"
        cmd = Command(
            id=cmd_id,
            agent_id=agent_id,
            action=cmd_action,
            payload=action_params,
            status=CommandStatus.PENDING
        )
        await self.cmd_repo.add(cmd)
        await command_dispatcher.push_command(cmd.id, agent_id)

        # 7. Đánh dấu status = applied
        action.status = "applied"
        action.applied_at = now
        await self.session.flush()

        # Ghi audit log applied
        await self.audit_service.record_event(
            action_id=action_id,
            event="applied",
            actor=actor,
            reason=action_params.get("reason"),
            metadata={"command_id": cmd_id, "action_type": action_type}
        )

        await self.session.commit()
        await self.session.refresh(action)
        logger.info(f"Successfully applied response action '{action_id}' ({action_type}) on agent '{agent_id}'.")
        return action

    async def get_action(self, action_id: str) -> Optional[ResponseAction]:
        return await self.action_repo.get(action_id)

    async def list_actions_by_agent(self, agent_id: str, limit: int = 50, offset: int = 0) -> List[ResponseAction]:
        return await self.action_repo.get_by_agent(agent_id, limit=limit, offset=offset)

    async def list_actions_by_incident(self, incident_id: str) -> List[ResponseAction]:
        return await self.action_repo.get_by_incident(incident_id)
