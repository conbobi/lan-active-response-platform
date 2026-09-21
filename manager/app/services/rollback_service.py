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
from app.repositories.agent_group_repository import AgentGroupRepository
from app.services.command_dispatcher import command_dispatcher
from app.services.snapshot_service import SnapshotService
from app.services.action_audit_log_service import ActionAuditLogService
from app.services.setting_service import SettingService
from app.schemas.response_action import UndoBatchResponse
from app.core.exceptions import (
    NotFoundError,
    BadRequestError,
    ConflictError
)

logger = logging.getLogger(__name__)


class RollbackService:
    """
    Service chuyên trách xử lý Undo (thủ công & tự động) và Rollback
    các Response Actions, đảm bảo tính bất biến, concurrency-safe và anti-flapping.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.action_repo = ResponseActionRepository(session)
        self.agent_repo = AgentRepository(session)
        self.cmd_repo = CommandRepository(session)
        self.group_repo = AgentGroupRepository(session)
        self.snapshot_service = SnapshotService(session)
        self.audit_service = ActionAuditLogService(session)
        self.setting_service = SettingService(session)

    async def rollback_action(
        self,
        action_id: str,
        reason: str = "Manual undo via UI/API",
        actor: str = "analyst"
    ) -> ResponseAction:
        """
        Undo một action cụ thể.
        Sử dụng row lock (with_for_update) để ngăn chặn Race Condition (trả về 409 Conflict).
        """
        now = datetime.now(timezone.utc)

        # 1. Row-level Lock action để chống 2 admin cùng bấm undo
        action = await self.action_repo.get_for_update(action_id)
        if not action:
            raise NotFoundError(f"ResponseAction with ID '{action_id}' was not found.")

        # 2. Xử lý trạng thái và Race Condition
        if action.status == "reverting":
            raise ConflictError(
                f"Action '{action_id}' is currently being reverted by another process."
            )
        if action.status == "reverted":
            raise ConflictError(
                f"Action '{action_id}' has already been reverted at {action.undone_at}."
            )
        if action.status != "applied":
            raise BadRequestError(
                f"Cannot undo action in status '{action.status}'. Only 'applied' actions can be undone."
            )

        # 3. Đánh dấu status = reverting
        action.status = "reverting"
        await self.session.flush()

        # Ghi log yêu cầu undo
        is_auto = (actor == "system")
        request_event = "auto_rollback_requested" if is_auto else "undo_requested"
        await self.audit_service.record_event(
            action_id=action_id,
            event=request_event,
            actor=actor,
            reason=reason,
            metadata={"previous_status": "applied"}
        )

        try:
            # 4. Xác định compensation action từ snapshot
            compensation = self.snapshot_service.get_compensation_action(
                action.action_type,
                action.action_params,
                action.snapshot
            )

            cmd_action = compensation.get("command_action")
            cmd_payload = compensation.get("payload", {})
            cmd_id = None

            # 5. Dispatch compensation command xuống agent (ví dụ: unisolate, release_quarantine)
            if cmd_action:
                cmd_id = f"cmd_{uuid.uuid4().hex[:12]}"
                cmd = Command(
                    id=cmd_id,
                    agent_id=action.agent_id,
                    action=cmd_action,
                    payload=cmd_payload,
                    status=CommandStatus.PENDING
                )
                await self.cmd_repo.add(cmd)
                await command_dispatcher.push_command(cmd.id, action.agent_id)
                logger.info(f"Dispatched compensation command '{cmd_action}' (ID: {cmd_id}) for action '{action_id}'.")

            # 6. Khôi phục trạng thái Agent trong DB
            agent = await self.agent_repo.get(action.agent_id)
            if agent:
                if compensation.get("restore_is_isolated") is False:
                    agent.is_isolated = False
                if compensation.get("restore_agent_status") == "active":
                    agent.status = AgentStatus.ACTIVE

            # 7. Thiết lập Anti-Flapping Cooldown
            settings = await self.setting_service.get_auto_rollback_settings()
            cooldown_secs = settings.get("cooldown_seconds", 600)
            cooldown_until = now + timedelta(seconds=cooldown_secs)

            # 8. Cập nhật action status = reverted
            action.status = "reverted"
            action.undone_at = now
            action.undone_by = actor
            action.undo_reason = reason
            action.cooldown_until = cooldown_until
            action.updated_at = now

            # 9. Ghi audit log hoàn tất undo
            final_event = "auto_undone" if is_auto else "undone"
            await self.audit_service.record_event(
                action_id=action_id,
                event=final_event,
                actor=actor,
                reason=reason,
                metadata={
                    "compensation_command": cmd_action,
                    "compensation_cmd_id": cmd_id,
                    "cooldown_until": cooldown_until.isoformat()
                }
            )

            await self.session.commit()
            await self.session.refresh(action)
            logger.info(f"Successfully reverted response action '{action_id}' by '{actor}'.")
            return action

        except Exception as e:
            action.status = "applied"  # rollback trạng thái nếu lỗi
            await self.session.flush()
            await self.audit_service.record_event(
                action_id=action_id,
                event="failed",
                actor=actor,
                reason=f"Rollback failed: {str(e)}",
                metadata={"error": str(e)}
            )
            await self.session.commit()
            logger.error(f"Failed to rollback action '{action_id}': {e}", exc_info=True)
            raise

    async def rollback_incident_actions(
        self,
        incident_id: str,
        reason: str = "Batch incident undo",
        actor: str = "analyst"
    ) -> UndoBatchResponse:
        """Undo toàn bộ các action đang áp dụng thuộc về một incident."""
        actions = await self.action_repo.get_active_applied_by_incident(incident_id)
        reverted_ids = []
        failed_count = 0
        details = []

        for act in actions:
            try:
                await self.rollback_action(
                    action_id=act.id,
                    reason=f"{reason} (Incident: {incident_id})",
                    actor=actor
                )
                reverted_ids.append(act.id)
                details.append({"action_id": act.id, "status": "reverted"})
            except Exception as e:
                failed_count += 1
                details.append({"action_id": act.id, "status": "failed", "error": str(e)})

        return UndoBatchResponse(
            reverted=len(reverted_ids),
            failed=failed_count,
            action_ids=reverted_ids,
            details=details
        )

    async def rollback_agent_actions(
        self,
        agent_id: str,
        reason: str = "Batch agent undo",
        actor: str = "analyst"
    ) -> UndoBatchResponse:
        """Undo toàn bộ các action đang áp dụng trên một agent."""
        actions = await self.action_repo.get_active_applied_by_agent(agent_id)
        reverted_ids = []
        failed_count = 0
        details = []

        for act in actions:
            try:
                await self.rollback_action(
                    action_id=act.id,
                    reason=f"{reason} (Agent: {agent_id})",
                    actor=actor
                )
                reverted_ids.append(act.id)
                details.append({"action_id": act.id, "status": "reverted"})
            except Exception as e:
                failed_count += 1
                details.append({"action_id": act.id, "status": "failed", "error": str(e)})

        return UndoBatchResponse(
            reverted=len(reverted_ids),
            failed=failed_count,
            action_ids=reverted_ids,
            details=details
        )

    async def rollback_group_actions(
        self,
        group_id: str,
        reason: str = "Batch group undo",
        actor: str = "analyst"
    ) -> UndoBatchResponse:
        """
        Undo toàn bộ các response action đang có hiệu lực trên tất cả các agent thuộc một nhóm.
        Khôi phục đồng thời các máy trong nhóm về trạng thái an toàn (unisolate, unblock_ip...).
        """
        group = await self.group_repo.get(group_id)
        if not group:
            raise NotFoundError(f"Agent group with ID '{group_id}' was not found.")

        agents = await self.group_repo.get_agents_in_group(group_id)
        agent_ids = [a.id for a in agents]

        if not agent_ids:
            return UndoBatchResponse(reverted=0, failed=0, action_ids=[], details=[])

        actions = await self.action_repo.get_active_applied_by_agents(agent_ids)
        reverted_ids = []
        failed_count = 0
        details = []

        for act in actions:
            try:
                await self.rollback_action(
                    action_id=act.id,
                    reason=f"{reason} (Group: {group.name})",
                    actor=actor
                )
                reverted_ids.append(act.id)
                details.append({"action_id": act.id, "agent_id": act.agent_id, "status": "reverted"})
            except Exception as e:
                failed_count += 1
                details.append({"action_id": act.id, "agent_id": act.agent_id, "status": "failed", "error": str(e)})

        logger.info(
            f"Batch rollback on group '{group.name}' completed: "
            f"{len(reverted_ids)} reverted, {failed_count} failed."
        )

        return UndoBatchResponse(
            reverted=len(reverted_ids),
            failed=failed_count,
            action_ids=reverted_ids,
            details=details
        )
