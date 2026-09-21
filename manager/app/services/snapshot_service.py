import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.agent_repository import AgentRepository

logger = logging.getLogger(__name__)


class SnapshotService:
    """
    Service chuyên trách chụp (capture) và diễn giải snapshot trạng thái agent
    trước khi áp dụng response action để phục vụ cho việc undo/rollback.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.agent_repo = AgentRepository(session)

    async def capture_snapshot(
        self,
        agent_id: str,
        action_type: str,
        action_params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Chụp snapshot trạng thái hiện tại của Agent trước khi thực hiện response action.
        """
        agent = await self.agent_repo.get(agent_id)
        current_time = datetime.now(timezone.utc).isoformat()

        snapshot: Dict[str, Any] = {
            "captured_at": current_time,
            "agent_id": agent_id,
            "action_type": action_type,
            "agent_state": {
                "status": agent.status.value if (agent and hasattr(agent.status, "value")) else "active",
                "is_isolated": getattr(agent, "is_isolated", False),
                "hostname": getattr(agent, "hostname", None),
                "ip_address": getattr(agent, "ip_address", None)
            }
        }

        if action_type in ("isolate", "auto_isolate"):
            snapshot["network"] = {
                "pre_action_isolated": getattr(agent, "is_isolated", False),
                "iptables_state": "unrestricted"
            }
        elif action_type == "quarantine":
            snapshot["quarantine"] = {
                "pre_action_status": agent.status.value if (agent and hasattr(agent.status, "value")) else "active",
            }
        elif action_type in ("kill", "kill_process", "kill_process_tree"):
            snapshot["process"] = {
                "target_pid": action_params.get("pid"),
                "target_name": action_params.get("process_name"),
                "restartable": False,
                "note": "Process memory state cannot be restored; snapshot records process metadata"
            }
        elif action_type == "block_ip":
            snapshot["firewall"] = {
                "blocked_ip": action_params.get("ip") or action_params.get("target_ip"),
                "direction": action_params.get("direction", "both")
            }

        logger.info(f"Captured pre-action snapshot for agent '{agent_id}', action '{action_type}'.")
        return snapshot

    def get_compensation_action(
        self,
        action_type: str,
        action_params: Dict[str, Any],
        snapshot: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Xác định command đảo nghịch (compensation command) tương ứng để rollback action.
        """
        if action_type in ("isolate", "auto_isolate"):
            return {
                "command_action": "unisolate",
                "payload": {},
                "restore_agent_status": "active",
                "restore_is_isolated": False
            }
        elif action_type == "quarantine":
            return {
                "command_action": "release_quarantine",
                "payload": {},
                "restore_agent_status": "active",
                "restore_is_isolated": False
            }
        elif action_type == "block_ip":
            target_ip = action_params.get("ip") or action_params.get("target_ip")
            return {
                "command_action": "unblock_ip",
                "payload": {"ip": target_ip},
                "restore_agent_status": None,
                "restore_is_isolated": None
            }
        elif action_type in ("kill", "kill_process", "kill_process_tree"):
            return {
                "command_action": None,
                "payload": {},
                "restore_agent_status": None,
                "restore_is_isolated": None,
                "note": "Process terminated cannot be automatically re-spawned"
            }
        else:
            return {
                "command_action": None,
                "payload": {},
                "restore_agent_status": None,
                "restore_is_isolated": None
            }
