import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.agent_repository import AgentRepository
from app.repositories.process_info_repository import ProcessInfoRepository

logger = logging.getLogger(__name__)


class SnapshotService:
    """
    Service chuyên trách chụp (capture) và diễn giải snapshot trạng thái agent
    trước khi áp dụng response action để phục vụ cho việc undo/rollback.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.agent_repo = AgentRepository(session)
        self.proc_repo = ProcessInfoRepository(session)

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
            file_path = action_params.get("file_path") or action_params.get("path")
            snapshot["file"] = {
                "path": file_path,
                "hash_sha256": action_params.get("sha256") or action_params.get("hash_sha256") or "",
                "size": action_params.get("size") or 0,
                "quarantine_path": action_params.get("quarantine_path"),
            }
            snapshot["quarantine"] = {
                "pre_action_status": agent.status.value if (agent and hasattr(agent.status, "value")) else "active",
            }
        elif action_type in ("kill", "kill_process", "kill_process_tree"):
            raw_pid = action_params.get("pid") or action_params.get("target_pid")
            pid_int = None
            if raw_pid is not None:
                try:
                    pid_int = int(raw_pid)
                except (ValueError, TypeError):
                    pass

            target_proc = None
            if pid_int is not None:
                try:
                    procs = await self.proc_repo.find_by_agent(agent_id)
                    target_proc = next((p for p in procs if p.pid == pid_int), None)
                except Exception as e:
                    logger.debug(f"Could not load process details for snapshot: {e}")

            if target_proc:
                snapshot["process"] = {
                    "pid": target_proc.pid,
                    "target_pid": target_proc.pid,
                    "name": target_proc.name,
                    "target_name": target_proc.name,
                    "exe": getattr(target_proc, "exe", None) or getattr(target_proc, "exe_path", None) or "",
                    "cmdline": getattr(target_proc, "cmdline", "") or "",
                    "parent_pid": getattr(target_proc, "parent_pid", None),
                    "restartable": False,
                    "note": "Process memory state cannot be restored; snapshot records process metadata"
                }
            else:
                snapshot["process"] = {
                    "pid": pid_int,
                    "target_pid": pid_int,
                    "name": action_params.get("process_name"),
                    "target_name": action_params.get("process_name"),
                    "restartable": False,
                    "note": "Process memory state cannot be restored; snapshot records process metadata"
                }
        elif action_type == "remove_registry":
            key_path = action_params.get("key_path")
            value_name = action_params.get("value_name")
            backup_file = action_params.get("backup_file")
            snapshot["registry"] = {
                "key_path": key_path,
                "value_name": value_name,
                "backup_file": backup_file,
            }
            snapshot["backup_file"] = backup_file
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
        snapshot = snapshot or {}

        if action_type in ("isolate", "auto_isolate"):
            return {
                "command_action": "unisolate",
                "payload": {},
                "restore_agent_status": "active",
                "restore_is_isolated": False
            }
        elif action_type == "quarantine":
            file_info = snapshot.get("file", {})
            target_path = file_info.get("path") or action_params.get("file_path") or action_params.get("path")
            source_path = (
                file_info.get("quarantine_path")
                or snapshot.get("quarantine_path")
                or action_params.get("quarantine_path")
            )
            if not source_path and file_info.get("hash_sha256"):
                source_path = f"C:\\ProgramData\\LARP\\Quarantine\\{file_info.get('hash_sha256')}"

            return {
                "command_action": "restore_file",
                "payload": {
                    "source_path": source_path,
                    "target_path": target_path
                },
                "restore_agent_status": "active",
                "restore_is_isolated": False
            }
        elif action_type == "remove_registry":
            registry_info = snapshot.get("registry", {})
            backup_file = (
                registry_info.get("backup_file")
                or snapshot.get("backup_file")
                or action_params.get("backup_file")
            )
            return {
                "command_action": "restore_registry",
                "payload": {
                    "backup_file": backup_file,
                    "key_path": registry_info.get("key_path") or action_params.get("key_path")
                },
                "restore_agent_status": None,
                "restore_is_isolated": None
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
