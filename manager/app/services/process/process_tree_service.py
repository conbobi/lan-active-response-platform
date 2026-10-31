import uuid
import logging
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.command import Command
from app.schemas.enums import CommandStatus
from app.repositories.process_info_repository import ProcessInfoRepository
from app.repositories.command_repository import CommandRepository
from app.services.core.command_dispatcher import command_dispatcher

logger = logging.getLogger(__name__)


class ProcessTreeService:
    """
    Process Tree & Root Cause Analysis Service.
    Constructs parent-child process hierarchies from snapshot telemetry,
    traces suspicious process lineage, and issues process termination commands.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.process_repo = ProcessInfoRepository(session)

    async def build_tree(self, agent_id: str) -> Dict[str, Any]:
        """
        Fetch latest process telemetry for an agent and format process hierarchy into a structured JSON tree.
        Natural roots = processes with parent_pid not in snapshot, parent_pid = 0/None, or parent_pid = pid (self-loop).
        """
        processes = await self.process_repo.get_by_agent(agent_id, limit=500)
        if not processes:
            return {"agent_id": agent_id, "total_processes": 0, "root_count": 0, "tree": []}

        # Map pid -> process
        pid_map = {p.pid: p for p in processes}

        # Find natural roots
        roots = []
        for p in processes:
            ppid = p.parent_pid
            is_root = (
                ppid is None or
                ppid == 0 or
                ppid == p.pid or
                ppid not in pid_map
            )
            if is_root:
                roots.append(p)

        # Fallback if no root found
        if not roots and processes:
            roots = [min(processes, key=lambda x: x.pid)]

        # Build children map
        children_map = {}
        for p in processes:
            ppid = p.parent_pid
            if ppid is None or ppid == p.pid or ppid not in pid_map:
                continue
            children_map.setdefault(ppid, []).append(p)

        # Recursive build node with branch path cycle detection
        def build_node(proc, depth=0, path=None):
            if path is None:
                path = set()
            if depth > 50 or proc.pid in path:
                return self._proc_to_dict(proc, [])
            current_path = path | {proc.pid}
            children = children_map.get(proc.pid, [])
            return self._proc_to_dict(
                proc,
                [build_node(c, depth + 1, current_path) for c in children if c.pid not in current_path]
            )

        tree = [build_node(r) for r in roots]

        return {
            "agent_id": agent_id,
            "total_processes": len(processes),
            "root_count": len(tree),
            "tree": tree,
        }

    def _proc_to_dict(self, proc, children: list) -> dict:
        return {
            "pid": proc.pid,
            "parent_pid": proc.parent_pid,
            "name": proc.name,
            "exe": proc.exe or getattr(proc, "exe_path", "") or "",
            "cmdline": proc.cmdline or "",
            "cpu_percent": float(proc.cpu_percent or 0),
            "memory_percent": float(proc.memory_percent or 0),
            "hash": proc.hash,
            "is_suspicious": proc.is_suspicious_process() if hasattr(proc, "is_suspicious_process") else bool(getattr(proc, "is_suspicious", False)),
            "created_at": proc.created_at.isoformat() if proc.created_at else None,
            "children": children,
        }

    async def find_suspicious_process(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Identify suspicious processes for an agent and trace their parent execution chain.
        """
        processes = await self.process_repo.get_by_agent(agent_id, limit=500)
        proc_map = {p.pid: p for p in processes}

        suspicious_list = []
        for p in processes:
            if p.is_suspicious_process():
                # Trace parent chain
                chain = []
                curr_ppid = p.parent_pid
                depth = 0
                while curr_ppid and curr_ppid in proc_map and depth < 10:
                    parent_proc = proc_map[curr_ppid]
                    chain.append({
                        "pid": parent_proc.pid,
                        "name": parent_proc.name,
                        "exe": parent_proc.exe or parent_proc.exe_path or ""
                    })
                    curr_ppid = parent_proc.parent_pid
                    depth += 1

                reason = "Suspicious binary pattern / cmdline flagged"
                if p.exe and ("/tmp/" in p.exe or "/dev/shm" in p.exe):
                    reason = "Process executing from temporary directory (/tmp or /dev/shm)"

                suspicious_list.append({
                    "pid": p.pid,
                    "parent_pid": p.parent_pid,
                    "name": p.name,
                    "exe": p.exe or p.exe_path or "",
                    "path": p.exe or p.exe_path or "",
                    "cmdline": p.cmdline,
                    "cpu_percent": p.cpu_percent,
                    "memory_percent": p.memory_percent,
                    "hash": p.hash,
                    "reason": reason,
                    "parent_chain": chain
                })

        return suspicious_list

    async def kill_process(self, agent_id: str, pid: int) -> Command:
        """
        Generate and push a 'kill_process' command to terminate a specific process on an agent.
        """
        cmd_repo = CommandRepository(self.session)
        cmd = Command(
            id=f"cmd_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            action="kill_process",
            payload={"pid": pid, "reason": "Terminated by Root Cause Analysis operator"},
            status=CommandStatus.PENDING
        )
        await cmd_repo.add(cmd)
        await command_dispatcher.push_command(cmd.id, agent_id)
        await self.session.flush()
        logger.info(f"Pushed kill_process command for PID {pid} on agent '{agent_id}'.")
        return cmd

    async def kill_process_tree(
        self, agent_id: str, pid: int, process_name: Optional[str] = None, reason: Optional[str] = None
    ) -> Command:
        """
        Generate and push a 'kill_process_tree' command to terminate a process and all its children on an agent.
        """
        cmd_repo = CommandRepository(self.session)
        cmd = Command(
            id=f"cmd_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            action="kill_process_tree",
            payload={
                "pid": pid,
                "process_name": process_name,
                "reason": reason or "Terminated by Process Tree / Risk Assessment"
            },
            status=CommandStatus.PENDING
        )
        await cmd_repo.add(cmd)
        await command_dispatcher.push_command(cmd.id, agent_id)
        await self.session.flush()
        logger.info(f"Pushed kill_process_tree command for PID {pid} ({process_name}) on agent '{agent_id}'.")
        return cmd
