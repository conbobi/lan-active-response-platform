import uuid
import logging
from typing import Dict, List, Any, Optional
import networkx as nx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.command import Command
from app.schemas.enums import CommandStatus
from app.repositories.process_info_repository import ProcessInfoRepository
from app.repositories.command_repository import CommandRepository
from app.services.command_dispatcher import command_dispatcher

logger = logging.getLogger(__name__)


class ProcessTreeService:
    """
    Process Tree & Root Cause Analysis Service.
    Uses NetworkX directed graphs to construct parent-child process hierarchies,
    trace suspicious process lineage, and issue process termination commands.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.process_repo = ProcessInfoRepository(session)

    async def build_tree(self, agent_id: str) -> Dict[str, Any]:
        """
        Fetch latest process telemetry for an agent, construct a directed graph (DiGraph),
        and format process hierarchy into a structured JSON tree.
        """
        processes = await self.process_repo.get_by_agent(agent_id, limit=200)
        if not processes:
            return {"agent_id": agent_id, "nodes": [], "edges": [], "tree": []}

        G = nx.DiGraph()
        proc_dict = {}

        for p in processes:
            proc_dict[p.pid] = {
                "pid": p.pid,
                "parent_pid": p.parent_pid,
                "name": p.name,
                "exe": p.exe or p.exe_path or "",
                "cmdline": p.cmdline,
                "cpu_percent": p.cpu_percent,
                "memory_percent": p.memory_percent,
                "hash": p.hash,
                "is_suspicious": p.is_suspicious_process(),
                "created_at": p.created_at.isoformat() if p.created_at else None
            }
            G.add_node(p.pid, **proc_dict[p.pid])

        for p in processes:
            if p.parent_pid and p.parent_pid in proc_dict:
                G.add_edge(p.parent_pid, p.pid)

        # Build root nodes (nodes with in-degree 0 or parent not in snapshot)
        roots = [n for n in G.nodes() if G.in_degree(n) == 0]

        def get_subtree(node_id):
            node_data = proc_dict.get(node_id, {"pid": node_id})
            children = [get_subtree(child) for child in G.successors(node_id)]
            node_data["children"] = children
            return node_data

        tree_nodes = [get_subtree(r) for r in roots]

        return {
            "agent_id": agent_id,
            "total_processes": len(processes),
            "root_count": len(roots),
            "tree": tree_nodes
        }

    async def find_suspicious_process(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Identify suspicious processes for an agent and trace their parent execution chain.
        """
        processes = await self.process_repo.get_by_agent(agent_id, limit=200)
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

                suspicious_list.append({
                    "pid": p.pid,
                    "parent_pid": p.parent_pid,
                    "name": p.name,
                    "exe": p.exe or p.exe_path or "",
                    "cmdline": p.cmdline,
                    "hash": p.hash,
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
