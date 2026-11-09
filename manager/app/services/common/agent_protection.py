import logging
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Pattern names of LARP Agent binaries and core scripts
AGENT_PROCESS_NAMES = {
    "win_agent_minimal.py",
    "win_agent_minimal.exe",
    "larp_agent.exe",
    "win_agent_service.py",
    "watchdog.py",
    "agent.py",
    "win_agent.py",
}

# Legitimate commands invoked by the LARP Agent
AGENT_CHILD_PATTERNS = [
    "netsh advfirewall",
    "netsh",
    "taskkill",
    "taskkill /f",
    "get-nettcpconnection",
    "larp_block",
    "larp_allow",
]


def is_agent_process(process: Any) -> bool:
    """
    Check if a process (dict or ProcessInfo object) is the LARP agent itself
    or one of its legitimate child commands (netsh, taskkill, powershell).
    """
    if process is None:
        return False

    if hasattr(process, "name"):
        name = (getattr(process, "name", "") or "").lower()
        cmdline = (getattr(process, "cmdline", "") or "").lower()
        parent_name = (getattr(process, "parent_name", "") or "").lower()
        exe = (getattr(process, "exe", "") or "").lower()
        exe_path = (getattr(process, "exe_path", "") or "").lower()
    elif isinstance(process, dict):
        name = (process.get("name") or "").lower()
        cmdline = (process.get("cmdline") or "").lower()
        parent_name = (process.get("parent_name") or "").lower()
        exe = (process.get("exe") or "").lower()
        exe_path = (process.get("exe_path") or "").lower()
    else:
        return False

    # 1. Check agent executable or script name in name, cmdline, exe, exe_path
    for agent_name in AGENT_PROCESS_NAMES:
        if (
            agent_name in name
            or agent_name in cmdline
            or agent_name in exe
            or agent_name in exe_path
        ):
            return True

    # 2. Check direct isolation or agent firewall/kill command patterns in cmdline
    if any(pat in cmdline for pat in ("larp_block", "larp_allow", "netsh advfirewall")):
        return True

    # 3. Check child commands of Python / Agent
    is_agent_parent = (
        parent_name in ("python.exe", "python3.exe", "python", "win_agent_minimal.exe", "larp_agent.exe")
        or "win_agent" in parent_name
        or any(an in parent_name for an in AGENT_PROCESS_NAMES)
    )

    if is_agent_parent:
        if any(pat in cmdline for pat in AGENT_CHILD_PATTERNS):
            return True
        if name in ("netsh.exe", "netsh", "taskkill.exe", "taskkill"):
            return True

    return False


def check_agent_kill_protection(
    process_tree: List[Any],
    target_pid: int
) -> Tuple[bool, Optional[str]]:
    """
    Checks if terminating target_pid is safe:
    Returns (True, None) if allowed.
    Returns (False, reason) if target is agent, has agent ancestor, or has agent descendant.
    """
    if not process_tree or not target_pid:
        return True, None

    pid_map: Dict[int, Any] = {}
    for p in process_tree:
        p_pid = getattr(p, "pid", None) if hasattr(p, "pid") else p.get("pid")
        if p_pid is not None:
            try:
                pid_map[int(p_pid)] = p
            except (ValueError, TypeError):
                pass

    target = pid_map.get(target_pid)
    # Check 1: Target itself
    if target and is_agent_process(target):
        return False, "target is LARP agent or legitimate child"

    # Check 2: Ancestors (if target has an ancestor that is the agent)
    curr = target
    visited_anc = set()
    while curr:
        curr_ppid = getattr(curr, "parent_pid", None) if hasattr(curr, "parent_pid") else curr.get("parent_pid")
        if not curr_ppid:
            break
        try:
            ppid_int = int(curr_ppid)
        except (ValueError, TypeError):
            break
        if ppid_int in visited_anc:
            break
        visited_anc.add(ppid_int)
        parent = pid_map.get(ppid_int)
        if parent:
            if is_agent_process(parent):
                return False, f"target {target_pid} has agent ancestor (PID {ppid_int})"
            curr = parent
        else:
            break

    # Check 3: Descendants (if any descendant of target is the agent)
    children_map: Dict[int, List[Any]] = {}
    for p in process_tree:
        p_ppid = getattr(p, "parent_pid", None) if hasattr(p, "parent_pid") else p.get("parent_pid")
        if p_ppid is not None:
            try:
                children_map.setdefault(int(p_ppid), []).append(p)
            except (ValueError, TypeError):
                pass

    queue = list(children_map.get(target_pid, []))
    visited_desc = set()
    while queue:
        child = queue.pop(0)
        c_pid = getattr(child, "pid", None) if hasattr(child, "pid") else child.get("pid")
        try:
            c_pid_int = int(c_pid)
        except (ValueError, TypeError):
            continue
        if c_pid_int in visited_desc:
            continue
        visited_desc.add(c_pid_int)
        if is_agent_process(child):
            return False, f"target {target_pid} has agent descendant (PID {c_pid_int})"
        queue.extend(children_map.get(c_pid_int, []))

    return True, None

