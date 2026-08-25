import os
import signal
import psutil
import logging
from typing import Any, Dict
from .base import BaseCommand

logger = logging.getLogger(__name__)


class KillProcessTreeCommand(BaseCommand):
    name = "kill_process_tree"

    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        pid = params.get("pid")
        process_name = params.get("process_name")
        
        killed_pids = []
        errors = []

        # 1. Kill process tree starting from PID
        if pid:
            try:
                target_pid = int(pid)
                if psutil.pid_exists(target_pid):
                    parent = psutil.Process(target_pid)
                    children = parent.children(recursive=True)

                    # Kill children first in reverse order (bottom-up) to avoid orphan/zombie processes
                    for child in reversed(children):
                        try:
                            child.kill()
                            killed_pids.append(child.pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    # Kill parent process
                    try:
                        parent.kill()
                        killed_pids.append(parent.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, ValueError):
                pass
            except Exception as e:
                errors.append(f"PID {pid}: {str(e)}")

        # 2. Fallback: Search by process_name if provided and no PIDs killed yet
        if process_name and not killed_pids:
            try:
                pname_lower = str(process_name).strip().lower()
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        p_info = proc.info
                        p_name = str(p_info.get('name') or "").lower()
                        p_cmd = " ".join(p_info.get('cmdline') or []).lower()

                        if pname_lower in p_name or (p_cmd and pname_lower in p_cmd):
                            try:
                                children = proc.children(recursive=True)
                                for c in reversed(children):
                                    c.kill()
                                    killed_pids.append(c.pid)
                                proc.kill()
                                killed_pids.append(proc.pid)
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except Exception as e:
                errors.append(f"Name {process_name}: {str(e)}")

        # 3. Reap any zombie processes
        try:
            psutil.wait_procs([], timeout=0.1)
        except Exception:
            pass

        if killed_pids:
            msg = f"Successfully terminated process tree (Killed PIDs: {killed_pids})"
            logger.info(f"[KillProcessTree] {msg}")
            return {"status": "success", "message": msg, "killed_pids": killed_pids}
        elif errors:
            return {"status": "failed", "message": f"Failed to kill process tree: {'; '.join(errors)}"}
        else:
            return {"status": "success", "message": f"No active matching process tree found for PID {pid} / Name '{process_name}'"}
