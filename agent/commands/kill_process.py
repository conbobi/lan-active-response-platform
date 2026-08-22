import os
import signal
from typing import Any, Dict
from .base import BaseCommand


class KillProcessCommand(BaseCommand):
    name = "kill_process"

    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        pid = params.get("pid")
        if not pid:
            return {"status": "failed", "message": "No PID provided"}

        try:
            os.kill(int(pid), signal.SIGKILL)
            return {"status": "success", "message": f"Successfully killed process {pid}"}
        except Exception as e:
            return {"status": "failed", "message": f"Failed to kill process {pid}: {str(e)}"}
