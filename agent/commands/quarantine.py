from typing import Any, Dict
from .base import BaseCommand


class QuarantineCommand(BaseCommand):
    name = "quarantine"

    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        reason = params.get("reason", "Quarantine requested")
        return {"status": "success", "message": f"Agent placed in quarantine mode: {reason}"}


class ReleaseQuarantineCommand(BaseCommand):
    name = "release_quarantine"

    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        return {"status": "success", "message": "Quarantine mode released successfully"}
