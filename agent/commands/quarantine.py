from typing import Any, Dict
from .base import BaseCommand


class QuarantineCommand(BaseCommand):
    name = "quarantine"

    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        # Host "quarantine mode" was never implemented: report it instead of a success that changed nothing.
        return {"status": "failed", "message": "Host quarantine mode is not supported; use isolate or quarantine_file"}


class ReleaseQuarantineCommand(BaseCommand):
    name = "release_quarantine"

    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        return {"status": "failed", "message": "Host quarantine mode is not supported"}
