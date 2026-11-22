import asyncio
import os

from network_sources import CollectionError

from .base import BaseCommand
from .scoped_isolation import scoped_isolation


class IsolateCommand(BaseCommand):
    name = "isolate"

    async def execute(self, params, websocket):
        manager = os.getenv("MANAGER_URL", "wss://edr.alwayready.id.vn/ws/agent")
        try:
            return await asyncio.to_thread(scoped_isolation, self.name, manager, getattr(websocket, "remote_address", None))
        except (CollectionError, OSError, ValueError) as error:
            return {"status": "failed", "message": str(error)}
