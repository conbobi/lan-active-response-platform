# manager/app/websocket/connection_manager.py
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, agent_id: str, websocket: WebSocket):
        self.active_connections[agent_id] = websocket

    def disconnect(self, agent_id: str):
        self.active_connections.pop(agent_id, None)

    async def send_command(self, agent_id: str, message: str):
        if agent_id in self.active_connections:
            await self.active_connections[agent_id].send_text(message)

manager = ConnectionManager()
