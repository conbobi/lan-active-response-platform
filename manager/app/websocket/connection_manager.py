import logging
from typing import Dict, ClassVar, Optional
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Singleton ConnectionManager managing active WebSocket connections per agent.
    """
    _instance: ClassVar[Optional["ConnectionManager"]] = None

    def __new__(cls) -> "ConnectionManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.active_connections: Dict[str, WebSocket] = {}
        return cls._instance

    @classmethod
    def get_instance(cls) -> "ConnectionManager":
        return cls()

    async def connect(self, agent_id: str, websocket: WebSocket) -> None:
        """Accept WebSocket connection and register agent."""
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        logger.info(f"WebSocket connected for agent '{agent_id}'. Total connections: {len(self.active_connections)}")

    def disconnect(self, agent_id: str) -> None:
        """Unregister agent WebSocket connection."""
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            logger.info(f"WebSocket disconnected for agent '{agent_id}'. Remaining: {len(self.active_connections)}")

    async def send_personal_message(self, message: dict, agent_id: str) -> bool:
        """Send JSON message to a specific connected agent."""
        ws = self.active_connections.get(agent_id)
        if ws:
            try:
                await ws.send_json(message)
                return True
            except Exception as e:
                logger.error(f"Failed to send WS message to agent '{agent_id}': {e}")
                self.disconnect(agent_id)
        return False

    async def broadcast(self, message: dict) -> None:
        """Broadcast JSON message to all connected agents."""
        disconnected = []
        for agent_id, ws in self.active_connections.items():
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.error(f"Broadcast error for agent '{agent_id}': {e}")
                disconnected.append(agent_id)

        for agent_id in disconnected:
            self.disconnect(agent_id)


connection_manager = ConnectionManager()
