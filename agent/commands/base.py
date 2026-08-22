from abc import ABC, abstractmethod
from typing import Any, Dict
import asyncio

class BaseCommand(ABC):
    """Base class for all agent commands."""
    name: str = ""

    @abstractmethod
    async def execute(self, params: Dict[str, Any], websocket) -> Dict[str, Any]:
        """Execute the command and return ack payload."""
        pass