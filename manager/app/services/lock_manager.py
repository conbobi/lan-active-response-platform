import asyncio
from typing import Dict, Optional, ClassVar


class LockManager:
    """
    Singleton LockManager providing asyncio mutex locks per topology link_id.
    """
    _instance: ClassVar[Optional["LockManager"]] = None

    def __new__(cls) -> "LockManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._locks: Dict[str, asyncio.Lock] = {}
        return cls._instance

    @classmethod
    def get_instance(cls) -> "LockManager":
        return cls()

    def _get_lock(self, link_id: str) -> asyncio.Lock:
        if link_id not in self._locks:
            self._locks[link_id] = asyncio.Lock()
        return self._locks[link_id]

    async def acquire_lock(self, link_id: str) -> bool:
        """Acquire lock for given link_id."""
        lock = self._get_lock(link_id)
        await lock.acquire()
        return True

    def release_lock(self, link_id: str) -> None:
        """Release lock for given link_id if held."""
        if link_id in self._locks:
            lock = self._locks[link_id]
            if lock.locked():
                lock.release()

    def is_locked(self, link_id: str) -> bool:
        """Check if lock for given link_id is currently held."""
        if link_id in self._locks:
            return self._locks[link_id].locked()
        return False