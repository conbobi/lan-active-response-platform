from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.whitelist import WhitelistEntry
from app.repositories.whitelist_repository import WhitelistRepository
from app.schemas.whitelist import WhitelistEntryCreate
from app.services.base import AbstractService


class WhitelistService(AbstractService[WhitelistRepository]):
    """Service managing system whitelist entries for agents, processes, and paths."""

    def __init__(self, session: AsyncSession):
        repo = WhitelistRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def add_entry(self, dto: WhitelistEntryCreate) -> WhitelistEntry:
        """Add a new whitelist entry."""
        entry = WhitelistEntry(
            agent_id=dto.agent_id,
            process_name=dto.process_name,
            path=dto.path,
            reason=dto.reason
        )
        return await self.repository.add(entry)

    async def remove_entry(self, entry_id: str) -> bool:
        """Remove a whitelist entry by ID."""
        return await self.repository.delete(entry_id)

    async def is_whitelisted(
        self,
        agent_id: Optional[str] = None,
        process_name: Optional[str] = None,
        path: Optional[str] = None
    ) -> bool:
        """Check if an agent, process, or file path is whitelisted."""
        return await self.repository.is_whitelisted(
            agent_id=agent_id,
            process_name=process_name,
            path=path
        )

    async def list_entries(self, skip: int = 0, limit: int = 100) -> List[WhitelistEntry]:
        """List all whitelist entries."""
        return await self.repository.list(skip=skip, limit=limit)
