from typing import Optional
from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.whitelist import WhitelistEntry
from app.repositories.base import SqlAlchemyRepository


class WhitelistRepository(SqlAlchemyRepository[WhitelistEntry]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, WhitelistEntry)

    async def is_whitelisted(
        self,
        agent_id: Optional[str] = None,
        process_name: Optional[str] = None,
        path: Optional[str] = None
    ) -> bool:
        """
        Check if a given agent/process/path matches any whitelist entry.
        Matching logic:
        Entry matches if:
          - (entry.agent_id is null OR entry.agent_id == agent_id) AND
          - ((entry.process_name is not null AND entry.process_name == process_name) OR
             (entry.path is not null AND entry.path == path))
        """
        conditions = []
        if process_name:
            conditions.append(WhitelistEntry.process_name == process_name)
        if path:
            conditions.append(WhitelistEntry.path == path)

        if not conditions:
            if agent_id:
                stmt = select(WhitelistEntry).where(WhitelistEntry.agent_id == agent_id)
                res = await self.session.execute(stmt)
                return res.scalar_one_or_none() is not None
            return False

        match_target = or_(*conditions)
        if agent_id:
            agent_match = or_(WhitelistEntry.agent_id.is_(None), WhitelistEntry.agent_id == agent_id)
        else:
            agent_match = WhitelistEntry.agent_id.is_(None)

        stmt = select(WhitelistEntry).where(and_(agent_match, match_target))
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none() is not None
