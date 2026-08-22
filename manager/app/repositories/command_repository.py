from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.command import Command
from app.schemas.enums import CommandStatus
from app.repositories.base import SqlAlchemyRepository


class CommandRepository(SqlAlchemyRepository[Command]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, Command)

    async def get_pending_by_agent(self, agent_id: str) -> List[Command]:
        stmt = select(Command).where(
            Command.agent_id == agent_id,
            Command.status == CommandStatus.PENDING
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self, command_id: str, status: CommandStatus, error_message: Optional[str] = None
    ) -> Optional[Command]:
        cmd = await self.get(command_id)
        if cmd:
            cmd.acknowledge(status, error_message)
            await self.session.flush()
            await self.session.refresh(cmd)
        return cmd
