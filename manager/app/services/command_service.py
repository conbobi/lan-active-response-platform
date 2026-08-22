from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.command import Command
from app.repositories.command_repository import CommandRepository
from app.schemas.command import CommandCreate
from app.schemas.command_ack import CommandAckDTO
from app.schemas.enums import CommandStatus
from app.core.exceptions import NotFoundError
from app.services.base import AbstractService
from app.services.command_dispatcher import command_dispatcher


class CommandService(AbstractService[CommandRepository]):
    def __init__(self, session: AsyncSession):
        repo = CommandRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def issue_command(self, dto: CommandCreate) -> Command:
        cmd = Command(
            id=dto.id,
            agent_id=dto.agent_id,
            action=dto.action,
            payload=dto.payload,
            status=CommandStatus.PENDING,
            max_retries=dto.max_retries
        )
        created = await self.repository.add(cmd)
        await command_dispatcher.push_command(cmd.id, cmd.agent_id)
        return created

    async def get_command(self, command_id: str) -> Command:
        cmd = await self.repository.get(command_id)
        if not cmd:
            raise NotFoundError(f"Command '{command_id}' not found.")
        return cmd

    async def list_commands(self, skip: int = 0, limit: int = 100) -> List[Command]:
        return await self.repository.list(skip=skip, limit=limit)

    async def process_ack(self, ack_data: CommandAckDTO) -> Command:
        cmd = await command_dispatcher.verify_execution(ack_data, self.session)
        if not cmd:
            raise NotFoundError(f"Command '{ack_data.command_id}' not found.")
        return cmd
