from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.command import Command
from app.repositories.command_repository import CommandRepository
from app.schemas.command import CommandCreate
from app.schemas.command_ack import CommandAckDTO
from app.schemas.enums import CommandStatus
from app.core.exceptions import BadRequestError, NotFoundError
from app.core.network_security import is_reserved_action
from app.core.response_safety import PROTECTED_COMMANDS
from app.services.core.base import AbstractService
from app.services.core.command_dispatcher import command_dispatcher


class CommandService(AbstractService[CommandRepository]):
    def __init__(self, session: AsyncSession):
        repo = CommandRepository(session)
        super().__init__(repository=repo)
        self.session = session

    async def issue_command(self, dto: CommandCreate) -> Command:
        if is_reserved_action(dto.action):
            raise BadRequestError("Use the authenticated network action endpoint")
        if dto.action in PROTECTED_COMMANDS:
            raise BadRequestError("Use a confirmed response action for this command")
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
        if not cmd or is_reserved_action(cmd.action):
            raise NotFoundError(f"Command '{command_id}' not found.")
        return cmd

    async def list_commands(self, skip: int = 0, limit: int = 100) -> List[Command]:
        from sqlalchemy import select
        statement = select(Command).where(~Command.action.startswith("network_", autoescape=True)).offset(skip).limit(limit)
        return list((await self.session.scalars(statement)).all())

    async def process_ack(self, ack_data: CommandAckDTO) -> Command:
        existing = await self.repository.get(ack_data.command_id)
        if existing and existing.action in PROTECTED_COMMANDS:
            raise BadRequestError("Response acknowledgements must arrive through the Agent connection")
        cmd = await command_dispatcher.verify_execution(ack_data, self.session)
        if not cmd:
            raise NotFoundError(f"Command '{ack_data.command_id}' not found.")
        return cmd
