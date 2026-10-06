import asyncio
import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.command_repository import CommandRepository
from app.schemas.command_ack import CommandAckDTO
from app.schemas.enums import CommandStatus
from app.models.command import Command

logger = logging.getLogger(__name__)


class CommandDispatcher:
    """
    CommandDispatcher implements an Observer/Queue pattern for managing agent commands.
    """
    def __init__(self):
        self.pending_queue: asyncio.Queue = asyncio.Queue()
        # In-memory mapping of agent_id -> list of command_ids
        self._agent_queues: Dict[str, List[str]] = {}

    async def push_command(self, command_id: str, agent_id: str) -> None:
        """Push command into queue for dispatching."""
        if agent_id not in self._agent_queues:
            self._agent_queues[agent_id] = []
        self._agent_queues[agent_id].append(command_id)
        await self.pending_queue.put(command_id)
        logger.info(f"Command '{command_id}' queued for agent '{agent_id}'.")

    async def pull_pending_commands(self, agent_id: str, session: AsyncSession) -> List[Command]:
        """Pull and mark pending commands for a specific agent."""
        repo = CommandRepository(session)
        pending = await repo.get_pending_by_agent(agent_id)
        for cmd in pending:
            cmd.send_to_agent()
        await session.flush()
        # Clear in-memory queue for this agent
        self._agent_queues.pop(agent_id, None)
        return pending

    async def verify_execution(self, ack_data: CommandAckDTO, session: AsyncSession) -> Optional[Command]:
        """Verify command execution acknowledgement from agent."""
        repo = CommandRepository(session)
        cmd = await repo.get(ack_data.command_id)
        if not cmd:
            logger.warning(f"Ack received for unknown command '{ack_data.command_id}'.")
            return None

        cmd.acknowledge(ack_data.status, ack_data.error_message)
        if ack_data.status == CommandStatus.FAILED:
            logger.warning(f"Command '{cmd.id}' failed on agent '{cmd.agent_id}'. Checking retry...")
            await self.schedule_retry(cmd, session)
        else:
            logger.info(f"Command '{cmd.id}' executed successfully on agent '{cmd.agent_id}'.")

        await session.flush()
        return cmd

    async def schedule_retry(self, cmd: Command, session: AsyncSession) -> bool:
        """Schedule a retry for a failed command if retries remain."""
        if cmd.retry():
            logger.info(f"Retrying command '{cmd.id}' (Attempt {cmd.retry_count}/{cmd.max_retries}).")
            await self.push_command(cmd.id, cmd.agent_id)
            return True
        else:
            logger.error(f"Command '{cmd.id}' exceeded max retries. Marked FAILED.")
            return False


command_dispatcher = CommandDispatcher()
