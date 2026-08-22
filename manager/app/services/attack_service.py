import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.command import Command
from app.repositories.command_repository import CommandRepository
from app.services.command_dispatcher import command_dispatcher
from app.schemas.enums import CommandStatus
from datetime import datetime, timezone

class AttackService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.command_repo = CommandRepository(db)

    async def launch_syn_flood(self, dto) -> Command:
        command = Command(
            id=f"cmd_{uuid.uuid4().hex[:12]}",
            agent_id="attacker",   # Gửi lệnh đến attacker agent
            action="syn_flood",
            payload={
                "target_ip": dto.target_ip,
                "target_port": dto.target_port,
                "duration": dto.duration,
                "target_agent_id": dto.target_agent_id,
            },
            status=CommandStatus.PENDING,
            retry_count=0,
            max_retries=3,
            issued_at=datetime.now(timezone.utc)
        )
        created = await self.command_repo.add(command)
        await command_dispatcher.push_command(created.id, created.agent_id)
        return created