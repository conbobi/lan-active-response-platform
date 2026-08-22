from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.command import CommandCreate, CommandOut
from app.schemas.command_ack import CommandAckDTO
from app.services.command_service import CommandService

router = APIRouter(tags=["Commands"])


@router.post("/", response_model=CommandOut, status_code=status.HTTP_201_CREATED)
async def create_command(dto: CommandCreate, db: AsyncSession = Depends(get_db)):
    """Issue a new command to an agent."""
    service = CommandService(db)
    return await service.issue_command(dto)


@router.get("/", response_model=List[CommandOut])
async def list_commands(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List issued commands."""
    service = CommandService(db)
    return await service.list_commands(skip=skip, limit=limit)


@router.get("/{command_id}", response_model=CommandOut)
async def get_command(command_id: str, db: AsyncSession = Depends(get_db)):
    """Get command execution details."""
    service = CommandService(db)
    return await service.get_command(command_id)


@router.post("/{command_id}/ack", response_model=CommandOut)
async def acknowledge_command(command_id: str, ack: CommandAckDTO, db: AsyncSession = Depends(get_db)):
    """Acknowledge command result from agent."""
    service = CommandService(db)
    ack.command_id = command_id
    return await service.process_ack(ack)
