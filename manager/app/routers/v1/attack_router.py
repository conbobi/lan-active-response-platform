from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.deps import get_db
from app.schemas.attack import AttackRequestDTO
from app.services.attack_service import AttackService
from app.schemas.command import CommandOut

router = APIRouter(tags=["Attack"])

@router.post("/syn-flood", response_model=CommandOut, status_code=status.HTTP_202_ACCEPTED)
async def launch_syn_flood(dto: AttackRequestDTO, db: AsyncSession = Depends(get_db)):
    service = AttackService(db)
    command = await service.launch_syn_flood(dto)
    return command