from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.rule import RuleCreate, RuleOut
from app.services.rule_service import RuleService

router = APIRouter(tags=["Rules"])


@router.post("/", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(dto: RuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a security detection rule."""
    service = RuleService(db)
    return await service.create_rule(dto)


@router.get("/", response_model=List[RuleOut])
async def list_rules(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List detection rules."""
    service = RuleService(db)
    return await service.list_rules(skip=skip, limit=limit)


@router.get("/{rule_id}", response_model=RuleOut)
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Get rule detail."""
    service = RuleService(db)
    return await service.get_rule(rule_id)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a detection rule."""
    service = RuleService(db)
    await service.delete_rule(rule_id)
