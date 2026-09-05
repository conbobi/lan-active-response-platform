from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.process_chain_rule import (
    ProcessChainRuleCreate,
    ProcessChainRuleUpdate,
    ProcessChainRuleOut
)
from app.services.process_chain_rule_service import ProcessChainRuleService

router = APIRouter(tags=["Process Chain Rules"])


@router.get("/", response_model=List[ProcessChainRuleOut])
async def list_process_chain_rules(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List all process chain rules with attached parent and child groups."""
    service = ProcessChainRuleService(db)
    return await service.list_rules(skip=skip, limit=limit)


@router.post("/", response_model=ProcessChainRuleOut, status_code=status.HTTP_201_CREATED)
async def create_process_chain_rule(dto: ProcessChainRuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new process chain detection rule linking parent and child groups."""
    service = ProcessChainRuleService(db)
    return await service.create_rule(dto)


@router.get("/{id}", response_model=ProcessChainRuleOut)
async def get_process_chain_rule(id: str, db: AsyncSession = Depends(get_db)):
    """Get details of a process chain rule by ID."""
    service = ProcessChainRuleService(db)
    return await service.get_rule(id)


@router.put("/{id}", response_model=ProcessChainRuleOut)
async def update_process_chain_rule(id: str, dto: ProcessChainRuleUpdate, db: AsyncSession = Depends(get_db)):
    """Update process chain rule attributes (name, parent/child groups, action, active state)."""
    service = ProcessChainRuleService(db)
    return await service.update_rule(id, dto)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_process_chain_rule(id: str, db: AsyncSession = Depends(get_db)):
    """Delete a process chain rule."""
    service = ProcessChainRuleService(db)
    await service.delete_rule(id)
