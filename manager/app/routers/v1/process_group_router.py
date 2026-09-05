from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.process_group import (
    ProcessGroupCreate,
    ProcessGroupUpdate,
    ProcessGroupOut
)
from app.services.process_group_service import ProcessGroupService

router = APIRouter(tags=["Process Groups"])


@router.get("/", response_model=List[ProcessGroupOut])
async def list_process_groups(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List all configured process groups."""
    service = ProcessGroupService(db)
    return await service.list_groups(skip=skip, limit=limit)


@router.post("/", response_model=ProcessGroupOut, status_code=status.HTTP_201_CREATED)
async def create_process_group(dto: ProcessGroupCreate, db: AsyncSession = Depends(get_db)):
    """Create a new process group with patterns."""
    service = ProcessGroupService(db)
    return await service.create_group(dto)


@router.get("/{id}", response_model=ProcessGroupOut)
async def get_process_group(id: str, db: AsyncSession = Depends(get_db)):
    """Get details of a process group by ID."""
    service = ProcessGroupService(db)
    return await service.get_group(id)


@router.put("/{id}", response_model=ProcessGroupOut)
async def update_process_group(id: str, dto: ProcessGroupUpdate, db: AsyncSession = Depends(get_db)):
    """Update process group name, patterns, or description."""
    service = ProcessGroupService(db)
    return await service.update_group(id, dto)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_process_group(id: str, db: AsyncSession = Depends(get_db)):
    """Delete a process group. Fails with 409 Conflict if referenced by active rules."""
    service = ProcessGroupService(db)
    await service.delete_group(id)
