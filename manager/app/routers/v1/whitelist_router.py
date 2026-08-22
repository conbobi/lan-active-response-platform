from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.core.exceptions import NotFoundError
from app.schemas.whitelist import WhitelistEntryCreate, WhitelistEntryOut
from app.services.whitelist_service import WhitelistService

router = APIRouter(tags=["Whitelist"])


@router.get("/", response_model=List[WhitelistEntryOut])
async def list_whitelist_entries(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Retrieve list of whitelisted processes, paths, or agents."""
    service = WhitelistService(db)
    return await service.list_entries(skip=skip, limit=limit)


@router.post("/", response_model=WhitelistEntryOut, status_code=status.HTTP_201_CREATED)
async def add_whitelist_entry(dto: WhitelistEntryCreate, db: AsyncSession = Depends(get_db)):
    """Add a new whitelist entry."""
    service = WhitelistService(db)
    return await service.add_entry(dto)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_whitelist_entry(entry_id: str, db: AsyncSession = Depends(get_db)):
    """Remove a whitelist entry by ID."""
    service = WhitelistService(db)
    deleted = await service.remove_entry(entry_id)
    if not deleted:
        raise NotFoundError(f"Whitelist entry with ID '{entry_id}' was not found.")
