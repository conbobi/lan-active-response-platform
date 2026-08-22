from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.setting import SystemSettingOut, SystemSettingUpdate
from app.services.setting_service import SettingService

router = APIRouter(tags=["Settings"])


@router.get("/", response_model=List[SystemSettingOut])
async def list_system_settings(db: AsyncSession = Depends(get_db)):
    """Retrieve list of system settings and configuration parameters."""
    service = SettingService(db)
    return await service.list_settings()


@router.get("/{key}", response_model=SystemSettingOut)
async def get_system_setting(key: str, db: AsyncSession = Depends(get_db)):
    """Get system setting by key."""
    service = SettingService(db)
    setting = await service.repo.get_by_key(key)
    if not setting:
        from app.core.exceptions import NotFoundError
        raise NotFoundError(f"Setting with key '{key}' was not found.")
    return setting


@router.put("/{key}", response_model=SystemSettingOut)
async def update_system_setting(key: str, dto: SystemSettingUpdate, db: AsyncSession = Depends(get_db)):
    """Update or create system setting by key."""
    service = SettingService(db)
    setting = await service.set_setting(key, dto.value)
    return setting
