from typing import List, Dict, Any
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.models.notification import NotificationConfig
from app.schemas.notification import (
    NotificationConfigCreate,
    NotificationConfigOut,
    NotificationLogOut
)
from app.repositories.notification_repository import NotificationRepository
from app.services.notification_service import NotificationService

router = APIRouter(tags=["Notifications"])


@router.get("/configs", response_model=List[NotificationConfigOut])
async def list_notification_configs(db: AsyncSession = Depends(get_db)):
    """Retrieve list of configured notification endpoints."""
    repo = NotificationRepository(db)
    return await repo.list()


@router.post("/configs", response_model=NotificationConfigOut, status_code=status.HTTP_201_CREATED)
async def create_notification_config(dto: NotificationConfigCreate, db: AsyncSession = Depends(get_db)):
    """Create a new notification channel configuration."""
    repo = NotificationRepository(db)
    config = NotificationConfig(
        channel=dto.channel,
        bot_token=dto.bot_token,
        chat_id=dto.chat_id,
        enabled=dto.enabled
    )
    created = await repo.add(config)
    await db.flush()
    return created


@router.post("/webhook/telegram")
async def telegram_webhook(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """Webhook listener for Telegram bot callback queries."""
    service = NotificationService(db)
    callback_query = payload.get("callback_query")
    if callback_query:
        result = await service.handle_callback(callback_query, db)
        return result
    return {"status": "ok", "message": "No callback query in payload"}


@router.get("/logs", response_model=List[NotificationLogOut])
async def list_notification_logs(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Retrieve notification audit log history."""
    repo = NotificationRepository(db)
    return await repo.list_logs(skip=skip, limit=limit)
