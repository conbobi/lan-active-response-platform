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
from fastapi import Request, HTTPException
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
        webhook_url=dto.webhook_url,
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
@router.post("/webhook/telegram")
async def telegram_webhook(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """Webhook listener for Telegram bot callback queries."""
    service = NotificationService(db)
    callback_query = payload.get("callback_query")
    if callback_query:
        result = await service.handle_callback_telegram(callback_query, db)
        return result
    return {"status": "ok", "message": "No callback query in payload"}


@router.post("/webhook/discord")
async def discord_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Webhook listener cho Discord Interactions (Nút bấm)."""
    # 1. Lấy signature từ Headers (Bắt buộc của Discord)
    signature = request.headers.get("X-Signature-Ed25519")
    timestamp = request.headers.get("X-Signature-Timestamp")
    
    if not signature or not timestamp:
        raise HTTPException(status_code=401, detail="Missing Discord signatures")

    # Đọc body thô để verify chữ ký
    raw_body = await request.body()
    
    service = NotificationService(db)
    
    # 2. Verify chữ ký (Logic này bạn sẽ viết trong NotificationService)
    is_valid = service.verify_discord_signature(raw_body, signature, timestamp)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid request signature")

    payload = await request.json()
    
    # 3. Phản hồi PING của Discord (Bắt buộc)
    if payload.get("type") == 1: # 1 là PING
        return {"type": 1} # Trả về PONG

    # 4. Xử lý khi Admin bấm nút (type == 3 là MESSAGE_COMPONENT)
    if payload.get("type") == 3:
        result = await service.handle_callback_discord(payload, db)
        return result

    return {"status": "ok"}