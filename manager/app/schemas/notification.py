from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.schemas.base import ORMBaseModel


class NotificationConfigCreate(BaseModel):
    channel: str = "telegram"
    bot_token: str
    chat_id: str
    enabled: bool = True


class NotificationConfigOut(ORMBaseModel):
    id: str
    channel: str
    bot_token: str
    chat_id: str
    enabled: bool


class NotificationLogOut(ORMBaseModel):
    id: str
    config_id: Optional[str] = None
    channel: str
    recipient: str
    message: str
    status: str
    sent_at: Optional[datetime] = None
    created_at: datetime
