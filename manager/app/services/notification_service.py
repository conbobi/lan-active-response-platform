import logging
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import NotificationConfig, NotificationLog
from app.repositories.notification_repository import NotificationRepository
from app.services.command_dispatcher import command_dispatcher
from app.models.command import Command
from app.schemas.enums import CommandStatus
from app.repositories.command_repository import CommandRepository
from app.repositories.agent_repository import AgentRepository

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Facade service for dispatching security notifications via Discord webhook.
    """

    def __init__(self, session: Optional[AsyncSession] = None):
        self.session = session
        self.repo = NotificationRepository(session) if session else None

    async def get_active_config(self) -> Optional[NotificationConfig]:
        """Fetch active Discord notification configuration from DB or return None."""
        if self.repo:
            configs = await self.repo.get_enabled_configs(channel="discord")
            if configs:
                return configs[0]
        return None

    async def send_alert(
        self,
        message: str,
        title: str = "LARP Security Alert",
        webhook_url: Optional[str] = None,
        color: int = 0xFF0000,  # Màu đỏ
        buttons: Optional[List[Any]] = None
    ) -> bool:
        """
        Send a Discord alert message via webhook.
        """
        config = await self.get_active_config()

        target_webhook = webhook_url or (config.webhook_url if config else os.getenv("DISCORD_WEBHOOK_URL", ""))
        config_id = config.id if config else None

        if not target_webhook:
            logger.warning("Discord notification skipped: Webhook URL not configured.")
            return False

        payload = {
            "embeds": [
                {
                    "title": title,
                    "description": message,
                    "color": color,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            ]
        }

        status_str = "failed"
        sent_at = None

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(target_webhook, json=payload)
                if response.status_code in (200, 204):
                    status_str = "sent"
                    sent_at = datetime.now(timezone.utc)
                    logger.info("Discord notification sent successfully.")
                else:
                    logger.error(f"Discord notification failed ({response.status_code}): {response.text}")
        except Exception as e:
            logger.exception(f"Error dispatching Discord alert: {e}")

        if self.repo:
            log_entry = NotificationLog(
                config_id=config_id,
                channel="discord",
                recipient=target_webhook,
                message=message,
                status=status_str,
                sent_at=sent_at
            )
            await self.repo.add_log(log_entry)

        return status_str == "sent"

    # Discord không có cơ chế callback như Telegram, có thể loại bỏ hoặc giữ nhưng không dùng.
    async def handle_callback(
        self,
        callback_data: Dict[str, Any],
        session: AsyncSession
    ) -> Dict[str, Any]:
        """Discord webhooks không hỗ trợ callback như Telegram, method này tạm thời không xử lý."""
        logger.info("Discord webhook callback không được hỗ trợ.")
        return {"status": "ignored", "reason": "Discord webhook does not support callbacks"}