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
    Facade service for dispatching security notifications and handling Telegram bot callbacks.
    """

    def __init__(self, session: Optional[AsyncSession] = None):
        self.session = session
        self.repo = NotificationRepository(session) if session else None

    async def get_active_config(self) -> Optional[NotificationConfig]:
        """Fetch active notification configuration from DB or return None."""
        if self.repo:
            configs = await self.repo.get_enabled_configs(channel="telegram")
            if configs:
                return configs[0]
        return None

    async def send_alert(
        self,
        message: str,
        chat_id: Optional[str] = None,
        bot_token: Optional[str] = None,
        buttons: Optional[List[List[Dict[str, str]]]] = None
    ) -> bool:
        """
        Send a Telegram alert message with optional inline keyboard buttons.
        """
        config = await self.get_active_config()

        token = bot_token or (config.bot_token if config else os.getenv("TELEGRAM_BOT_TOKEN", ""))
        target_chat = chat_id or (config.chat_id if config else os.getenv("TELEGRAM_CHAT_ID", ""))
        config_id = config.id if config else None

        if not token or not target_chat:
            logger.warning("Telegram notification skipped: Bot token or Chat ID not configured.")
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload: Dict[str, Any] = {
            "chat_id": target_chat,
            "text": message,
            "parse_mode": "HTML"
        }

        if buttons:
            payload["reply_markup"] = {
                "inline_keyboard": buttons
            }

        status_str = "failed"
        sent_at = None

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code == 200:
                    status_str = "sent"
                    sent_at = datetime.now(timezone.utc)
                    logger.info(f"Telegram notification sent successfully to chat '{target_chat}'.")
                else:
                    logger.error(f"Telegram notification failed ({response.status_code}): {response.text}")
        except Exception as e:
            logger.exception(f"Error dispatching Telegram alert: {e}")

        if self.repo:
            log_entry = NotificationLog(
                config_id=config_id,
                channel="telegram",
                recipient=target_chat,
                message=message,
                status=status_str,
                sent_at=sent_at
            )
            await self.repo.add_log(log_entry)

        return status_str == "sent"

    async def handle_callback(
        self,
        callback_data: Dict[str, Any],
        session: AsyncSession
    ) -> Dict[str, Any]:
        """
        Process callback payloads received from Telegram webhook / inline button triggers.
        Example callback string: "isolate:<agent_id>" or "unisolate:<agent_id>"
        """
        data_str = callback_data.get("data", "")
        parts = data_str.split(":", 1)
        action = parts[0]
        agent_id = parts[1] if len(parts) > 1 else ""

        if not agent_id:
            return {"status": "ignored", "reason": "No agent_id provided in callback"}

        agent_repo = AgentRepository(session)
        agent = await agent_repo.get(agent_id)
        if not agent:
            return {"status": "error", "message": f"Agent '{agent_id}' not found"}

        if action == "isolate":
            agent.isolate()
            cmd_repo = CommandRepository(session)
            cmd = Command(
                agent_id=agent_id,
                action="isolate",
                payload={"reason": "Telegram manual callback trigger"},
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)
            await session.flush()
            logger.info(f"Agent '{agent_id}' isolated via Telegram callback.")
            return {"status": "success", "action": "isolated", "agent_id": agent_id}

        elif action == "unisolate":
            agent.unisolate()
            cmd_repo = CommandRepository(session)
            cmd = Command(
                agent_id=agent_id,
                action="unisolate",
                payload={"reason": "Telegram manual callback trigger"},
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)
            await session.flush()
            logger.info(f"Agent '{agent_id}' unisolated via Telegram callback.")
            return {"status": "success", "action": "unisolated", "agent_id": agent_id}

        return {"status": "ignored", "action": action}
