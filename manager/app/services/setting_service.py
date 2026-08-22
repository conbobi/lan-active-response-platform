from typing import Any, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.system_setting import SystemSetting
from app.repositories.system_setting_repository import SystemSettingRepository


class SettingService:
    """Service managing system configuration parameters and risk threshold settings."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = SystemSettingRepository(session)

    async def get_setting(self, key: str, default: Any = None) -> Any:
        setting = await self.repo.get_by_key(key)
        if setting:
            return setting.value.get("data", setting.value)
        return default

    async def set_setting(self, key: str, value: Any) -> SystemSetting:
        return await self.repo.set_key(key, value)

    async def list_settings(self) -> List[SystemSetting]:
        return await self.repo.list()

    async def get_risk_thresholds(self) -> Dict[str, float]:
        """Fetch configurable risk thresholds or fallback to default values."""
        thresholds = await self.get_setting("risk_thresholds")
        if isinstance(thresholds, dict):
            return {
                "log": float(thresholds.get("log", 30.0)),
                "alert": float(thresholds.get("alert", 30.0)),
                "alert_with_buttons": float(thresholds.get("alert_with_buttons", 60.0)),
                "auto_isolate": float(thresholds.get("auto_isolate", 80.0)),
            }
        return {"log": 30.0, "alert": 30.0, "alert_with_buttons": 60.0, "auto_isolate": 80.0}

    async def get_heartbeat_interval(self) -> int:
        val = await self.get_setting("heartbeat_interval", default=30)
        return int(val)

    async def get_sweep_interval(self) -> int:
        val = await self.get_setting("sweep_interval", default=60)
        return int(val)
