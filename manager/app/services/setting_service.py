from typing import Any, Dict, List, Optional
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
                "incident_creation_threshold": float(thresholds.get("incident_creation_threshold", 50.0)),
                "auto_kill_threshold": float(thresholds.get("auto_kill_threshold", 85.0)),
                "auto_isolate": float(thresholds.get("auto_isolate", 85.0)),
                "alert_with_buttons": float(thresholds.get("alert_with_buttons", 70.0)),
                "alert": float(thresholds.get("alert", 50.0)),
                "log": float(thresholds.get("log", 20.0)),
            }
        return {
            "incident_creation_threshold": 50.0,
            "auto_kill_threshold": 85.0,
            "auto_isolate": 85.0,
            "alert_with_buttons": 70.0,
            "alert": 50.0,
            "log": 20.0,
        }

    async def update_risk_thresholds(self, thresholds: Dict[str, Any]) -> Dict[str, float]:
        val = {
            "incident_creation_threshold": float(thresholds.get("incident_creation_threshold", 50.0)),
            "auto_kill_threshold": float(thresholds.get("auto_kill_threshold", 85.0)),
            "auto_isolate": float(thresholds.get("auto_isolate", 85.0)),
            "alert_with_buttons": float(thresholds.get("alert_with_buttons", 70.0)),
            "alert": float(thresholds.get("alert", 50.0)),
            "log": float(thresholds.get("log", 20.0)),
        }
        await self.set_setting("risk_thresholds", val)
        await self.session.commit()
        return val

    async def get_file_changes_thresholds(self) -> Dict[str, int]:
        thresholds = await self.get_setting("file_changes_thresholds")
        if isinstance(thresholds, dict):
            return {
                "file_changes_critical": int(thresholds.get("file_changes_critical", 100)),
                "file_changes_elevated": int(thresholds.get("file_changes_elevated", 30)),
            }
        return {"file_changes_critical": 100, "file_changes_elevated": 30}

    async def update_file_changes_thresholds(self, thresholds: Dict[str, Any]) -> Dict[str, int]:
        val = {
            "file_changes_critical": int(thresholds.get("file_changes_critical", 100)),
            "file_changes_elevated": int(thresholds.get("file_changes_elevated", 30)),
        }
        await self.set_setting("file_changes_thresholds", val)
        await self.session.commit()
        return val

    async def get_heartbeat_interval(self) -> int:
        val = await self.get_setting("heartbeat_interval", default=30)
        return int(val)

    async def get_sweep_interval(self) -> int:
        val = await self.get_setting("sweep_interval", default=60)
        return int(val)

    async def get_auto_rollback_settings(self) -> Dict[str, Any]:
        """Lấy cấu hình auto-rollback và anti-flapping cooldown."""
        timeout_val = await self.get_setting("auto_rollback_timeout_seconds", default=300)
        if isinstance(timeout_val, dict):
            timeout_val = timeout_val.get("value", 300)
        enabled_val = await self.get_setting("auto_rollback_enabled", default=True)
        if isinstance(enabled_val, dict):
            enabled_val = enabled_val.get("value", True)
        cooldown_val = await self.get_setting("rollback_cooldown_seconds", default=600)
        if isinstance(cooldown_val, dict):
            cooldown_val = cooldown_val.get("value", 600)

        return {
            "timeout_seconds": int(timeout_val),
            "enabled": bool(enabled_val),
            "cooldown_seconds": int(cooldown_val)
        }

    async def update_auto_rollback_settings(
        self,
        timeout_seconds: Optional[int] = None,
        enabled: Optional[bool] = None,
        cooldown_seconds: Optional[int] = None
    ) -> Dict[str, Any]:
        """Cập nhật cấu hình auto-rollback."""
        current = await self.get_auto_rollback_settings()
        if timeout_seconds is not None:
            current["timeout_seconds"] = int(timeout_seconds)
            await self.set_setting(
                "auto_rollback_timeout_seconds",
                {"value": int(timeout_seconds), "description": "Thời gian timeout tự động rollback action (giây)"}
            )
        if enabled is not None:
            current["enabled"] = bool(enabled)
            await self.set_setting(
                "auto_rollback_enabled",
                {"value": bool(enabled), "description": "Bật/tắt tính năng auto-rollback khi hết timeout"}
            )
        if cooldown_seconds is not None:
            current["cooldown_seconds"] = int(cooldown_seconds)
            await self.set_setting(
                "rollback_cooldown_seconds",
                {"value": int(cooldown_seconds), "description": "Thời gian cooldown chống flapping sau khi rollback (giây)"}
            )
        await self.session.commit()
        return current

