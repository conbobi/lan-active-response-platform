from unittest.mock import AsyncMock, patch, MagicMock
import pytest

pytestmark = pytest.mark.asyncio


async def test_notification_config_crud_and_send_real_db(async_client, db_session):
    # 1. Create config
    payload = {
        "channel": "discord",
        "webhook_url": "https://discord.com/api/webhooks/test-real-db",
        "enabled": True
    }
    res_create = await async_client.post("/api/v1/notifications/configs", json=payload)
    assert res_create.status_code == 201
    cfg_data = res_create.json()
    assert cfg_data["webhook_url"] == "https://discord.com/api/webhooks/test-real-db"

    # 2. Get configs
    res_list = await async_client.get("/api/v1/notifications/configs")
    assert res_list.status_code == 200
    configs = res_list.json()
    assert len(configs) >= 1
    assert any(c["webhook_url"] == "https://discord.com/api/webhooks/test-real-db" for c in configs)

    # 3. Send alert with external mock
    from app.services.notification_service import NotificationService
    service = NotificationService(db_session)
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = MagicMock(status_code=204, text="")
        sent = await service.send_alert("Test alert message for real DB test", webhook_url="https://discord.com/api/webhooks/test-real-db")
    assert sent is True
