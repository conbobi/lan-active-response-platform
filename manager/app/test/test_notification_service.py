import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.notification_service import NotificationService

pytestmark = pytest.mark.asyncio


async def test_send_alert_discord(mock_db, mock_notification_repo):
    with patch("app.services.notification_service.NotificationRepository", return_value=mock_notification_repo):
        service = NotificationService(mock_db)

    webhook_url = "https://discord.com/api/webhooks/1540670659749875733/yeMQIpiSsydQW3jzAf8wQplCFheUWm8UVmN3YWgoiOgqALgkpSnLx2mJiR6ai934UlHU"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = MagicMock(status_code=204, text="")
        result = await service.send_alert("Test message", webhook_url=webhook_url)

    assert result is True
    mock_post.assert_awaited_once()

    args, kwargs = mock_post.call_args
    assert args[0] == webhook_url
    payload = kwargs.get("json", {})
    assert "embeds" in payload
    assert payload["embeds"][0]["description"] == "Test message"


async def test_handle_callback(mock_db):
    service = NotificationService(mock_db)
    res = await service.handle_callback({}, mock_db)
    assert res.get("status") == "ignored"