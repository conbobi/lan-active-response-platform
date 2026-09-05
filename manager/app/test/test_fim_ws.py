import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocketDisconnect
from app.websocket.agent_ws import agent_websocket_endpoint
from app.schemas.enums import IncidentSeverity

pytestmark = pytest.mark.asyncio


async def test_fim_alert_critical_file_creates_incident():
    mock_ws = MagicMock()
    mock_ws.query_params = {"agent_id": "client1"}

    fim_msg = {
        "type": "FIM_ALERT",
        "payload": {
            "agent_id": "client1",
            "file_path": "/etc/passwd",
            "old_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "new_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            "action": "MODIFIED",
            "timestamp": "2026-09-04T12:00:00Z"
        },
        "wait_ack": True
    }

    import json
    mock_ws.receive_text = AsyncMock(side_effect=[
        json.dumps(fim_msg),
        WebSocketDisconnect()
    ])
    mock_ws.send_json = AsyncMock()

    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    mock_session_local = MagicMock(return_value=mock_session)
    mock_session_local.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_local.__aexit__ = AsyncMock(return_value=None)

    mock_inc_service = MagicMock()
    mock_inc_service.create_incident = AsyncMock()

    mock_event_repo = MagicMock()
    mock_event_repo.add = AsyncMock()

    with patch("app.websocket.agent_ws.connection_manager.connect", AsyncMock()), \
         patch("app.websocket.agent_ws.connection_manager.disconnect", MagicMock()), \
         patch("app.websocket.agent_ws.AsyncSessionLocal", mock_session_local), \
         patch("app.websocket.agent_ws.EventRepository", return_value=mock_event_repo), \
         patch("app.websocket.agent_ws.IncidentService", return_value=mock_inc_service):

        await agent_websocket_endpoint(mock_ws)

        # 1. Verify Event was added via EventRepository
        mock_event_repo.add.assert_awaited_once()
        event_obj = mock_event_repo.add.call_args[0][0]
        assert event_obj.event_type == "FIM_ALERT"
        assert event_obj.severity == IncidentSeverity.HIGH
        assert event_obj.agent_id == "client1"

        # 2. Verify CRITICAL incident was created for /etc/passwd
        mock_inc_service.create_incident.assert_awaited_once()
        inc_dto = mock_inc_service.create_incident.call_args[0][0]
        assert inc_dto.severity == IncidentSeverity.CRITICAL
        assert "/etc/passwd" in inc_dto.title
        assert inc_dto.agent_id == "client1"

        # 3. Verify response ACK
        mock_ws.send_json.assert_called_once_with({
            "status": "ack",
            "message": "FIM alert processed"
        })
