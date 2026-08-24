import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.websocket.agent_ws import agent_websocket_endpoint

pytestmark = pytest.mark.asyncio


async def test_telemetry_risk_ws_handling():
    mock_ws = MagicMock()
    mock_ws.query_params = {"agent_id": "test-agent-001"}
    
    # Mock connection manager
    mock_connect = AsyncMock()
    
    # Return TELEMETRY_RISK payload then disconnect
    telemetry_msg = {
        "type": "TELEMETRY_RISK",
        "payload": {
            "agent_id": "test-agent-001",
            "cpu_usage": 15.0,
            "process_list": [{"pid": 100, "name": "cmd.exe", "path": "C:\\cmd.exe", "is_suspicious": True}],
            "network_connections": [{"src_ip": "192.168.1.10", "dst_ip": "1.1.1.1", "dst_port": 4444}],
            "file_changes_count": 0
        }
    }
    
    from fastapi import WebSocketDisconnect
    mock_ws.receive_text = AsyncMock(side_effect=[
        import_json := __import__("json").dumps(telemetry_msg),
        WebSocketDisconnect()
    ])
    mock_ws.send_json = AsyncMock()

    mock_record = MagicMock()
    mock_record.score = 65.0
    mock_risk_service = MagicMock()
    mock_risk_service.process_risk = AsyncMock(return_value=mock_record)

    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session_local = MagicMock(return_value=mock_session)
    mock_session_local.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_local.__aexit__ = AsyncMock(return_value=None)

    with patch("app.websocket.agent_ws.connection_manager.connect", mock_connect), \
         patch("app.websocket.agent_ws.connection_manager.disconnect", MagicMock()), \
         patch("app.websocket.agent_ws.AsyncSessionLocal", mock_session_local), \
         patch("app.websocket.agent_ws.RiskAssessmentService", return_value=mock_risk_service), \
         patch("app.websocket.agent_ws.command_dispatcher.pull_pending_commands", AsyncMock(return_value=[])):

        await agent_websocket_endpoint(mock_ws)

        mock_risk_service.process_risk.assert_awaited_once()
        args, kwargs = mock_risk_service.process_risk.call_args
        assert kwargs["agent_id"] == "test-agent-001"
        assert kwargs["data"]["cpu_usage"] == 15.0

        mock_ws.send_json.assert_called_once_with({
            "status": "ack",
            "message": "Risk telemetry processed",
            "score": 65.0
        })
