import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocketDisconnect
from app.websocket.agent_ws import agent_websocket_endpoint

pytestmark = pytest.mark.asyncio


async def test_flow_stats_ws_handling():
    mock_ws = MagicMock()
    mock_ws.query_params = {"agent_id": "test-agent-flow"}

    flow_msg = {
        "type": "FLOW_STATS",
        "payload": {
            "agent_id": "test-agent-flow",
            "bytes_sent_delta": 4500,
            "packets_sent_delta": 30,
            "tcp_packets_delta": 20,
            "udp_packets_delta": 10,
            "ip_address": "192.168.10.12",
            "timestamp": "2026-09-04T12:00:00Z"
        },
        "wait_ack": True
    }

    import json
    mock_ws.receive_text = AsyncMock(side_effect=[
        json.dumps(flow_msg),
        WebSocketDisconnect()
    ])
    mock_ws.send_json = AsyncMock()

    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    mock_session_local = MagicMock(return_value=mock_session)
    mock_session_local.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_local.__aexit__ = AsyncMock(return_value=None)

    with patch("app.websocket.agent_ws.connection_manager.connect", AsyncMock()), \
         patch("app.websocket.agent_ws.connection_manager.disconnect", MagicMock()), \
         patch("app.websocket.agent_ws.AsyncSessionLocal", mock_session_local), \
         patch("app.websocket.agent_ws.FlowRepository") as mock_flow_repo_cls:

        mock_repo = MagicMock()
        mock_repo.add = AsyncMock()
        mock_flow_repo_cls.return_value = mock_repo

        await agent_websocket_endpoint(mock_ws)

        # Verify Flow records were added for TCP and UDP
        assert mock_repo.add.await_count == 2
        calls = mock_repo.add.await_args_list
        flow_tcp = calls[0].args[0]
        flow_udp = calls[1].args[0]

        assert flow_tcp.protocol == "TCP"
        assert flow_tcp.packets_sent == 20
        assert flow_udp.protocol == "UDP"
        assert flow_udp.packets_sent == 10

        # Verify ACK sent
        mock_ws.send_json.assert_called_once_with({
            "status": "ack",
            "message": "Flow stats processed"
        })
