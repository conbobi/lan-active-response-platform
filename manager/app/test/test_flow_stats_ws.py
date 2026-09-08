import sys
from pathlib import Path
from collections import namedtuple
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocketDisconnect

# Ensure agent directory is importable
agent_dir = Path(__file__).resolve().parents[3] / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

import agent
from app.websocket.agent_ws import agent_websocket_endpoint
from app.services.flow_service import FlowService
from app.models.flow import Flow

pytestmark = pytest.mark.asyncio

NetIOCounters = namedtuple("NetIOCounters", ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv"])


async def test_get_network_flow_stats_delta_calculation():
    """Verify get_network_flow_stats() correctly calculates delta bytes and packets between intervals."""
    # Reset global state
    agent._prev_net_io = None
    agent._prev_net_time = None

    io_t1 = NetIOCounters(bytes_sent=10000, bytes_recv=20000, packets_sent=100, packets_recv=200)
    io_t2 = NetIOCounters(bytes_sent=14500, bytes_recv=26000, packets_sent=130, packets_recv=250)

    with patch("psutil.net_io_counters", return_value=io_t1), \
         patch("agent.get_ip_address", return_value="192.168.1.50"):
        # First call: records baseline, returns 0 deltas
        res1 = agent.get_network_flow_stats()
        assert res1["bytes_sent_delta"] == 0
        assert res1["bytes_recv_delta"] == 0
        assert res1["packets_sent_delta"] == 0
        assert res1["packets_recv_delta"] == 0

    with patch("psutil.net_io_counters", return_value=io_t2), \
         patch("agent.get_ip_address", return_value="192.168.1.50"):
        # Second call: calculates delta from previous sample
        res2 = agent.get_network_flow_stats()
        assert res2["bytes_sent_delta"] == 4500
        assert res2["bytes_recv_delta"] == 6000
        assert res2["packets_sent_delta"] == 30
        assert res2["packets_recv_delta"] == 50
        assert res2["ip_address"] == "192.168.1.50"


async def test_flow_stats_ws_handling():
    """Verify backend agent_ws receives FLOW_STATS and records real flow entries into repository."""
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


async def test_flow_service_list_flows_prefers_real_data():
    """Verify FlowService.list_flows() returns real DB flows when available, and only falls back to synthetic when empty."""
    mock_session = AsyncMock()
    service = FlowService(mock_session)

    real_flow = Flow(
        id="flow-real-1",
        src_ip="192.168.10.12",
        dst_ip="192.168.10.1",
        src_port=443,
        dst_port=52341,
        protocol="TCP",
        bytes_sent=4500,
        packets_sent=30,
        agent_id="client1"
    )

    # 1. Case: Real flows exist in repository
    service.repository.find_recent_flows = AsyncMock(return_value=[real_flow])
    service.repository.find_flows_paginated = AsyncMock(return_value=[real_flow])

    flows = await service.list_flows(agent_id="client1", minutes=5)
    assert len(flows) == 1
    assert flows[0].id == "flow-real-1"
    assert flows[0].bytes_sent == 4500

    # 2. Case: No flows exist in DB at all -> Fallback to synthetic
    service.repository.find_recent_flows = AsyncMock(return_value=[])
    service.repository.find_flows_paginated = AsyncMock(return_value=[])

    fallback_flows = await service.list_flows(agent_id="client1", minutes=5)
    assert len(fallback_flows) > 0
    # Synthetic flows have generated random IPs and ports
    assert any(f.agent_id == "client1" for f in fallback_flows)
