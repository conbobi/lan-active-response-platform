from datetime import datetime, timezone
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.schemas.enums import AgentStatus

pytestmark = pytest.mark.asyncio


def make_mock_agent(
    agent_id="agent-001",
    hostname="host-001",
    ip_address="192.168.1.10",
    mac_address="00:11:22:33:44:55",
    status=AgentStatus.ACTIVE,
    cpu=0.0,
    ram=0.0,
    disk=0.0,
    is_isolated=True
):
    agent = MagicMock()
    agent.id = agent_id
    agent.hostname = hostname
    agent.ip_address = ip_address
    agent.mac_address = mac_address
    agent.status = status
    agent.cpu = cpu
    agent.ram = ram
    agent.disk = disk
    agent.is_isolated = is_isolated
    agent.last_seen = datetime.now(timezone.utc)
    agent.created_at = datetime.now(timezone.utc)
    agent.updated_at = datetime.now(timezone.utc)
    return agent


async def test_concurrent_heartbeats_api(async_client):
    payloads = [
        {
            "agent_id": f"agent-{i:03d}",
            "cpu": 10.0 + i,
            "ram": 30.0,
            "disk": 25.0,
            "ip_address": f"192.168.1.{10+i}",
            "mac_address": "00:11:22:33:44:55"
        }
        for i in range(10)
    ]
    with patch("app.services.topology_service.topology_facade.process_heartbeat", new_callable=AsyncMock):
        tasks = [async_client.post("/api/v1/agents/heartbeat", json=p) for p in payloads]
        responses = await asyncio.gather(*tasks)

    for resp in responses:
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "message": "Heartbeat received"}


async def test_concurrent_isolate_commands_api(async_client):
    mock_agent = make_mock_agent(is_isolated=True)
    with patch("app.repositories.agent_repository.AgentRepository.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_agent
        tasks = [async_client.post(f"/api/v1/agents/agent-{i:03d}/isolate") for i in range(10)]
        responses = await asyncio.gather(*tasks)

    for resp in responses:
        assert resp.status_code == 200
        assert resp.json()["is_isolated"] is True
    assert mock_get.call_count == 10
