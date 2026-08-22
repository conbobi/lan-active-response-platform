import pytest

pytestmark = pytest.mark.asyncio


async def test_agent_heartbeat_api(async_client, db_session):
    payload = {
        "agent_id": "real-agent-001",
        "cpu": 15.5,
        "ram": 42.0,
        "disk": 30.0,
        "ip_address": "192.168.1.50",
        "mac_address": "00:11:22:33:44:55"
    }
    response = await async_client.post("/api/v1/agents/heartbeat", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "Heartbeat received"}

    # Verify agent was auto-registered in real DB
    res = await async_client.get("/api/v1/agents/real-agent-001")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "real-agent-001"
    assert data["cpu"] == 15.5


async def test_list_agents_api(async_client):
    # Register an agent first via heartbeat
    payload = {
        "agent_id": "real-agent-002",
        "cpu": 10.0,
        "ram": 20.0,
        "disk": 30.0,
        "ip_address": "192.168.1.51",
        "mac_address": "00:11:22:33:44:56"
    }
    await async_client.post("/api/v1/agents/heartbeat", json=payload)

    response = await async_client.get("/api/v1/agents/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    agent_ids = [a["id"] for a in data]
    assert "real-agent-002" in agent_ids


async def test_isolate_and_unisolate_agent_api(async_client):
    # Register agent
    payload = {
        "agent_id": "real-agent-003",
        "cpu": 50.0,
        "ram": 50.0,
        "disk": 50.0,
        "ip_address": "192.168.1.52",
        "mac_address": "00:11:22:33:44:57"
    }
    await async_client.post("/api/v1/agents/heartbeat", json=payload)

    # Isolate
    response_iso = await async_client.post("/api/v1/agents/real-agent-003/isolate")
    assert response_iso.status_code == 200
    assert response_iso.json()["is_isolated"] is True

    # Unisolate
    response_uniso = await async_client.post("/api/v1/agents/real-agent-003/unisolate")
    assert response_uniso.status_code == 200
    assert response_uniso.json()["is_isolated"] is False
