import pytest

pytestmark = pytest.mark.asyncio


async def test_create_and_get_topology_links_api(async_client):
    # Register 2 agents
    for aid in ["agent-tp-1", "agent-tp-2"]:
        await async_client.post("/api/v1/agents/heartbeat", json={
            "agent_id": aid,
            "cpu": 10.0,
            "ram": 10.0,
            "disk": 10.0,
            "ip_address": "192.168.1.1",
            "mac_address": "00:00:00:00:00:00"
        })

    payload = {
        "id": "link-real-001",
        "source_agent_id": "agent-tp-1",
        "target_agent_id": "agent-tp-2",
        "capacity": 1000.0,
        "reserved_bandwidth": 0.0,
        "latency": 5.0,
        "load": 10.0,
        "packet_loss": 0.0,
        "is_active": True
    }
    response_create = await async_client.post("/api/v1/topology/links", json=payload)
    assert response_create.status_code == 201
    assert response_create.json()["id"] == "link-real-001"

    response_get = await async_client.get("/api/v1/topology/links")
    assert response_get.status_code == 200
    links = response_get.json()
    assert len(links) >= 1
    assert any(l["id"] == "link-real-001" for l in links)


async def test_update_topology_api(async_client):
    # Register 2 agents
    for aid in ["agent-tp-3", "agent-tp-4"]:
        await async_client.post("/api/v1/agents/heartbeat", json={
            "agent_id": aid,
            "cpu": 10.0,
            "ram": 10.0,
            "disk": 10.0,
            "ip_address": "192.168.1.1",
            "mac_address": "00:00:00:00:00:00"
        })

    # Create link first
    link_payload = {
        "id": "link-real-002",
        "source_agent_id": "agent-tp-3",
        "target_agent_id": "agent-tp-4",
        "capacity": 1000.0,
        "reserved_bandwidth": 0.0,
        "latency": 5.0,
        "load": 10.0,
        "packet_loss": 0.0,
        "is_active": True
    }
    await async_client.post("/api/v1/topology/links", json=link_payload)

    # Update topology metrics
    update_payload = {
        "link_id": "link-real-002",
        "source_agent_id": "agent-tp-3",
        "target_agent_id": "agent-tp-4",
        "new_latency": 25.0,
        "new_load": 80.0,
        "new_packet_loss": 2.0,
        "is_active": True,
        "reason": "Traffic spike"
    }
    response_update = await async_client.post("/api/v1/topology/update", json=update_payload)
    assert response_update.status_code == 200
    assert response_update.json() == {"status": "ok", "message": "Topology updated successfully"}

    # Verify link updated in DB
    res = await async_client.get("/api/v1/topology/links/link-real-002")
    assert res.status_code == 200
    link_data = res.json()
    assert link_data["latency"] == 25.0
    assert link_data["load"] == 80.0
