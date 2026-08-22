import pytest

pytestmark = pytest.mark.asyncio


async def test_path_request_and_release_real_db(async_client):
    # Setup agents and link in real DB
    for aid in ["node-A", "node-B"]:
        await async_client.post("/api/v1/agents/heartbeat", json={
            "agent_id": aid,
            "cpu": 5.0,
            "ram": 5.0,
            "disk": 5.0,
            "ip_address": "192.168.1.1",
            "mac_address": "00:00:00:00:00:00"
        })

    link_payload = {
        "id": "link-AB",
        "source_agent_id": "node-A",
        "target_agent_id": "node-B",
        "capacity": 1000.0,
        "reserved_bandwidth": 0.0,
        "latency": 1.0,
        "load": 0.0,
        "packet_loss": 0.0,
        "is_active": True
    }
    await async_client.post("/api/v1/topology/links", json=link_payload)

    # 1. Path Request
    req_payload = {
        "source_agent_id": "node-A",
        "destination_agent_id": "node-B",
        "required_bandwidth": 200.0,
        "priority": 1,
        "exclude_link_ids": [],
        "max_hops": 5
    }
    resp_req = await async_client.post("/api/v1/path/request", json=req_payload)
    assert resp_req.status_code == 200
    res_data = resp_req.json()
    assert res_data["found"] is True
    assert res_data["path"] == ["node-A", "node-B"]
    session_id = res_data["session_id"]

    # 2. Path Release
    rel_payload = {
        "session_id": session_id,
        "link_ids": res_data["link_ids"],
        "allocated_bandwidth": 200.0
    }
    resp_rel = await async_client.post("/api/v1/path/release", json=rel_payload)
    assert resp_rel.status_code == 200
    assert resp_rel.json() == {"status": "ok", "released": True}
