import pytest

pytestmark = pytest.mark.asyncio


async def test_risk_evaluate_and_history_real_db(async_client):
    # Register agent first
    agent_id = "agent-risk-001"
    await async_client.post("/api/v1/agents/heartbeat", json={
        "agent_id": agent_id,
        "cpu": 10.0,
        "ram": 10.0,
        "disk": 10.0,
        "ip_address": "192.168.1.10",
        "mac_address": "00:11:22:33:44:55"
    })

    # Evaluate Risk
    payload = {
        "agent_id": agent_id,
        "cpu_usage": 95.0,
        "process_list": [{"name": "suspicious_tool.exe", "is_suspicious": True}],
        "network_connections": [{"dst_port": 4444, "dst_ip": "1.2.3.4"}],
        "file_changes_count": 20
    }
    response_eval = await async_client.post("/api/v1/risk/evaluate", json=payload)
    assert response_eval.status_code == 200
    eval_data = response_eval.json()
    assert eval_data["agent_id"] == agent_id
    assert eval_data["score"] > 50.0

    # Get History
    response_hist = await async_client.get(f"/api/v1/risk/{agent_id}/history")
    assert response_hist.status_code == 200
    hist_data = response_hist.json()
    assert len(hist_data) >= 1
    assert hist_data[0]["agent_id"] == agent_id
