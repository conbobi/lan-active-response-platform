import asyncio
import pytest
from sqlalchemy import select
from app.models.agent import Agent

pytestmark = pytest.mark.asyncio


async def test_concurrent_heartbeats_real_db(async_client, db_session):
    payloads = [
        {
            "agent_id": f"conc-agent-{i:03d}",
            "cpu": 10.0 + i,
            "ram": 30.0,
            "disk": 25.0,
            "ip_address": f"192.168.2.{10+i}",
            "mac_address": f"00:11:22:33:44:{i:02x}"
        }
        for i in range(10)
    ]

    tasks = [async_client.post("/api/v1/agents/heartbeat", json=p) for p in payloads]
    responses = await asyncio.gather(*tasks)

    for resp in responses:
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "message": "Heartbeat received"}

    # Verify all 10 agents were saved in real DB
    res = await db_session.execute(select(Agent).where(Agent.id.like("conc-agent-%")))
    saved_agents = res.scalars().all()
    assert len(saved_agents) == 10


async def test_concurrent_isolate_commands_real_db(async_client, db_session):
    # Pre-register 10 agents
    for i in range(10):
        await async_client.post("/api/v1/agents/heartbeat", json={
            "agent_id": f"iso-agent-{i:03d}",
            "cpu": 20.0,
            "ram": 20.0,
            "disk": 20.0,
            "ip_address": f"192.168.3.{10+i}",
            "mac_address": f"00:11:22:33:55:{i:02x}"
        })

    tasks = [async_client.post(f"/api/v1/agents/iso-agent-{i:03d}/isolate") for i in range(10)]
    responses = await asyncio.gather(*tasks)

    for resp in responses:
        assert resp.status_code == 200
        assert resp.json()["is_isolated"] is True

    res = await db_session.execute(select(Agent).where(Agent.id.like("iso-agent-%"), Agent.is_isolated == True))
    isolated_agents = res.scalars().all()
    assert len(isolated_agents) == 10
