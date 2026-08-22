from unittest.mock import patch
from tests.integration.conftest import TestSessionLocal
from app.models.agent import Agent
from app.models.command import Command
from app.schemas.enums import CommandStatus
from app.repositories.agent_repository import AgentRepository
from app.repositories.command_repository import CommandRepository
from app.services.command_dispatcher import command_dispatcher


def test_websocket_agent_full_flow_real_db(test_client):
    import asyncio

    # Ensure both target and source agents exist in DB for FK constraints
    async def pre_register_agents():
        async with TestSessionLocal() as session:
            repo = AgentRepository(session)
            for aid in ["agent-ws-001", "agent-ws-002"]:
                existing = await repo.get(aid)
                if not existing:
                    await repo.add(Agent(
                        id=aid, hostname=aid, ip_address="192.168.1.99", mac_address="AA:BB:CC:11:22:33"
                    ))
            await session.commit()

    asyncio.run(pre_register_agents())

    with patch("app.websocket.agent_ws.AsyncSessionLocal", TestSessionLocal):
        # 1. Heartbeat
        with test_client.websocket_connect("/ws/agent?agent_id=agent-ws-001") as websocket:
            payload_hb = {
                "type": "HEARTBEAT",
                "payload": {
                    "agent_id": "agent-ws-001",
                    "cpu": 12.0,
                    "ram": 35.0,
                    "disk": 20.0,
                    "ip_address": "192.168.1.99",
                    "mac_address": "AA:BB:CC:11:22:33"
                }
            }
            websocket.send_json(payload_hb)
            data_hb = websocket.receive_json()
            assert data_hb["status"] == "ack"
            assert data_hb["message"] == "Heartbeat processed"
            assert "pending_commands" in data_hb

            # 2. Topology Update
            payload_topo = {
                "type": "TOPOLOGY_UPDATE",
                "payload": {
                    "link_id": "link-ws-001",
                    "source_agent_id": "agent-ws-001",
                    "target_agent_id": "agent-ws-002",
                    "new_latency": 4.5,
                    "new_load": 15.0,
                    "new_packet_loss": 0.0,
                    "is_active": True
                }
            }
            websocket.send_json(payload_topo)
            data_topo = websocket.receive_json()
            assert data_topo["status"] == "ack"
            assert data_topo["message"] == "Topology update processed"

            # 3. Path Release
            payload_path = {
                "type": "PATH_RELEASE",
                "payload": {
                    "session_id": "sess-ws-100",
                    "link_ids": ["link-ws-001"],
                    "allocated_bandwidth": 50.0
                }
            }
            websocket.send_json(payload_path)
            data_path = websocket.receive_json()
            assert data_path["status"] == "ack"
            assert "released" in data_path

            # 4. Command Ack
            payload_ack = {
                "type": "COMMAND_ACK",
                "payload": {
                    "command_id": "cmd-ws-fake",
                    "status": "success",
                    "output": "Command processed"
                }
            }
            websocket.send_json(payload_ack)
            data_ack = websocket.receive_json()
            assert data_ack["status"] == "ack"
            assert data_ack["message"] == "Command ack recorded"


def test_websocket_pull_pending_commands_real_db(test_client):
    import asyncio

    async def setup_pending_command():
        async with TestSessionLocal() as session:
            agent_repo = AgentRepository(session)
            await agent_repo.add(Agent(
                id="agent-ws-002",
                hostname="agent-ws-002",
                ip_address="192.168.1.98",
                mac_address="AA:BB:CC:11:22:34"
            ))
            cmd_repo = CommandRepository(session)
            cmd = Command(
                id="cmd-pending-001",
                agent_id="agent-ws-002",
                action="isolate",
                payload={"reason": "Test pending command"},
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await session.commit()
            await command_dispatcher.push_command(cmd.id, "agent-ws-002")

    asyncio.run(setup_pending_command())

    with patch("app.websocket.agent_ws.AsyncSessionLocal", TestSessionLocal):
        with test_client.websocket_connect("/ws/agent?agent_id=agent-ws-002") as websocket:
            payload_hb = {
                "type": "HEARTBEAT",
                "payload": {
                    "agent_id": "agent-ws-002",
                    "cpu": 25.0,
                    "ram": 50.0,
                    "disk": 10.0,
                    "ip_address": "192.168.1.98",
                    "mac_address": "AA:BB:CC:11:22:34"
                }
            }
            websocket.send_json(payload_hb)
            data_hb = websocket.receive_json()
            assert data_hb["status"] == "ack"
            pending = data_hb["pending_commands"]
            assert len(pending) == 1
            assert pending[0]["command_id"] == "cmd-pending-001"
            assert pending[0]["action"] == "isolate"
