from unittest.mock import AsyncMock, patch
import pytest
from sqlalchemy import select
from app.models.command import Command
from app.models.incident import Incident
from app.schemas.enums import CommandStatus
from app.schemas.command_ack import CommandAckDTO
from app.services.command_dispatcher import command_dispatcher

pytestmark = pytest.mark.asyncio


async def test_auto_isolate_end_to_end_flow(async_client, db_session):
    agent_id = "agent-e2e-001"

    # Step 1: Agent registers via initial Heartbeat API
    resp_hb = await async_client.post("/api/v1/agents/heartbeat", json={
        "agent_id": agent_id,
        "cpu": 10.0,
        "ram": 20.0,
        "disk": 15.0,
        "ip_address": "192.168.1.88",
        "mac_address": "AA:BB:CC:DD:EE:11"
    })
    assert resp_hb.status_code == 200

    # Step 2: High-risk telemetry evaluation (CPU 98%, suspicious process, malicious connection)
    with patch("app.services.notification_service.NotificationService.send_alert", new_callable=AsyncMock):
        risk_payload = {
            "agent_id": agent_id,
            "cpu_usage": 98.0,
            "process_list": [{"name": "mimikatz.exe", "is_suspicious": True, "hash": "badhash123"}],
            "network_connections": [{"dst_port": 4444, "dst_ip": "1.2.3.4"}],
            "file_changes_count": 100
        }
        resp_eval = await async_client.post("/api/v1/risk/evaluate", json=risk_payload)
        assert resp_eval.status_code == 200
        risk_data = resp_eval.json()
        assert risk_data["score"] >= 80.0

    # Step 3: Verify auto-isolate Command was created in DB
    stmt_cmd = select(Command).where(Command.agent_id == agent_id, Command.action == "isolate")
    res_cmd = await db_session.execute(stmt_cmd)
    cmds = res_cmd.scalars().all()
    assert len(cmds) >= 1
    isolate_cmd = cmds[0]
    assert isolate_cmd.action == "isolate"

    # Step 4: Pull pending commands via CommandDispatcher
    pending = await command_dispatcher.pull_pending_commands(agent_id, db_session)
    assert len(pending) >= 1
    assert pending[0].id == isolate_cmd.id

    # Step 5: Agent executes command and sends ACK back to dispatcher
    ack_dto = CommandAckDTO(
        command_id=isolate_cmd.id,
        status=CommandStatus.SUCCESS,
        error_message=None
    )
    await command_dispatcher.verify_execution(ack_dto, db_session)
    await db_session.commit()

    # Step 6: Verify Command status updated to SUCCESS in DB & Incident created
    res_updated = await db_session.execute(select(Command).where(Command.id == isolate_cmd.id))
    updated_cmd = res_updated.scalar_one()
    assert updated_cmd.status == CommandStatus.SUCCESS

    res_inc = await db_session.execute(select(Incident).where(Incident.agent_id == agent_id))
    incidents = res_inc.scalars().all()
    assert len(incidents) >= 1
    assert incidents[0].agent_id == agent_id
