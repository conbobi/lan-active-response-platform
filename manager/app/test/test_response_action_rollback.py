import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.schemas.enums import AgentStatus
from app.models.agent import Agent
from app.models.response_action import ResponseAction
from app.services.snapshot_service import SnapshotService
from app.services.response_action_service import ResponseActionService
from app.services.rollback_service import RollbackService
from app.core.exceptions import ConflictError, FlappingCooldownError, NotFoundError


@pytest.mark.asyncio
async def test_snapshot_capture_isolate(mock_db):
    """Test snapshot capture for network isolation action."""
    mock_agent = Agent(id="test_agent", hostname="host1", ip_address="192.168.1.100", status=AgentStatus.ACTIVE)
    mock_agent.is_isolated = False

    service = SnapshotService(mock_db)
    service.agent_repo.get = AsyncMock(return_value=mock_agent)

    snapshot = await service.capture_snapshot("test_agent", "isolate", {"reason": "Malware activity"})
    assert snapshot["agent_id"] == "test_agent"
    assert snapshot["action_type"] == "isolate"
    assert snapshot["network"]["pre_action_isolated"] is False

    compensation = service.get_compensation_action("isolate", {}, snapshot)
    assert compensation["command_action"] == "unisolate"
    assert compensation["restore_is_isolated"] is False
    assert compensation["restore_agent_status"] == "active"


@pytest.mark.asyncio
async def test_response_action_lifecycle(mock_db):
    """Test creating and applying response action with auto-rollback time."""
    mock_agent = Agent(id="agent_1", hostname="host1", ip_address="10.0.0.1", status=AgentStatus.ACTIVE)
    mock_agent.is_isolated = False
    mock_agent.isolate = MagicMock()

    service = ResponseActionService(mock_db)
    service.agent_repo.get = AsyncMock(return_value=mock_agent)
    service.action_repo.get_active_cooldown = AsyncMock(return_value=None)
    service.action_repo.add = AsyncMock()
    service.cmd_repo.add = AsyncMock()
    service.audit_service.record_event = AsyncMock()
    service.setting_service.get_auto_rollback_settings = AsyncMock(
        return_value={"timeout_seconds": 300, "enabled": True, "cooldown_seconds": 600}
    )

    with patch("app.services.response_action_service.command_dispatcher.push_command", AsyncMock()):
        action = await service.create_and_apply_action(
            agent_id="agent_1",
            action_type="isolate",
            action_params={"reason": "Test unit"},
            auto_rollback_seconds=120
        )

        assert action.status == "applied"
        assert action.agent_id == "agent_1"
        assert action.action_type == "isolate"
        assert action.auto_rollback_at is not None
        mock_agent.isolate.assert_called_once()
        service.audit_service.record_event.assert_awaited()


@pytest.mark.asyncio
async def test_rollback_action_success(mock_db):
    """Test successful rollback of an applied action with compensation command."""
    mock_agent = Agent(id="agent_1", hostname="host1", ip_address="10.0.0.1", status=AgentStatus.ISOLATED)
    mock_agent.is_isolated = True

    action = ResponseAction(
        id="act_123",
        agent_id="agent_1",
        action_type="isolate",
        action_params={},
        status="applied",
        snapshot={
            "agent_id": "agent_1",
            "action_type": "isolate",
            "network": {"pre_action_isolated": False}
        }
    )

    service = RollbackService(mock_db)
    service.action_repo.get_for_update = AsyncMock(return_value=action)
    service.agent_repo.get = AsyncMock(return_value=mock_agent)
    service.cmd_repo.add = AsyncMock()
    service.audit_service.record_event = AsyncMock()
    service.setting_service.get_auto_rollback_settings = AsyncMock(
        return_value={"timeout_seconds": 300, "enabled": True, "cooldown_seconds": 600}
    )

    with patch("app.services.rollback_service.command_dispatcher.push_command", AsyncMock()) as mock_push:
        reverted = await service.rollback_action("act_123", reason="False alarm", actor="analyst")

        assert reverted.status == "reverted"
        assert reverted.undone_by == "analyst"
        assert reverted.undo_reason == "False alarm"
        assert reverted.cooldown_until is not None
        assert mock_agent.is_isolated is False
        mock_push.assert_awaited_once()


@pytest.mark.asyncio
async def test_rollback_concurrency_conflict(mock_db):
    """Test that reverting an already reverted action raises ConflictError (409)."""
    action = ResponseAction(
        id="act_reverted",
        agent_id="agent_1",
        action_type="isolate",
        status="reverted",
        undone_at=datetime.now(timezone.utc)
    )

    service = RollbackService(mock_db)
    service.action_repo.get_for_update = AsyncMock(return_value=action)

    with pytest.raises(ConflictError) as exc_info:
        await service.rollback_action("act_reverted")

    assert "already been reverted" in str(exc_info.value)


@pytest.mark.asyncio
async def test_anti_flapping_cooldown_rejection(mock_db):
    """Test that applying action to an agent currently in cooldown raises FlappingCooldownError (429)."""
    mock_agent = Agent(id="agent_1", hostname="host1", ip_address="10.0.0.1", status=AgentStatus.ACTIVE)
    cooldown_action = ResponseAction(
        id="act_old",
        agent_id="agent_1",
        action_type="isolate",
        status="reverted",
        cooldown_until=datetime.now(timezone.utc) + timedelta(minutes=5)
    )

    service = ResponseActionService(mock_db)
    service.agent_repo.get = AsyncMock(return_value=mock_agent)
    service.action_repo.get_active_cooldown = AsyncMock(return_value=cooldown_action)

    with pytest.raises(FlappingCooldownError) as exc_info:
        await service.create_and_apply_action("agent_1", "isolate")

    assert "cooldown" in str(exc_info.value).lower()
