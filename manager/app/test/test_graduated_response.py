import pytest
from unittest.mock import AsyncMock, MagicMock
from app.models.agent import Agent
from app.schemas.enums import AgentStatus
from app.services.response.policy_engine_service import (
    POLICY_LEVELS,
    get_action_for_score,
    PolicyEngineService,
)


def test_graduated_response_threshold_mapping():
    """Verify 5 graduated response levels & get_action_for_score mapping."""
    assert len(POLICY_LEVELS) == 5

    # Level 1: 0 - 29 -> log_only (auto=True)
    lvl0 = get_action_for_score(0)
    assert lvl0["action"] == "log_only"
    assert lvl0["auto"] is True
    assert get_action_for_score(25)["action"] == "log_only"

    # Level 2: 30 - 49 -> alert (auto=True, no block)
    lvl1 = get_action_for_score(35)
    assert lvl1["action"] == "alert"
    assert lvl1["auto"] is True

    # Level 3: 50 - 69 -> alert_with_action (auto=False, analyst button)
    lvl2 = get_action_for_score(55)
    assert lvl2["action"] == "alert_with_action"
    assert lvl2["auto"] is False

    # Level 4: 70 - 84 -> kill_process_tree (auto=True, rollback=300)
    lvl3 = get_action_for_score(75)
    assert lvl3["action"] == "kill_process_tree"
    assert lvl3["auto"] is True
    assert lvl3["rollback_window"] == 300

    # Level 5: 85 - 100 -> isolate (auto=True, rollback=300)
    lvl4 = get_action_for_score(90)
    assert lvl4["action"] == "isolate"
    assert lvl4["auto"] is True
    assert lvl4["rollback_window"] == 300

    # Edge cases
    assert get_action_for_score(100)["action"] == "isolate"
    assert get_action_for_score(105)["action"] == "isolate"


@pytest.mark.asyncio
async def test_policy_engine_graduated_evaluation_flow():
    """Verify PolicyEngineService executes graduated actions without DB policies."""
    mock_db = AsyncMock()
    engine = PolicyEngineService(mock_db)

    agent = Agent(id="WIN-DEMO-01", hostname="WIN-DEMO-01", ip_address="192.168.1.100", status=AgentStatus.ACTIVE)
    engine.agent_repo.get = AsyncMock(return_value=agent)
    engine.group_service.list_groups_for_agent = AsyncMock(return_value=[])
    engine.policy_service.match_policy = AsyncMock(return_value=None)
    engine.action_service.create_and_apply_action = AsyncMock(return_value=MagicMock(id="act_123"))

    # Case 1: score = 35 -> alert only (no auto-block)
    res_alert = await engine.evaluate_and_execute(agent_id="WIN-DEMO-01", risk_score=35, dry_run=False)
    assert res_alert.action_type == "alert"
    assert res_alert.executed is True
    engine.action_service.create_and_apply_action.assert_not_called()

    # Case 2: score = 55 -> alert_with_action (auto=False, analyst decide)
    res_alert_action = await engine.evaluate_and_execute(agent_id="WIN-DEMO-01", risk_score=55, dry_run=False)
    assert res_alert_action.action_type == "alert_with_action"
    assert res_alert_action.executed is False
    assert res_alert_action.execution_summary["auto"] is False
    engine.action_service.create_and_apply_action.assert_not_called()

    # Case 3: score = 75 -> kill_process_tree + rollback 300s
    res_kill = await engine.evaluate_and_execute(
        agent_id="WIN-DEMO-01",
        risk_score=75,
        context={"pid": 4567, "process_name": "malware.exe"},
        dry_run=False
    )
    assert res_kill.action_type == "kill_process_tree"
    assert res_kill.executed is True
    engine.action_service.create_and_apply_action.assert_called_once()
    call_args = engine.action_service.create_and_apply_action.call_args[1]
    assert call_args["action_type"] == "kill_process_tree"
    assert call_args["auto_rollback_seconds"] == 300
    assert call_args["action_params"]["pid"] == 4567

    # Case 4: score = 90 -> isolate + rollback 300s
    engine.action_service.create_and_apply_action.reset_mock()
    res_isolate = await engine.evaluate_and_execute(agent_id="WIN-DEMO-01", risk_score=90, dry_run=False)
    assert res_isolate.action_type == "isolate"
    assert res_isolate.executed is True
    engine.action_service.create_and_apply_action.assert_called_once()
    call_args_iso = engine.action_service.create_and_apply_action.call_args[1]
    assert call_args_iso["action_type"] == "isolate"
    assert call_args_iso["auto_rollback_seconds"] == 300
