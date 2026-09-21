import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.schemas.enums import AgentStatus
from app.models.agent import Agent
from app.models.agent_group import AgentGroup, AgentGroupMember
from app.models.response_policy import ResponsePolicy
from app.models.response_action import ResponseAction
from app.services.agent_group_service import AgentGroupService
from app.services.response_policy_service import ResponsePolicyService
from app.services.policy_engine_service import PolicyEngineService
from app.services.rollback_service import RollbackService
from app.schemas.response_action import UndoBatchResponse


@pytest.mark.asyncio
async def test_group_crud_and_membership(mock_db):
    """Test tạo nhóm, thêm và xóa agent khỏi nhóm."""
    service = AgentGroupService(mock_db)
    service.group_repo.get_by_name = AsyncMock(return_value=None)
    service.group_repo.add = AsyncMock()

    # 1. Tạo nhóm HR
    group = await service.create_group(name="HR", description="Human Resources")
    assert group.name == "HR"
    assert group.id.startswith("grp_")

    # 2. Thêm agent vào nhóm
    mock_agent1 = Agent(id="client1", hostname="client1", ip_address="172.19.0.4", status=AgentStatus.ACTIVE)
    mock_agent2 = Agent(id="client2", hostname="client2", ip_address="172.19.0.5", status=AgentStatus.ACTIVE)
    service.group_repo.get = AsyncMock(return_value=group)
    service.agent_repo.get = AsyncMock(side_effect=lambda aid: mock_agent1 if aid == "client1" else mock_agent2)
    service.group_repo.add_agent_to_group = AsyncMock(
        side_effect=lambda gid, aid: AgentGroupMember(group_id=gid, agent_id=aid)
    )

    members = await service.add_agents_to_group(group.id, ["client1", "client2"])
    assert len(members) == 2
    assert members[0].agent_id == "client1"
    assert members[1].agent_id == "client2"


@pytest.mark.asyncio
async def test_batch_group_action_creates_independent_snapshots(mock_db):
    """Test batch response action trên group: mỗi agent nhận 1 snapshot và action độc lập."""
    service = AgentGroupService(mock_db)
    group = AgentGroup(id="grp_hr", name="HR", description="HR Department")
    agent1 = Agent(id="client1", hostname="client1", ip_address="172.19.0.4", status=AgentStatus.ACTIVE)
    agent2 = Agent(id="client2", hostname="client2", ip_address="172.19.0.5", status=AgentStatus.ACTIVE)

    service.group_repo.get = AsyncMock(return_value=group)
    service.group_repo.get_agents_in_group = AsyncMock(return_value=[agent1, agent2])

    # Mock action_service.create_and_apply_action
    action1 = ResponseAction(id="act_1", agent_id="client1", action_type="isolate", status="applied", snapshot={"agent_id": "client1"})
    action2 = ResponseAction(id="act_2", agent_id="client2", action_type="isolate", status="applied", snapshot={"agent_id": "client2"})

    service.action_service.create_and_apply_action = AsyncMock(
        side_effect=lambda agent_id, **kwargs: action1 if agent_id == "client1" else action2
    )

    res = await service.execute_group_action(
        group_id="grp_hr",
        action_type="isolate",
        action_params={"reason": "Compromised credential in HR"},
        auto_rollback_seconds=300
    )

    assert res.group_id == "grp_hr"
    assert res.group_name == "HR"
    assert res.total_agents == 2
    assert res.succeeded == 2
    assert res.failed == 0
    assert len(res.actions) == 2
    assert res.actions[0].action_id == "act_1"
    assert res.actions[1].action_id == "act_2"
    assert service.action_service.create_and_apply_action.call_count == 2


@pytest.mark.asyncio
async def test_batch_group_rollback(mock_db):
    """Test rollback toàn bộ action của một group."""
    service = RollbackService(mock_db)
    group = AgentGroup(id="grp_hr", name="HR")
    agent1 = Agent(id="client1", hostname="client1", ip_address="172.19.0.4", status=AgentStatus.ISOLATED)
    agent2 = Agent(id="client2", hostname="client2", ip_address="172.19.0.5", status=AgentStatus.ISOLATED)

    service.group_repo.get = AsyncMock(return_value=group)
    service.group_repo.get_agents_in_group = AsyncMock(return_value=[agent1, agent2])

    act1 = ResponseAction(id="act_1", agent_id="client1", action_type="isolate", status="applied")
    act2 = ResponseAction(id="act_2", agent_id="client2", action_type="isolate", status="applied")
    service.action_repo.get_active_applied_by_agents = AsyncMock(return_value=[act1, act2])
    service.rollback_action = AsyncMock()

    res = await service.rollback_group_actions(group_id="grp_hr", reason="Incident resolved")

    assert res.reverted == 2
    assert res.failed == 0
    assert "act_1" in res.action_ids
    assert "act_2" in res.action_ids
    assert service.rollback_action.call_count == 2


@pytest.mark.asyncio
async def test_policy_matching_thresholds(mock_db):
    """Test Policy Service matching theo dải điểm rủi ro và group."""
    service = ResponsePolicyService(mock_db)

    policy_alert = ResponsePolicy(id="p1", name="Alert", min_score=30.0, max_score=49.99, action_type="alert", scope="agent", priority=10, is_active=True)
    policy_block = ResponsePolicy(id="p2", name="Block", min_score=50.0, max_score=69.99, action_type="block_ip", scope="agent", priority=20, is_active=True)
    policy_isolate_agent = ResponsePolicy(id="p3", name="Isolate Agent", min_score=70.0, max_score=84.99, action_type="isolate", scope="agent", priority=30, is_active=True)
    policy_isolate_group = ResponsePolicy(id="p4", name="Isolate Group", min_score=85.0, max_score=100.0, action_type="isolate", scope="group", priority=40, is_active=True)

    def mock_find(score, group_ids=None):
        policies = [policy_isolate_group, policy_isolate_agent, policy_block, policy_alert]
        matched = [p for p in policies if p.min_score <= score <= p.max_score]
        return matched

    service.policy_repo.find_matching_policies = AsyncMock(side_effect=mock_find)

    # Score 40 -> Alert
    m1 = await service.match_policy(40.0)
    assert m1 is not None and m1.action_type == "alert" and m1.scope == "agent"

    # Score 60 -> Block IP
    m2 = await service.match_policy(60.0)
    assert m2 is not None and m2.action_type == "block_ip" and m2.scope == "agent"

    # Score 75 -> Isolate Agent
    m3 = await service.match_policy(75.0)
    assert m3 is not None and m3.action_type == "isolate" and m3.scope == "agent"

    # Score 90 -> Isolate Group
    m4 = await service.match_policy(90.0)
    assert m4 is not None and m4.action_type == "isolate" and m4.scope == "group"


@pytest.mark.asyncio
async def test_policy_engine_dry_run_preview(mock_db):
    """Test Policy Engine Dry-Run mode không can thiệp thực tế và preview đúng scope group."""
    engine = PolicyEngineService(mock_db)

    agent1 = Agent(id="client1", hostname="client1", ip_address="172.19.0.4", status=AgentStatus.ACTIVE)
    agent2 = Agent(id="client2", hostname="client2", ip_address="172.19.0.5", status=AgentStatus.ACTIVE)
    group_hr = AgentGroup(id="grp_hr", name="HR")

    policy_isolate_group = ResponsePolicy(
        id="pol_group",
        name="Critical Risk Group Isolate",
        min_score=85.0,
        max_score=100.0,
        action_type="isolate",
        scope="group",
        priority=40,
        is_active=True,
        target_group=None,
        action_params={},
        auto_rollback_seconds=300
    )

    engine.agent_repo.get = AsyncMock(return_value=agent1)
    engine.group_service.list_groups_for_agent = AsyncMock(return_value=[group_hr])
    engine.policy_service.match_policy = AsyncMock(return_value=policy_isolate_group)
    engine.group_service.list_agents_in_group = AsyncMock(return_value=[agent1, agent2])
    engine.action_service.create_and_apply_action = AsyncMock()
    engine.group_service.execute_group_action = AsyncMock()

    # Chạy evaluate với dry_run = True
    res = await engine.evaluate_and_execute(agent_id="client1", risk_score=88.5, dry_run=True)

    assert res.dry_run is True
    assert res.executed is False
    assert res.scope == "group"
    assert res.action_type == "isolate"
    assert len(res.affected_groups) == 1
    assert res.affected_groups[0].name == "HR"
    assert len(res.affected_agents) == 2
    assert len(res.simulated_actions) == 2

    # Verify không có lệnh hay action nào được thực thi
    engine.action_service.create_and_apply_action.assert_not_called()
    engine.group_service.execute_group_action.assert_not_called()
