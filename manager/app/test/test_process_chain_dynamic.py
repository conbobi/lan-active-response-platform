import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.process_group import ProcessGroup
from app.models.process_chain_rule import ProcessChainRule as ModelProcessChainRule
from app.schemas.process_group import ProcessGroupCreate, ProcessGroupUpdate
from app.schemas.process_chain_rule import ProcessChainRuleCreate, ProcessChainRuleUpdate
from app.services.process_group_service import ProcessGroupService
from app.services.process_chain_rule_service import ProcessChainRuleService
from app.services.risk_rules.process_chain_rule import ProcessChainRule as RiskProcessChainRule
from app.core.exceptions import AppException

pytestmark = pytest.mark.asyncio


async def test_process_chain_rule_fallback():
    """Verify that fallback rules are used when no DB session is in context."""
    RiskProcessChainRule.invalidate_cache()
    rule = RiskProcessChainRule()

    telemetry = {
        "process_tree": [
            {"parent_name": "WINWORD.EXE", "child_name": "cmd.exe"}
        ],
        "process_list": [
            {"parent_name": "excel.exe", "name": "powershell.exe"}
        ]
    }

    # Empty context -> fallback to default parents/children
    score, reason = await rule.evaluate(telemetry, {})
    assert score > 0.0
    assert "Process chain anomaly detected" in reason
    assert "WINWORD.EXE" in reason or "excel.exe" in reason


async def test_process_chain_rule_with_mock_session():
    """Verify dynamic evaluation against mock DB session rules."""
    RiskProcessChainRule.invalidate_cache()
    rule = RiskProcessChainRule()

    # Create mock groups and rule
    group_parent = ProcessGroup(
        id="grp-parent-1",
        name="Test Browsers",
        patterns=["chrome.exe", "firefox.exe"],
        description="Web browsers"
    )
    group_child = ProcessGroup(
        id="grp-child-1",
        name="Test Payloads",
        patterns=["malware.exe", "beacon.exe"],
        description="Suspicious binaries"
    )

    db_rule = ModelProcessChainRule(
        id="pcr-1",
        name="Browser Launching Malware",
        parent_group_id="grp-parent-1",
        child_group_id="grp-child-1",
        action="block",
        is_active=True
    )
    db_rule.parent_group = group_parent
    db_rule.child_group = group_child

    mock_session = AsyncMock(spec=AsyncSession)
    mock_execute_result = MagicMock()
    mock_execute_result.scalars.return_value.all.return_value = [db_rule]
    mock_session.execute = AsyncMock(return_value=mock_execute_result)

    context = {
        "session": mock_session,
        "agent_id": "test-agent-01"
    }

    telemetry = {
        "process_tree": [
            {"parent_name": "chrome.exe", "child_name": "malware.exe"}
        ],
        "process_list": []
    }

    score, reason = await rule.evaluate(telemetry, context)
    assert score >= 35.0
    assert "Browser Launching Malware" in reason
    assert "BLOCK" in reason
    assert "chrome.exe" in reason
    assert "malware.exe" in reason

    # Cached evaluation (should not query session.execute again)
    call_count_before = mock_session.execute.call_count
    score2, reason2 = await rule.evaluate(telemetry, context)
    assert score2 == score
    assert mock_session.execute.call_count == call_count_before


async def test_process_group_service_crud():
    mock_session = AsyncMock(spec=AsyncSession)
    service = ProcessGroupService(mock_session)

    # Mock repo
    service.repo.get_by_name = AsyncMock(return_value=None)
    service.repo.add = AsyncMock(side_effect=lambda x: x)
    service.repo.get = AsyncMock(return_value=ProcessGroup(
        id="grp-1", name="Office", patterns=["winword.exe"], description="Office"
    ))
    service.repo.delete = AsyncMock(return_value=True)
    service.chain_rule_repo.count_by_group_id = AsyncMock(return_value=0)

    # 1. Create
    dto = ProcessGroupCreate(name="New Group", patterns=["test.exe"], description="Desc")
    res = await service.create_group(dto)
    assert res.name == "New Group"
    assert "test.exe" in res.patterns

    # 2. Update
    update_dto = ProcessGroupUpdate(name="Updated Name")
    service.repo.get_by_name = AsyncMock(return_value=None)
    res_up = await service.update_group("grp-1", update_dto)
    assert res_up.name == "Updated Name"

    # 3. Delete success
    await service.delete_group("grp-1")

    # 4. Delete conflict (referenced by rules -> 409)
    service.chain_rule_repo.count_by_group_id = AsyncMock(return_value=2)
    with pytest.raises(AppException) as exc_info:
        await service.delete_group("grp-1")
    assert exc_info.value.status_code == 409
    assert "referenced by 2 process chain rule(s)" in exc_info.value.message
