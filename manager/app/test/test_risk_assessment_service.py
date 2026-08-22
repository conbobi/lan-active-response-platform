import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.risk_assessment_service import RiskAssessmentService
from app.schemas.risk import RiskAssessmentDTO

pytestmark = pytest.mark.asyncio


async def test_evaluate_low_risk(mock_db, mock_notification_service):
    service = RiskAssessmentService(mock_db)
    service.risk_repo = MagicMock()
    service.risk_repo.add = AsyncMock()
    service.whitelist_service = MagicMock()
    service.whitelist_service.is_whitelisted = AsyncMock(return_value=False)
    service.threat_intel_service = MagicMock()
    service.threat_intel_service.check_hash = AsyncMock(return_value={"is_malicious": False})
    service.threat_intel_service.check_ip = AsyncMock(return_value={"is_malicious": False})
    service.setting_service = MagicMock()
    service.setting_service.get_risk_thresholds = AsyncMock(return_value={"log": 30.0, "alert": 30.0, "alert_with_buttons": 60.0, "auto_isolate": 80.0})

    dto = RiskAssessmentDTO(
        agent_id="agent-1",
        cpu_usage=10.0,
        process_list=[],
        network_connections=[]
    )

    score, factors = await service.evaluate(dto.agent_id, dto)
    assert 0 <= score <= 100
    assert score == 0.0


async def test_process_risk_high_risk_auto_isolate(mock_db, mock_notification_service):
    service = RiskAssessmentService(mock_db)
    service.risk_repo = MagicMock()
    service.risk_repo.add = AsyncMock()
    service.agent_repo = MagicMock()
    service.agent_repo.get = AsyncMock(return_value=MagicMock(hostname="agent-1", isolate=MagicMock()))

    service.whitelist_service = MagicMock()
    service.whitelist_service.is_whitelisted = AsyncMock(return_value=False)

    service.threat_intel_service = MagicMock()
    service.threat_intel_service.check_hash = AsyncMock(return_value={"is_malicious": True})
    service.threat_intel_service.check_ip = AsyncMock(return_value={"is_malicious": True})

    service.setting_service = MagicMock()
    service.setting_service.get_risk_thresholds = AsyncMock(return_value={"log": 30.0, "alert": 30.0, "alert_with_buttons": 60.0, "auto_isolate": 80.0})

    service.notification_service = mock_notification_service

    mock_dispatcher = MagicMock()
    mock_dispatcher.push_command = AsyncMock()

    mock_cmd_repo = MagicMock()
    mock_cmd_repo.add = AsyncMock()

    with patch("app.services.risk_assessment_service.command_dispatcher", mock_dispatcher), \
         patch("app.services.risk_assessment_service.CommandRepository", return_value=mock_cmd_repo), \
         patch("app.services.risk_assessment_service.IncidentService") as MockIncService:

        mock_inc_instance = MagicMock()
        mock_inc_instance.create_from_risk = AsyncMock(return_value=MagicMock(id="inc-123"))
        MockIncService.return_value = mock_inc_instance

        dto = RiskAssessmentDTO(
            agent_id="agent-1",
            cpu_usage=95.0,
            process_list=[{"name": "mimikatz.exe", "is_suspicious": True, "hash": "badhash"}],
            network_connections=[{"dst_port": 4444, "dst_ip": "1.2.3.4"}]
        )

        record = await service.process_risk(dto.agent_id, dto)
        assert record.score >= 80.0

        mock_dispatcher.push_command.assert_awaited_once()
        call_args = mock_dispatcher.push_command.call_args[0]
        assert call_args[1] == "agent-1"


async def test_whitelisted_agent_no_auto_isolate(mock_db, mock_notification_service):
    service = RiskAssessmentService(mock_db)
    service.risk_repo = MagicMock()
    service.risk_repo.add = AsyncMock()
    service.agent_repo = MagicMock()
    service.agent_repo.get = AsyncMock(return_value=MagicMock(hostname="agent-1"))

    service.whitelist_service = MagicMock()
    service.whitelist_service.is_whitelisted = AsyncMock(return_value=True)

    service.threat_intel_service = MagicMock()
    service.threat_intel_service.check_hash = AsyncMock(return_value={"is_malicious": False})
    service.threat_intel_service.check_ip = AsyncMock(return_value={"is_malicious": False})

    service.setting_service = MagicMock()
    service.setting_service.get_risk_thresholds = AsyncMock(return_value={"log": 30.0, "alert": 30.0, "alert_with_buttons": 60.0, "auto_isolate": 80.0})

    service.notification_service = mock_notification_service

    mock_dispatcher = MagicMock()
    mock_dispatcher.push_command = AsyncMock()

    with patch("app.services.risk_assessment_service.command_dispatcher", mock_dispatcher):
        dto = RiskAssessmentDTO(
            agent_id="agent-1",
            cpu_usage=95.0,
            process_list=[{"name": "excel.exe", "is_suspicious": False}],
            network_connections=[]
        )

        record = await service.process_risk(dto.agent_id, dto)
        mock_dispatcher.push_command.assert_not_awaited()