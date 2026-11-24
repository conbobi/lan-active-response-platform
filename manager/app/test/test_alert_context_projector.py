from datetime import UTC, datetime, timedelta

import pytest

from app.models.flow import Flow
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.services.ai.alert_context_projector import NA, build_alert_context, evidence_version
from app.services.detection.network_shell import RULE_ID, detect_network_shell

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def holder(pid=801, start=10.0, name="bash", fds=(0, 1), **extra):
    return {
        "pid": pid, "process_start_time": start, "process_name": name,
        "exe_path": f"/usr/bin/{name}", "socket_fds": list(fds), "stdio_fds": list(fds),
        "interactive": True, **extra,
    }


def socket_observation(*holders, port=4444, **extra):
    return {
        "protocol": "TCP", "src_ip": "192.0.2.10", "src_port": 43000,
        "dst_ip": "198.51.100.1", "dst_port": port, "status": "ESTABLISHED",
        "observed_at": NOW.isoformat(), "inode": "990", "socket_id": "sock-990",
        "attribution": "inode_verified", "direction": "outbound",
        "holders": list(holders), **extra,
    }


def incident_with(evidence, *, risk=75.0, description=None, identifier="inc-triage"):
    return Incident(
        id=identifier, agent_id="agent-a", created_at=NOW, title="Alert",
        description=description or "", risk_score=risk, detection_evidence=evidence,
        status="open",
    )


def verified_incident(*holders):
    evidence = detect_network_shell(socket_observation(*(holders or [holder()])))
    assert evidence
    return incident_with({**evidence, "rule_version": "builtin:1"})


def db_flow(raw, agent="agent-a"):
    return Flow(
        agent_id=agent, start_time=NOW, pid=801, socket_evidence=raw,
        **{key: raw[key] for key in ("protocol", "src_ip", "src_port", "dst_ip", "dst_port")},
    )


@pytest.mark.parametrize("row_start", [None, 9.0, 12.0])
def test_pid_reuse_cannot_enrich_snapshot(row_start):
    inc = incident_with({"process": holder(cmdline=None)})
    row = ProcessInfo(
        agent_id="agent-a", pid=801, process_start_time=row_start, created_at=NOW,
        cmdline="other process", name="other process",
    )
    assert build_alert_context(inc, processes=[row]).processes[0]["cmdline"] == NA


def test_exact_snapshot_identity_and_time_enrich_missing_value_only():
    inc = incident_with({"process": holder(cmdline=None)})
    wrong_agent = ProcessInfo(
        agent_id="agent-b", pid=801, process_start_time=10, created_at=NOW, cmdline="wrong",
    )
    exact = ProcessInfo(
        agent_id="agent-a", pid=801, process_start_time=10, created_at=NOW, cmdline="recorded",
    )
    result = build_alert_context(inc, processes=[wrong_agent, exact])
    assert result.processes[0]["cmdline"] == "recorded"
    assert inc.detection_evidence["process"]["cmdline"] is None


def test_socket_inode_fds_and_parent_survive_projection():
    parent = holder(800, 9, name="systemd", fds=())
    inc = verified_incident(holder(parent_pid=800, ancestry=[parent]))
    result = build_alert_context(inc, hostname="workstation")
    assert result.verified_shell == "N1"
    assert result.metadata["hostname"] == "workstation"
    assert result.processes[0]["parent"] == "P2"
    assert result.flows[0]["inode"] == "990"
    assert result.flows[0]["holders"] == [
        {"pid": 801, "process": "P1", "socket_fds": [0, 1], "stdio_fds": [0, 1]}
    ]
    assert result.flows[0]["originator_pid"] == NA


def test_equal_holders_have_no_primary_and_mandatory_overflow_is_explicit():
    result = build_alert_context(verified_incident(holder(), holder(802, 11)))
    assert result.conflict
    assert result.flows[0]["primary_process"] == NA
    assert len(result.flows[0]["holders"]) == 2
    assert result.prompt_data(1, 1)["omitted"]["required_evidence"] == 1


def test_flows_require_matching_agent_identity_and_observation_window():
    inc = incident_with({"rule_id": RULE_ID, "process": holder()})
    stale = socket_observation(holder(), observed_at=(NOW + timedelta(minutes=30)).isoformat())
    reused = socket_observation(holder(start=11.0))
    exact = socket_observation(holder())
    assert not build_alert_context(inc, flows=[db_flow(stale), db_flow(reused), db_flow(exact, "b")]).flows
    assert build_alert_context(inc, flows=[db_flow(exact)]).flows[0]["source"] == "flow_socket_evidence"


def test_no_anchor_or_verified_inode_does_not_join_flow():
    inc = incident_with(None, description="Incident created manually")
    assert not build_alert_context(inc, flows=[db_flow(socket_observation(holder()))]).flows
    sparse = incident_with({"process": holder(), "network": {"dst_port": 4444}})
    assert build_alert_context(sparse).flows[0]["holders"] == []
    assert "verified_socket_holder" in build_alert_context(sparse).missing


def test_fim_and_authentication_fields_survive_projection():
    old_hash, new_hash = "a" * 64, "b" * 64
    fim = incident_with({"rule_id": "builtin_linux_sensitive_file_change"}, description=(
        f"Detail: path=/etc/sudoers, action=MODIFIED, old_sha256={old_hash}, new_sha256={new_hash}"
    ))
    assert build_alert_context(fim).facts[0]["new_hash"] == new_hash
    auth = incident_with({"rule_id": "brute_force", "factors": [{
        "rule": "brute_force", "reason": "ssh login for 'operator' from 192.0.2.20 after 8 failed attempts for the same account and source",
        "window_seconds": 60,
    }]})
    fact = build_alert_context(auth).facts[0]
    assert (fact["account"], fact["service"], fact["source_ip"], fact["window_seconds"]) == (
        "operator", "ssh", "192.0.2.20", 60,
    )


def test_evidence_revision_ignores_receipt_counters_but_changes_for_socket_observation():
    inc = verified_incident()
    initial = evidence_version(inc)
    inc.detection_evidence["observations"] = 2
    inc.detection_evidence["last_received_at"] = NOW.isoformat()
    assert evidence_version(inc) == initial
    inc.detection_evidence["network"]["inode"] = "991"
    assert evidence_version(inc) != initial
