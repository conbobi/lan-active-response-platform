"""Regression tests for reverse-shell correlation, prior-upload linkage, enrichment, timeline, and containment status."""
from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from app.models.web_access_log import WebAccessLog
from app.schemas.enums import IncidentSeverity
from app.services.detection import web_compromise
from app.services.response import containment as ct
from app.websocket import agent_ws
from test_containment import ADMIN, ANALYST, OPERATOR, act, env, overview, run_agent
from test_http_response_assist import lab  # noqa: F401
from test_network_module import AGENT
from test_web_compromise_chain import ATTACKER, PING, PAYLOAD, SESSION, T0, WEB, bypass, chain_incidents, condition, iso, send


@pytest.mark.asyncio
async def test_orphaned_payload_without_proc_connector_and_prior_upload_correlates_to_critical(env):
    """Even when wrapper /bin/sh exited before polling (no proc_connector) and file was uploaded 3h ago,
    correlation joins upload -> command injection -> orphaned python3 -> outbound 4444 -> CRITICAL."""
    client, factory, _, payload = env
    earlier = datetime.fromtimestamp(T0 - 3 * 3600, timezone.utc)
    upload_sha = hashlib.sha256(payload.read_bytes()).hexdigest()
    async with factory.begin() as db:
        db.add(WebAccessLog(
            id="wlog_prior_upload_01",
            agent_id=AGENT,
            src_ip=ATTACKER,
            host="100.112.146.63:5000",
            method="POST",
            path="/upload",
            user_agent="curl/8.14.1",
            status_code=200,
            raw_message=(
                '{"source":"normalized_http","service":"flask_web","process_pid":153380,'
                f'"request_id":"prior123","session_ref":"{SESSION}",'
                '"app_event":{"type":"file_upload","stored":true,'
                f'"upload_path":"{payload}","upload_size":48,"upload_sha256":"{upload_sha}",'
                '"extension":".py","outside_upload_dir":false,"script_or_binary":true}}'
            ),
            timestamp=earlier,
            created_at=earlier,
        ))

    await bypass(factory)
    ping_ref = {
        **PING,
        "app_event": {
            **PING["app_event"],
            "referenced_upload_files": [payload.name],
        },
    }
    await send(factory, agent_ws._handle_web_access_log, ping_ref)
    # Only orphaned python3 (parent_pid=1) appears in PROCESS_LIST (no /bin/sh wrapper recorded!).
    orphan_py = {
        **PAYLOAD,
        "pid": 154107,
        "parent_pid": 1,
        "process_start_time": round(T0 + 67.2, 2),
        "cmdline": f"python3 {payload}",
    }
    await send(factory, agent_ws._handle_process_list, {"processes": [WEB, orphan_py], "activity_sample": {"complete": True}})
    conn = {
        "protocol": "TCP", "src_ip": "100.112.146.63", "src_port": 40986, "dst_ip": ATTACKER, "dst_port": 4444,
        "status": "ESTABLISHED", "direction": "outbound", "direction_basis": "no_local_listener",
        "attribution": "inode_verified", "observed_at": iso(90), "first_seen": iso(68), "pid": 154107,
        "holders": [{
            "pid": 154107, "parent_pid": 1, "process_start_time": orphan_py["process_start_time"],
            "process_name": "python3", "exe_path": "/usr/bin/python3.13", "cmdline": orphan_py["cmdline"],
            "uid": 0, "euid": 0, "socket_stdio": True, "ancestry": [],
        }],
    }
    await send(factory, agent_ws._handle_telemetry_risk, {"network_connections": [conn], "process_list": [orphan_py]})

    incident, = await chain_incidents(factory)
    assert incident.severity == IncidentSeverity.CRITICAL and incident.risk_score >= 90
    assert condition(incident, "web_spawned_shell")["status"] == "CORRELATED"
    assert condition(incident, "uploaded_file_execution")["status"] == "CORRELATED"
    assert condition(incident, "suspicious_upload")["status"] == "CORRELATED"
    assert condition(incident, "suspicious_upload")["upload_sha256"] == upload_sha
    assert condition(incident, "outbound_connection")["status"] == "OBSERVED"

    # Enriched incident API + Timeline API expose full process/network evidence
    detail = client.get(f"/api/v1/incidents/{incident.id}").json()
    assert detail["culprit_process"]["pid"] == 154107
    assert detail["network_indicators"][0]["dst_ip"] == ATTACKER
    assert detail["network_indicators"][0]["dst_port"] == 4444
    timeline = client.get(f"/api/v1/incidents/{incident.id}/timeline").json()["timeline"]
    assert any(item["type"] == "process_spawn" and item["details"]["pid"] == 154107 for item in timeline)
    assert any(item["type"] == "network_connection" and item["details"]["dst_ip"] == ATTACKER for item in timeline)

    # Containment overview exposes explicit Phase C file_status + command_id
    view = overview(client, incident.id)
    assert view["files"][0]["file_status"] == "FILE_EXECUTION_CORRELATED"
    assert view["files"][0]["sha256"] == upload_sha
    assert act(client, incident.id, "quarantine_file", {"path": str(payload)}).status_code == 409
    act(client, incident.id, "inspect_file", {"path": str(payload)})
    await run_agent(factory)
    req = act(client, incident.id, "quarantine_file", {"path": str(payload)}).json()
    client.post(f"/api/v1/containment/actions/{req['action_id']}/approve", headers=ADMIN, json={})
    await run_agent(factory)
    after = overview(client, incident.id)
    assert after["files"][0]["file_status"] == "FILE_QUARANTINED"
    assert next(a for a in after["actions"] if a["id"] == req["action_id"])["command_id"]

