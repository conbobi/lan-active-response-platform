"""Task C: multi-stage web compromise correlation (web_compromise_chain).

Messages are replayed through the real WebSocket handlers in the order of the 2026-11-27 lab
incident; PIDs/commands mirror it, timestamps are shifted to "now". Fixture data only.
"""
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.incident import Incident
from app.schemas.enums import IncidentSeverity
from app.services.detection import web_compromise
from app.websocket import agent_ws
from test_http_response_assist import lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

ATTACKER = "100.67.222.3"
SESSION = "614dd4c6968e1deb3a12b9ea4e7180517127172feb47d52bfe16a038f10084dc"
T0 = time.time() - 600  # attack began ten minutes ago


def iso(offset):
    return datetime.fromtimestamp(T0 + offset, timezone.utc).isoformat()


WEB = {"pid": 153380, "parent_pid": 1, "process_start_time": round(T0 - 300, 2), "name": "python",
       "exe": "/usr/bin/python3.13", "cmdline": "/opt/larp-agent/venv/bin/python -u /opt/larp-agent/vulnerable_web/app.py",
       "uid": 0, "euid": 0}
SH = {"pid": 154105, "parent_pid": 153380, "process_start_time": round(T0 + 66.8, 2), "name": "sh", "exe": "/usr/bin/dash",
      "cmdline": "/bin/sh -c ping -c 1 127.0.0.1;python3 /tmp/uploads/backdoor.py", "uid": 0, "euid": 0}
PAYLOAD = {"pid": 154107, "parent_pid": 154105, "process_start_time": round(T0 + 66.86, 2), "name": "python3",
           "exe": "/usr/bin/python3.13", "cmdline": "python3 /tmp/uploads/backdoor.py", "uid": 0, "euid": 0}


def web_log(request_id, method, path, status, offset, app_event=None, ua="curl/8.14.1", indicators=()):
    payload = {"agent_id": AGENT, "client_ip": ATTACKER, "method": method, "path": path, "status_code": status,
               "user_agent": ua, "request_id": request_id, "timestamp": iso(offset), "service": "flask_web",
               "payload_indicators": list(indicators), "event_id": request_id[:32].ljust(32, "0"),
               "process_pid": 153380, "parent_pid": 1, "session_ref": SESSION}
    if app_event:
        payload["app_event"] = app_event
    return payload


LOGIN = ("6ae03000ec1a4b73bc0d60da9543cc50", 0)
UPLOAD = web_log("fd0e8bc2731c4fbfbce6104ff9984102", "POST", "/upload", 200, 30, {
    "type": "file_upload", "stored": True, "upload_path": "/tmp/uploads/backdoor.py", "upload_size": 804,
    "upload_sha256": "c" * 64, "extension": ".py", "outside_upload_dir": False, "script_or_binary": True})
PING = web_log("1450d62b30884258bddd134d4a0cd040", "GET", "/ping", 500, 77, {
    "type": "shell_command", "parameter": "ip", "parameter_length": 41, "parameter_sha256": "d" * 64,
    "shell_indicators": ["shell_command_separator"], "referenced_upload_files": ["backdoor.py"],
    "execution_result": "timeout", "child_pid": 154105, "child_spawned_at": SH["process_start_time"], "duration_s": 10.0})


async def send(factory, handler, payload, **extra):
    async with factory() as db:
        await handler(AGENT, {"payload": {"agent_id": AGENT, **payload}, "wait_ack": False, **extra}, db)
        await db.commit()


async def bypass(factory):
    request_id, offset = LOGIN
    await send(factory, agent_ws._handle_auth_event, {"events": [{
        "service": "flask_web", "source_ip": ATTACKER, "status": "success", "count": 1, "timestamp": iso(offset),
        "event_id": request_id, "request_id": request_id, "method": "POST", "path": "/login", "http_status": 302,
        "payload_indicators": ["sql_boolean_expression"], "auth_result": "success", "credential_match": False,
        "suspected_auth_bypass": True, "session_ref": SESSION}]})


async def chain_incidents(factory):
    async with factory() as db:
        rows = (await db.scalars(select(Incident))).all()
    return [i for i in rows if (i.detection_evidence or {}).get("rule_id") == web_compromise.RULE_ID]


def condition(incident, key):
    return next(c for c in incident.detection_evidence["chain"]["conditions"] if c["id"] == key)


@pytest.mark.asyncio
async def test_lone_automated_request_is_not_escalated(lab):
    _, factory = lab
    await send(factory, agent_ws._handle_web_access_log, web_log("a" * 32, "GET", "/ping", 500, 77))
    assert await chain_incidents(factory) == []
    async with factory() as db:
        assert all(i.severity != IncidentSeverity.CRITICAL for i in (await db.scalars(select(Incident))).all())


@pytest.mark.asyncio
async def test_bypass_and_upload_without_execution_is_intrusion_not_rce(lab):
    _, factory = lab
    await bypass(factory)
    assert await chain_incidents(factory) == []  # one stage alone stays with the per-request detectors
    await send(factory, agent_ws._handle_web_access_log, UPLOAD)
    incident, = await chain_incidents(factory)
    assert incident.severity == IncidentSeverity.MEDIUM and incident.risk_score < 70
    assert incident.title.startswith("Web Application Intrusion")
    assert condition(incident, "auth_bypass")["status"] == "OBSERVED"
    assert "session_ref" in condition(incident, "auth_bypass")["link"]
    assert condition(incident, "uploaded_file_execution")["status"] == "NOT_OBSERVED"
    assert "chưa xác nhận đã thực thi" in condition(incident, "suspicious_upload")["detail"]


@pytest.mark.asyncio
async def test_legitimate_ping_shell_is_not_a_stage(lab):
    _, factory = lab
    legit = {**SH, "pid": 154200, "cmdline": "/bin/sh -c ping -c 1 8.8.8.8"}
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": legit["process_start_time"], **legit, "parent": WEB}]})
    assert await chain_incidents(factory) == []  # root web app spawning a plain ping shell


@pytest.mark.asyncio
async def test_full_chain_builds_one_explained_incident_that_escalates(lab):
    client, factory = lab
    await bypass(factory)
    await send(factory, agent_ws._handle_web_access_log, UPLOAD)
    await send(factory, agent_ws._handle_web_access_log, PING)
    # Kernel exec events: web app → sh -c (injected) → python3 /tmp/uploads/backdoor.py
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": SH["process_start_time"], **SH, "parent": WEB},
        {"event": "exec", "observed_at": PAYLOAD["process_start_time"], **PAYLOAD, "parent": SH}]})
    incident, = await chain_incidents(factory)
    first_id = incident.id
    assert incident.severity == IncidentSeverity.HIGH  # execution seen, no connection yet
    assert condition(incident, "outbound_connection")["status"] == "NOT_OBSERVED"

    # Socket sample: the orphaned payload holds stdio-bound outbound TCP to the attacker.
    conn = {"protocol": "TCP", "src_ip": "100.112.146.63", "src_port": 40986, "dst_ip": ATTACKER, "dst_port": 4444,
            "status": "ESTABLISHED", "direction": "outbound", "direction_basis": "no_local_listener",
            "attribution": "inode_verified", "observed_at": iso(90), "first_seen": iso(67), "pid": 154107,
            "holders": [{"pid": 154107, "parent_pid": 1, "process_start_time": PAYLOAD["process_start_time"],
                         "process_name": "python3", "exe_path": "/usr/bin/python3.13",
                         "cmdline": PAYLOAD["cmdline"], "uid": 0, "euid": 0, "socket_stdio": True, "ancestry": []}]}
    await send(factory, agent_ws._handle_telemetry_risk, {"network_connections": [conn], "process_list": []})

    incident, = await chain_incidents(factory)  # same incident, escalated — not a new one
    assert incident.id == first_id
    assert incident.severity == IncidentSeverity.CRITICAL and incident.risk_score >= 90
    assert incident.title.startswith("Web Application Compromise")
    chain = incident.detection_evidence["chain"]
    statuses = {c["id"]: c["status"] for c in chain["conditions"]}
    assert statuses == {"auth_bypass": "OBSERVED", "suspicious_upload": "OBSERVED", "command_injection": "OBSERVED",
                        "web_spawned_shell": "OBSERVED", "uploaded_file_execution": "CORRELATED",
                        "outbound_connection": "OBSERVED", "privileged_execution": "OBSERVED"}
    for item in chain["conditions"]:
        assert item["evidence_ids"] and item["contribution"] == item["weight"]
    assert chain["score_breakdown"]["sum_of_weights"] == sum(web_compromise.WEIGHTS.values())
    assert [p["pid"] for p in chain["process_tree"]] == [153380, 154105, 154107]
    assert chain["network"][0]["dst"] == f"{ATTACKER}:4444" and chain["network"][0]["socket_stdio"] is True
    assert chain["source_ips"] == [ATTACKER]
    assert "1450d62b30884258bddd134d4a0cd040" in chain["request_ids"]
    upload_exec = condition(incident, "uploaded_file_execution")
    assert "chưa so sánh hash" in upload_exec["detail"]

    # Replaying identical evidence does not touch the incident again.
    before = incident.updated_at
    async with factory() as db:
        await web_compromise.correlate(db, AGENT)
        await db.commit()
    incident, = await chain_incidents(factory)
    assert incident.updated_at == before

    detail = client.get(f"/api/v1/incidents/{incident.id}")
    assert detail.status_code == 200


@pytest.mark.asyncio
async def test_connection_from_unrelated_process_is_not_attributed(lab):
    _, factory = lab
    await send(factory, agent_ws._handle_web_access_log, PING)
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": SH["process_start_time"], **SH, "parent": WEB}]})
    other = {"protocol": "TCP", "src_ip": "172.31.32.238", "src_port": 37254, "dst_ip": "104.21.77.59", "dst_port": 443,
             "status": "ESTABLISHED", "direction": "outbound", "attribution": "inode_verified", "observed_at": iso(90),
             "holders": [{"pid": 153307, "parent_pid": 1, "process_start_time": T0 - 400, "process_name": "python",
                          "exe_path": "/usr/bin/python3.13", "cmdline": "python -u /opt/larp-agent/agent.py",
                          "socket_stdio": False}]}
    await send(factory, agent_ws._handle_telemetry_risk, {"network_connections": [other], "process_list": []})
    incident, = await chain_incidents(factory)
    assert condition(incident, "outbound_connection")["status"] == "NOT_OBSERVED"
    assert incident.severity == IncidentSeverity.HIGH


def test_score_comes_only_from_the_rule():
    source = (web_compromise.__file__ and open(web_compromise.__file__).read())
    assert "ai_" not in source.split("import")[0] and "ollama" not in source.lower()


@pytest.mark.asyncio
async def test_old_web_app_request_is_linked_as_inferred_and_cross_linked(lab):
    """Web app without child-PID telemetry: the /ping 500 is linked INFERRED, never scored or used as an IP target."""
    _, factory = lab
    legacy_ping = {k: v for k, v in web_log("e" * 32, "GET", "/ping", 500, 77).items()
                   if k not in ("process_pid", "parent_pid", "event_id", "session_ref")}
    await send(factory, agent_ws._handle_web_access_log, legacy_ping)  # per-request incident (automated HTTP)
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": SH["process_start_time"], **SH, "parent": WEB},
        {"event": "exec", "observed_at": PAYLOAD["process_start_time"], **PAYLOAD, "parent": SH}]})
    chain, = await chain_incidents(factory)
    doc = chain.detection_evidence["chain"]
    inferred, = doc["inferred_requests"]
    assert inferred["link"] == "INFERRED" and inferred["path"] == "/ping" and inferred["shell_pid"] == 154105
    assert doc["source_ips"] == []  # an inferred request never selects an IP to block
    assert condition(chain, "command_injection")["status"] == "NOT_OBSERVED"
    async with factory() as db:
        http = [i for i in (await db.scalars(select(Incident))).all()
                if (i.detection_evidence or {}).get("rule_id") == "automated_http_activity"]
    assert http and http[0].detection_evidence["correlated_chain"]["incident_id"] == chain.id
    assert http[0].detection_evidence["correlated_chain"]["link"] == "INFERRED"
    assert http[0].severity == IncidentSeverity.MEDIUM  # its own severity is untouched
