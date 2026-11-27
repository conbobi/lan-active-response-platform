"""Incident containment end to end: evidence → inspect → quarantine (approval) → verify → restore; verified
process stop; timeouts; offline Agent; RBAC; AI never creates actions; deterministic chain report.

File operations run the real Agent module (agent/file_containment.py) inside a temporary tree.
"""
import hashlib
import importlib.util
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, select, update

from app.core.config import NetworkOperator, settings
from app.models.command import Command
from app.models.containment import ContainmentAction
from app.models.incident import Incident
from app.services.detection import web_compromise
from app.services.response import containment as ct
from app.websocket import agent_ws
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT, digest, header

AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"
OPERATOR_TOKEN = "operator-token-for-containment-tests"
OPERATOR = header(OPERATOR_TOKEN)
API = "/api/v1/containment"
BODY = b"#!/usr/bin/env python3\nprint('lab payload')\n"


def agent_module(name):
    sys.path.insert(0, str(AGENT_DIR))
    try:
        spec = importlib.util.spec_from_file_location(f"larp_agent_{name}", AGENT_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(AGENT_DIR))


fc = agent_module("file_containment")


@pytest.fixture
def env(lab, monkeypatch, tmp_path):
    client, factory = lab
    operators = dict(settings.NETWORK_OPERATORS)
    operators["op"] = NetworkOperator(role="operator", agents={AGENT}, token_sha256=digest(OPERATOR_TOKEN))
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", operators)
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    payload = uploads / "backdoor.py"
    payload.write_bytes(BODY)
    monkeypatch.setenv("LARP_QUARANTINE_ALLOWED_ROOTS", str(uploads))
    monkeypatch.setenv("LARP_QUARANTINE_DIR", str(tmp_path / "store"))
    state = {"online": True}
    monkeypatch.setattr(ct, "online", lambda agent_id: state["online"])
    ct.record_capabilities(AGENT, ["inspect_file", "quarantine_file", "restore_file", "kill_process_tree_verified", "block_ip"])
    yield client, factory, state, payload
    ct.CAPABILITIES.pop(AGENT, None)


T0 = time.time() - 300


def proc(pid, ppid, name, exe, cmdline, start):
    return {"pid": pid, "parent_pid": ppid, "process_start_time": round(T0 + start, 2), "name": name, "exe": exe,
            "cmdline": cmdline, "uid": 0, "euid": 0}


async def send(factory, handler, payload):
    async with factory() as db:
        await handler(AGENT, {"payload": {"agent_id": AGENT, **payload}, "wait_ack": False}, db)
        await db.commit()


async def chain_incident(factory, payload_path, *, euid=0):
    web = proc(5000, 1, "python", "/usr/bin/python3.13", "python -u /srv/vulnerable_web/app.py", -600)
    sh = proc(5001, 5000, "sh", "/usr/bin/dash", f"/bin/sh -c ping -c 1 127.0.0.1;python3 {payload_path}", 0)
    py = proc(5002, 5001, "python3", "/usr/bin/python3.13", f"python3 {payload_path}", 0.05)
    for p in (sh, py):
        p["euid"] = euid
    await send(factory, agent_ws._handle_process_event, {"available": True, "events": [
        {"event": "exec", "observed_at": sh["process_start_time"], **sh, "parent": web},
        {"event": "exec", "observed_at": py["process_start_time"], **py, "parent": sh}]})
    orphan = {**py, "parent_pid": 1}  # the shell was killed by the web app's timeout
    await send(factory, agent_ws._handle_process_list, {"processes": [web, orphan], "activity_sample": {"complete": True}})
    conn = {"protocol": "TCP", "src_ip": "100.112.146.63", "src_port": 40986, "dst_ip": "100.67.222.3", "dst_port": 4444,
            "status": "ESTABLISHED", "direction": "outbound", "attribution": "inode_verified",
            "observed_at": datetime.now(timezone.utc).isoformat(), "first_seen": datetime.now(timezone.utc).isoformat(),
            "holders": [{"pid": 5002, "parent_pid": 1, "process_start_time": py["process_start_time"], "process_name": "python3",
                         "exe_path": "/usr/bin/python3.13", "cmdline": py["cmdline"], "socket_stdio": True, "euid": euid}]}
    await send(factory, agent_ws._handle_telemetry_risk, {"network_connections": [conn], "process_list": []})
    async with factory() as db:
        rows = (await db.scalars(select(Incident))).all()
    incident, = [i for i in rows if (i.detection_evidence or {}).get("rule_id") == web_compromise.RULE_ID]
    return incident, py


async def run_agent(factory, *, kill_ok=True):
    """Execute the newest dispatched containment command like the Agent and deliver its COMMAND_ACK."""
    async with factory() as db:
        cmd = (await db.scalars(select(Command).where(Command.payload.is_not(None)).order_by(Command.created_at.desc()))).first()
    p = cmd.payload
    if cmd.action == "inspect_file":
        receipt = fc.inspect(p["path"])
        ack = {"status": receipt["status"], "receipt": receipt}
    elif cmd.action == "quarantine_file":
        receipt = fc.quarantine(p["path"], p["sha256"], p["quarantine_id"])
        ack = {"status": receipt["status"], "receipt": receipt}
    elif cmd.action == "restore_file":
        receipt = fc.restore(p["quarantine_id"], p["sha256"])
        ack = {"status": receipt["status"], "receipt": receipt}
    else:
        ack = ({"status": "success", "validation": "validated", "killed_pids": [p["pid"]]} if kill_ok
               else {"status": "failed", "validation": "rejected", "killed_pids": [], "error_message": "Target process identity changed"})
    async with factory() as db:
        await agent_ws._handle_command_ack(AGENT, {"payload": {"command_id": cmd.id, **ack}}, db)
        await db.commit()
    return cmd


def overview(client, incident_id, headers=ANALYST):
    return client.get(f"{API}/incidents/{incident_id}/overview", headers=headers).json()


def act(client, incident_id, kind, target, headers=OPERATOR, reason="Điều tra backdoor từ chuỗi tấn công"):
    return client.post(f"{API}/incidents/{incident_id}/actions", headers=headers,
                       json={"kind": kind, "target": target, "reason": reason})


@pytest.mark.asyncio
async def test_overview_shows_correlated_process_file_and_connection(env):
    client, factory, _, payload = env
    incident, py = await chain_incident(factory, payload)
    view = overview(client, incident.id)
    assert view["is_chain"] and view["severity"] == "critical"
    stages = {s["id"]: s["status"] for s in view["stages"]}
    assert stages["outbound_connection"] == "OBSERVED" and stages["privileged_execution"] == "OBSERVED"
    payload_proc = next(p for p in view["processes"] if p["pid"] == 5002)
    assert payload_proc["live"]["state"] == "RUNNING" and payload_proc["holds_connection"] and payload_proc["euid"] == 0
    assert view["network"][0]["dst"] == "100.67.222.3:4444" and view["network"][0]["live"]["state"] == "ESTABLISHED"
    file_entry, = view["files"]
    assert file_entry["path"] == str(payload) and file_entry["state"] == "EXECUTION_OBSERVED" and file_entry["sha256"] is None
    assert all(view["capabilities"][k] for k in ("inspect_file", "quarantine_file", "terminate_process", "block_ip"))


@pytest.mark.asyncio
async def test_inspect_then_quarantine_with_approval_then_restore(env):
    client, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload)
    path = str(payload)
    early = act(client, incident.id, "quarantine_file", {"path": path})
    assert early.status_code == 409 and "SHA-256" in early.json()["detail"]  # evidence first
    assert act(client, incident.id, "inspect_file", {"path": path}, headers=ANALYST).status_code == 403
    assert act(client, incident.id, "inspect_file", {"path": "/etc/passwd"}).status_code == 422  # not in evidence
    inspected = act(client, incident.id, "inspect_file", {"path": path}).json()
    assert inspected["status"] == "DISPATCHED"  # read-only: no approval
    await run_agent(factory)
    view = overview(client, incident.id)
    assert view["files"][0]["sha256"] == hashlib.sha256(BODY).hexdigest()

    requested = act(client, incident.id, "quarantine_file", {"path": path}).json()
    assert requested["status"] == "PENDING_APPROVAL" and payload.exists()
    action_id = requested["action_id"]
    assert client.post(f"{API}/actions/{action_id}/approve", headers=OPERATOR, json={}).status_code == 403
    assert client.post(f"{API}/actions/{action_id}/approve", headers=ADMIN, json={}).json()["status"] == "DISPATCHED"
    assert payload.exists()  # dispatched ≠ done
    await run_agent(factory)
    view = overview(client, incident.id)
    quarantine = next(a for a in view["actions"] if a["id"] == action_id)
    assert quarantine["status"] == "VERIFIED" and quarantine["effect"] == "QUARANTINED" and quarantine["approved_by"] == "admin"
    assert quarantine["verification"]["original_absent"] and quarantine["verification"]["stored_hash_verified"]
    assert not payload.exists() and view["files"][0]["state"] == "QUARANTINED"
    # Quarantine does not stop the running payload: shown separately.
    assert next(p for p in view["processes"] if p["pid"] == 5002)["live"]["state"] == "RUNNING"

    restore = client.post(f"{API}/actions/{action_id}/restore", headers=OPERATOR, json={"reason": "Cần đối chiếu tại chỗ"}).json()
    assert restore["status"] == "PENDING_APPROVAL" and not payload.exists()
    client.post(f"{API}/actions/{restore['action_id']}/approve", headers=ADMIN, json={})
    await run_agent(factory)
    assert payload.read_bytes() == BODY
    view = overview(client, incident.id)
    assert next(a for a in view["actions"] if a["id"] == action_id)["status"] == "ROLLED_BACK"
    assert next(a for a in view["actions"] if a["id"] == restore["action_id"])["effect"] == "RESTORED"
    assert [h["event"] for h in next(a for a in view["actions"] if a["id"] == action_id)["history"]][:3] == [
        "requested", "approved", "dispatched"]


@pytest.mark.asyncio
async def test_verified_process_stop_uses_current_parent_and_reports_failures(env):
    client, factory, _, payload = env
    incident, py = await chain_incident(factory, payload)
    target = {"pid": 5002, "process_start_time": py["process_start_time"]}
    assert act(client, incident.id, "terminate_process", {"pid": 5000, "process_start_time": round(T0 - 600, 2)}).status_code == 422
    assert act(client, incident.id, "terminate_process", {**target, "process_start_time": 1.0}).status_code == 422  # PID reuse
    action_id = act(client, incident.id, "terminate_process", target).json()["action_id"]
    client.post(f"{API}/actions/{action_id}/approve", headers=ADMIN, json={})
    cmd = await run_agent(factory, kill_ok=False)
    assert cmd.action == "kill_process_tree_verified" and cmd.payload["parent_pid"] == 1  # current (orphan) parent
    assert cmd.payload["process_start_time"] == py["process_start_time"] and cmd.payload["confirmed"] is True
    failed = next(a for a in overview(client, incident.id)["actions"] if a["id"] == action_id)
    assert failed["status"] == "FAILED" and failed["effect"] == "NOT_APPLIED"
    retry = act(client, incident.id, "terminate_process", target).json()["action_id"]
    client.post(f"{API}/actions/{retry}/approve", headers=ADMIN, json={})
    await run_agent(factory)
    done = next(a for a in overview(client, incident.id)["actions"] if a["id"] == retry)
    assert done["status"] == "VERIFIED" and done["effect"] == "TERMINATED"


@pytest.mark.asyncio
async def test_timeout_is_unknown_and_late_receipt_resolves_it(env):
    client, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload)
    act(client, incident.id, "inspect_file", {"path": str(payload)})
    async with factory.begin() as db:
        await db.execute(update(ContainmentAction).values(dispatched_at=datetime.now(timezone.utc) - timedelta(minutes=5)))
    view = overview(client, incident.id)
    assert view["actions"][0]["status"] == "TIMEOUT" and view["actions"][0]["effect"] == "UNKNOWN"
    await run_agent(factory)  # the receipt arrives late: it ran after all
    assert overview(client, incident.id)["actions"][0]["status"] == "VERIFIED"


@pytest.mark.asyncio
async def test_offline_agent_and_missing_capability_never_produce_success(env):
    client, factory, state, payload = env
    incident, py = await chain_incident(factory, payload)
    action_id = act(client, incident.id, "terminate_process", {"pid": 5002, "process_start_time": py["process_start_time"]}).json()["action_id"]
    state["online"] = False
    response = client.post(f"{API}/actions/{action_id}/approve", headers=ADMIN, json={})
    assert response.status_code == 409 and "offline" in response.json()["detail"]
    assert next(a for a in overview(client, incident.id)["actions"] if a["id"] == action_id)["status"] == "PENDING_APPROVAL"
    ct.CAPABILITIES[AGENT] = {"items": {"inspect_file"}, "reported_at": "x"}
    assert act(client, incident.id, "quarantine_file", {"path": str(payload)}).status_code == 409
    assert overview(client, incident.id)["capabilities"]["quarantine_file"] is False
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(Command).where(Command.action == "kill_process_tree_verified")) == 0


@pytest.mark.asyncio
async def test_evidence_bundle_is_preserved_without_approval_and_survives_reload(env):
    client, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload)
    done = act(client, incident.id, "collect_process_evidence", {}).json()
    assert done["status"] == "VERIFIED"
    async with factory() as db:  # a new session (restart) reads the same history
        row = await db.get(ContainmentAction, done["action_id"])
        bundle = row.receipt["bundle"]
        assert row.receipt["sha256"] == hashlib.sha256(json.dumps(bundle, sort_keys=True, default=str).encode()).hexdigest()
        assert any(p["pid"] == 5002 for p in bundle["processes"])


@pytest.mark.asyncio
async def test_chain_report_is_evidence_based_and_labels_timeout(env):
    from app.services.ai.alert_context_projector import build_alert_context
    from app.services.ai.ai_triage_service import _analysis_fields, fallback_verdict
    client, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload)
    context = build_alert_context(incident)
    summary = _analysis_fields(context, fallback_verdict(context), "timeout", "v")["summary"]
    assert "KHÔNG phải phân tích AI" in summary and "PID `5002`" in summary and "100.67.222.3:4444" in summary
    assert "Quyền root: **có bằng chứng**" in summary and str(payload) in summary
    assert "/srv/vulnerable_web/app.py` — SHA" not in summary  # the web service is the victim, not a suspicious file
    # No request carried injection indicators, but the web-spawned shell command is chained: not "no evidence".
    gaps = summary.split("### Bằng chứng còn thiếu")[1]
    assert "Command injection: chưa có bằng chứng" not in gaps and "chứa ký tự nối lệnh" in gaps
    budget = _analysis_fields(context, fallback_verdict(context), "budget_exceeded", "v")["summary"]
    assert "KHÔNG phải phân tích AI" in budget and "budget_exceeded" not in budget


@pytest.mark.asyncio
async def test_no_root_claim_without_uid(env):
    from app.services.ai.alert_context_projector import build_alert_context
    from app.services.ai.ai_triage_service import _analysis_fields, fallback_verdict
    client, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload, euid=None)
    context = build_alert_context(incident)
    summary = _analysis_fields(context, fallback_verdict(context), "ok", "v")["summary"]
    assert "Quyền root: chưa chứng minh" in summary and "chưa kết luận được quyền root" in summary
    executed = summary.split("### Bằng chứng thực thi")[1].split("###")[0]
    assert "PID `5002`" in executed and "chưa có UID trong telemetry" in executed


@pytest.mark.asyncio
async def test_ai_and_cache_never_create_containment_actions(env):
    client, factory, _, payload = env
    incident, _ = await chain_incident(factory, payload)
    async with factory() as db:
        assert await db.scalar(select(func.count()).select_from(ContainmentAction)) == 0
        assert await db.scalar(select(func.count()).select_from(Command)) == 0
