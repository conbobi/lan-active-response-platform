"""Task A: structured telemetry of the intentionally vulnerable lab web app (agent/vulnerable_web/app.py).

The vulnerabilities stay; these tests check only what the application records about them.
"""
import hashlib
import importlib
import io
import json
import logging
import sys
from pathlib import Path

import pytest

WEB_DIR = Path(__file__).resolve().parents[3] / "agent" / "vulnerable_web"


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    root = tmp_path_factory.mktemp("web")
    mp = pytest.MonkeyPatch()
    mp.setenv("VULNERABLE_WEB_DIR", str(root))
    mp.setenv("VULNERABLE_DB_PATH", str(root / "users.db"))
    mp.delenv("LARP_HTTP_LAB_STATE", raising=False)
    mp.syspath_prepend(str(WEB_DIR))
    for name in ("http_evidence", "response_guard"):
        sys.modules.pop(name, None)
    loggers = [logging.getLogger(n) for n in ("larp_web_auth", "larp_web_access")]
    saved = [list(lg.handlers) for lg in loggers]
    for lg in loggers:  # named loggers are global: drop handlers left by an earlier import
        lg.handlers.clear()
    import importlib.util
    spec = importlib.util.spec_from_file_location("larp_lab_web_app", WEB_DIR / "app.py")
    module = importlib.util.module_from_spec(spec)  # not "app": that name is the Manager package
    spec.loader.exec_module(module)
    uploads = root / "uploads"
    uploads.mkdir()
    mp.setattr(module, "UPLOAD_DIR", str(uploads))
    module.init_db()
    module.app.config["TESTING"] = True
    yield module, root, uploads
    mp.undo()
    for lg, handlers in zip(loggers, saved):
        for h in lg.handlers:
            h.close()
        lg.handlers[:] = handlers


def entries(root, name):
    return [json.loads(line) for line in (root / name).read_text().splitlines() if line.strip()]


def last(root, name, path):
    return [e for e in entries(root, name) if e.get("path") == path][-1]


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password},
                       environ_overrides={"REMOTE_ADDR": "198.51.100.7"})


def test_sqli_login_is_recorded_as_suspected_bypass_and_valid_login_is_not(web):
    module, root, _ = web
    client = module.app.test_client()
    assert login(client, "admin' OR '1'='1' --", "anything").status_code == 302
    bypass = last(root, "auth.log", "/login")
    assert bypass["auth_result"] == "success" and bypass["credential_match"] is False
    assert bypass["suspected_auth_bypass"] is True and bypass["username"] is None
    assert "sql_boolean_expression" in bypass["payload_indicators"]
    raw = (root / "auth.log").read_text()
    assert "anything" not in raw and "OR '1'='1'" not in raw  # no password, no raw payload

    valid = module.app.test_client()
    assert login(valid, "admin", "admin123").status_code == 302
    ok = last(root, "auth.log", "/login")
    assert ok["credential_match"] is True and ok["suspected_auth_bypass"] is False and ok["username"] == "admin"

    failed = module.app.test_client()
    login(failed, "admin", "wrong")
    bad = last(root, "auth.log", "/login")
    assert bad["auth_result"] == "failed" and bad["suspected_auth_bypass"] is False


def test_every_event_has_identity_process_and_session_link(web):
    module, root, _ = web
    client = module.app.test_client()
    login(client, "admin", "admin123")
    session_ref = last(root, "access.log", "/login")["session_ref"]
    client.get("/dashboard", environ_overrides={"REMOTE_ADDR": "198.51.100.7"})
    entry = last(root, "access.log", "/dashboard")
    assert len(entry["event_id"]) == 32 and entry["request_id"] != entry["event_id"]
    assert entry["process_pid"] > 0 and entry["parent_pid"] > 0
    assert entry["session_ref"] == session_ref  # later requests link back to the login
    assert "cookie" not in json.dumps(entry).lower()


def test_upload_records_what_was_stored_not_that_it_ran(web):
    module, root, uploads = web
    client = module.app.test_client()
    login(client, "admin", "admin123")
    body = b"#!/usr/bin/env python3\nprint('lab')\n"
    client.post("/upload", data={"file": (io.BytesIO(body), "backdoor.py")}, content_type="multipart/form-data")
    event = last(root, "access.log", "/upload")["app_event"]
    assert event["type"] == "file_upload" and event["stored"] is True
    assert event["upload_path"] == str(uploads / "backdoor.py")
    assert event["upload_size"] == len(body) and event["upload_sha256"] == hashlib.sha256(body).hexdigest()
    assert event["script_or_binary"] is True and event["outside_upload_dir"] is False
    assert "execution_result" not in event and "executed" not in json.dumps(event)


def test_ping_records_injection_indicators_child_pid_and_outcome(web):
    module, root, uploads = web
    client = module.app.test_client()
    login(client, "admin", "admin123")

    client.get("/ping", query_string={"ip": "127.0.0.1"})
    plain = last(root, "access.log", "/ping")["app_event"]
    assert plain["shell_indicators"] == [] and plain["execution_result"] == "completed"
    assert plain["child_pid"] > 0

    payload = f"127.0.0.1;python3 {uploads}/backdoor.py"
    client.get("/ping", query_string={"ip": payload})
    injected = last(root, "access.log", "/ping")["app_event"]
    assert injected["shell_indicators"] == ["shell_command_separator"]
    assert injected["referenced_upload_files"] == ["backdoor.py"]
    assert injected["parameter_sha256"] == hashlib.sha256(payload.encode()).hexdigest()
    assert payload not in (root / "access.log").read_text()  # the command itself is not logged


def test_ping_timeout_is_recorded_and_still_returns_500(web, monkeypatch):
    module, root, _ = web
    client = module.app.test_client()
    login(client, "admin", "admin123")
    real_popen = module.subprocess.Popen

    class Slow(real_popen):
        def communicate(self, input=None, timeout=None):
            if timeout is not None:
                raise module.subprocess.TimeoutExpired(self.args, timeout)
            return super().communicate(input)

    monkeypatch.setattr(module.subprocess, "Popen", Slow)
    module.app.config["TESTING"] = False  # real 500 handling, as in the lab
    try:
        response = client.get("/ping", query_string={"ip": "127.0.0.1;sleep 30"})
    finally:
        module.app.config["TESTING"] = True
    assert response.status_code == 500
    event = last(root, "access.log", "/ping")
    assert event["status_code"] == 500 and event["app_event"]["execution_result"] == "timeout"
    assert event["app_event"]["child_pid"] > 0


# ── Agent forwarding and Manager ingestion of the new fields ─────────────────────────────────
AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"


def load_agent_module(name, monkeypatch):
    import importlib.util
    monkeypatch.syspath_prepend(str(AGENT_DIR))
    spec = importlib.util.spec_from_file_location(f"larp_agent_{name}", AGENT_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PING_LINE = {
    "client_ip": "100.67.222.3", "ip_source": "remote_addr", "method": "GET", "path": "/ping", "status_code": 500,
    "user_agent": "curl/8.14.1", "request_id": "1450d62b30884258bddd134d4a0cd040",
    "timestamp": "2026-11-27T00:01:39.308223+00:00", "host": "100.112.146.63:5000", "service": "flask_web",
    "payload_indicators": [], "event_id": "a" * 32, "process_pid": 153380, "parent_pid": 1,
    "app_event": {"type": "shell_command", "parameter": "ip", "parameter_length": 41, "parameter_sha256": "b" * 64,
                  "shell_indicators": ["shell_command_separator", "bogus"], "referenced_upload_files": ["backdoor.py", "../x"],
                  "execution_result": "timeout", "child_pid": 154105, "child_spawned_at": 1795737688.8,
                  "duration_s": 10.01, "injected": "ignored"},
}


def test_agent_forwards_app_fields_and_reads_the_right_journal_unit(monkeypatch):
    monitor = load_agent_module("web_log_monitor", monkeypatch)
    parsed = monitor.WebLogMonitor.parse_raw_log_line(json.dumps(PING_LINE))
    assert parsed["event_id"] == "a" * 32 and parsed["process_pid"] == 153380
    assert parsed["app_event"]["child_pid"] == 154105 and "injected" not in parsed["app_event"]
    source = (AGENT_DIR / "web_log_monitor.py").read_text()
    assert '"-u", "vulnerable-web"' in source  # the systemd unit is vulnerable-web.service


def test_agent_forwards_application_auth_evidence(tmp_path, monkeypatch):
    auth = load_agent_module("auth_monitor", monkeypatch)
    log = tmp_path / "auth.log"
    monitor = auth.AuthMonitor(agent_id="aws-test")
    monkeypatch.setattr(monitor, "_get_active_files", lambda: [str(log)])
    log.write_text(json.dumps({
        "client_ip": "100.67.222.3", "method": "POST", "path": "/login", "status_code": 302,
        "request_id": "6ae03000ec1a4b73bc0d60da9543cc50", "timestamp": "2026-11-27T00:00:22.344930+00:00",
        "service": "flask_web", "payload_indicators": ["sql_boolean_expression"], "status": "success",
        "event_type": "WEB_AUTH_SUCCESS", "auth_result": "success", "credential_match": False,
        "suspected_auth_bypass": True, "username": None, "source_ip": "100.67.222.3", "http_status": 302}) + "\n")
    event = monitor.get_new_events()[0]
    assert event["credential_match"] is False and event["suspected_auth_bypass"] is True
    assert event["auth_result"] == "success"


@pytest.mark.asyncio
async def test_manager_stores_validated_app_observation(tmp_path):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from app.models.agent import Agent
    from app.models.base import Base
    from app.models.event import Event
    from app.models.web_access_log import WebAccessLog
    from app.websocket import agent_ws

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/m.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory.begin() as db:
        db.add(Agent(id="aws-test", hostname="aws-test", ip_address="10.0.0.1", mac_address="00:00:00:00:00:01"))
    async with factory() as db:
        await agent_ws._handle_web_access_log("aws-test", {"payload": {**PING_LINE, "agent_id": "aws-test"}}, db)
        await agent_ws._handle_auth_event("aws-test", {"wait_ack": False, "payload": {"agent_id": "aws-test", "events": [{
            "service": "flask_web", "source_ip": "100.67.222.3", "status": "success", "count": 1,
            "timestamp": "2026-11-27T00:00:22.344930+00:00", "event_id": "6ae03000ec1a4b73bc0d60da9543cc50",
            "request_id": "6ae03000ec1a4b73bc0d60da9543cc50", "method": "POST", "path": "/login", "http_status": 302,
            "payload_indicators": ["sql_boolean_expression"], "auth_result": "success",
            "credential_match": False, "suspected_auth_bypass": True}]}}, db)
        await db.commit()
    async with factory() as db:
        row = (await db.scalars(__import__("sqlalchemy").select(WebAccessLog))).one()
        auth = (await db.scalars(__import__("sqlalchemy").select(Event).where(Event.event_type == "AUTH_OBSERVATION"))).one()
    stored = json.loads(row.raw_message)
    assert stored["app_event_id"] == "a" * 32 and stored["process_pid"] == 153380
    command = stored["app_event"]
    assert command["shell_indicators"] == ["shell_command_separator"]  # unknown indicator dropped
    assert command["referenced_upload_files"] == ["backdoor.py"] and "injected" not in command
    assert command["execution_result"] == "timeout" and command["child_pid"] == 154105
    assert auth.details["suspected_auth_bypass"] is True and auth.details["credential_match"] is False
    await engine.dispose()
