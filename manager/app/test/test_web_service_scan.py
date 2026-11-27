"""nmap -sV -sC against the lab web service: one scan is one incident that describes the whole scan.

The request sequence mirrors the access log recorded on 2026-11-27 06:36 (paths, methods, status codes,
the probes without a User-Agent). Addresses are documentation ranges; fixture data only.
"""
import time
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.incident import Incident
from app.services.ai.ai_triage_service import _analysis_fields
from app.services.ai.alert_context_projector import build_alert_context
from app.services.ai.triage_schema import behavior_verdict
from app.services.detection.behavior_evidence import technique_for
from app.websocket import agent_ws
from test_http_response_assist import lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT

SCANNER = "198.51.100.23"
NSE = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
NMAP_RUN = [  # (method, path, status, user agent)
    ("GET", "/", 302, ""), ("POST", "/sdk", 404, NSE), ("GET", "/tasktracker.jsp", 404, NSE),
    ("GET", "/flumemaster.jsp", 404, NSE), ("GET", "/", 302, NSE), ("GET", "/jobtracker.jsp", 404, NSE),
    ("GET", "/rs-status", 404, NSE), ("GET", "/robots.txt", 404, NSE), ("GET", "/browseDirectory.jsp", 404, NSE),
    ("GET", "/master.jsp", 404, NSE), ("OPTIONS", "/", 200, NSE), ("GET", "/status.jsp", 404, NSE),
    ("GET", "/.git/HEAD", 404, NSE), ("POST", "/", 405, NSE), ("GET", "/nmaplowercheck1795761378", 404, NSE),
    ("GET", "/dfshealth.jsp", 404, NSE), ("GET", "/login", 200, NSE), ("GET", "/HNAP1", 404, NSE),
    ("GET", "/evox/about", 404, NSE), ("GET", "/favicon.ico", 404, NSE), ("OPTIONS", "/", 200, NSE),
    ("GET", "/", 302, ""),
]


async def send_log(factory, method, path, status, ua, stamp, source=SCANNER):
    request_id = uuid.uuid4().hex
    async with factory() as db:
        await agent_ws._handle_web_access_log(AGENT, {"wait_ack": False, "payload": {
            "agent_id": AGENT, "client_ip": source, "method": method, "path": path, "status_code": status,
            "user_agent": ua, "request_id": request_id, "timestamp": datetime.fromtimestamp(stamp, timezone.utc).isoformat(),
            "service": "flask_web", "host": "192.0.2.1:5000"}}, db)
        await db.commit()


async def incidents_from(factory, source):
    async with factory() as db:
        rows = (await db.scalars(select(Incident))).all()
    return [i for i in rows if ((i.detection_evidence or {}).get("behavior") or {}).get("source_ip") == source]


@pytest.mark.asyncio
async def test_one_nmap_run_is_one_scan_incident_with_the_whole_activity(lab):
    _, factory = lab
    async with factory() as db:  # the same source logged in successfully earlier
        await agent_ws._handle_auth_event(AGENT, {"wait_ack": False, "payload": {"agent_id": AGENT, "events": [{
            "service": "flask_web", "source_ip": SCANNER, "status": "success", "username": "admin", "count": 1,
            "timestamp": datetime.fromtimestamp(time.time() - 1800, timezone.utc).isoformat()}]}}, db)
        await db.commit()
    start = time.time() - 30
    for index, (method, path, status, ua) in enumerate(NMAP_RUN):
        await send_log(factory, method, path, status, ua, start + index * 0.35)

    incident, = await incidents_from(factory, SCANNER)  # was one incident per probed path
    behavior = incident.detection_evidence["behavior"]
    scan = behavior["activity_summary"]
    assert incident.title.startswith(f"Web service scan (nmap) from {SCANNER} to port 5000")
    # The summary is refreshed by tool-tagged requests: the leading probe without a User-Agent is inside the
    # look-back window, the trailing one arrives after the last refresh and is not counted.
    counted = len(NMAP_RUN) - 1
    assert scan["request_count"] == counted and scan["is_service_scan"] is True
    assert scan["tool_request_count"] == len(NMAP_RUN) - 2 and scan["untagged_request_count"] == 1
    assert scan["distinct_path_count"] == len({path for _, path, _, _ in NMAP_RUN})
    assert scan["not_found_path_count"] == len({p for _, p, s, _ in NMAP_RUN if s == 404})
    assert {"method": "GET", "path": "/login", "http_status": 200, "count": 1} in scan["answered"]
    assert scan["successful_logins_from_source"][0]["username"] == "admin"
    assert scan["response_headers_recorded"] is False
    assert len(behavior["source_event_ids"]) == counted
    assert technique_for(behavior) == "T1595"

    context = build_alert_context(incident)
    verdict = behavior_verdict(context)
    assert [t["id"] for t in verdict.techniques] == ["T1595"] and verdict.confidence == 0.80
    summary = _analysis_fields(context, verdict, "queue_saturated", "v")["summary"]
    assert f"**{counted} request**" in summary and "Trinh sát dịch vụ web" in summary
    assert "`GET /login` → 200" in summary and "đăng nhập **thành công** tài khoản `admin`" in summary
    assert "header phản hồi" in summary  # the banner nmap read is not in the log: said, not guessed
    for unrelated in ("blind boolean", "câu truy vấn SQL", "request body của endpoint"):
        assert unrelated not in summary


@pytest.mark.asyncio
async def test_a_single_automated_request_is_not_called_a_scan(lab):
    _, factory = lab
    await send_log(factory, "GET", "/", 302, "curl/8.14.1", time.time() - 5, source="198.51.100.24")
    incident, = await incidents_from(factory, "198.51.100.24")
    behavior = incident.detection_evidence["behavior"]
    assert not incident.title.startswith("Web service scan")
    assert behavior["activity_summary"]["is_service_scan"] is False
    assert technique_for(behavior) is None
    assert behavior_verdict(build_alert_context(incident)).confidence == 0.50
