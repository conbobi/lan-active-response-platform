"""Summarize what one source did against a web service, from stored access and auth records.

A scanner (nmap -sV -sC, nikto, gobuster ...) sends dozens of requests to different paths within
seconds. Each request alone is only "an automated client"; together they are reconnaissance of the
service. This module rebuilds that picture from ``web_access_logs`` (and successful logins from
``auth_events``) so one incident describes the whole activity. Nothing here is inferred from text:
every count comes from a stored row, and the response headers a scanner reads (Server banner,
version) are not logged, so they are reported as unknown rather than guessed.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import select

from app.core.agent_health import as_utc
from app.models.auth_event import AuthEvent
from app.models.web_access_log import WebAccessLog
from app.services.detection.behavior_evidence import SQLI_TOOL_UA, TOOL_UA

SCAN_MIN_PATHS = 5          # distinct paths from one source, with a scanner User-Agent, in one activity window
LEAD_SECONDS = 10           # service probes (no User-Agent) that precede the first tool-tagged request
MAX_ROWS = 2000
MAX_EVENT_IDS = 64          # http_investigation accepts at most 64 correlated request ids
SAMPLE = 15


def _port(host: str | None):
    if not host or ":" not in host:
        return None
    tail = host.rsplit(":", 1)[1]
    return int(tail) if tail.isdigit() and 0 < int(tail) <= 65535 else None


def _tool(user_agent: str | None):
    ua = user_agent or ""
    match = SQLI_TOOL_UA.search(ua) or TOOL_UA.search(ua)
    return match[1].lower() if match else None


async def source_activity(session, agent_id: str, source_ip: str, start: datetime, end: datetime) -> dict | None:
    """Requests from ``source_ip`` to this agent's web service between ``start`` and ``end``."""
    start, end = as_utc(start), as_utc(end)
    if not source_ip or start is None or end is None:
        return None
    rows = (await session.scalars(
        select(WebAccessLog).where(
            WebAccessLog.agent_id == agent_id, WebAccessLog.src_ip == source_ip,
            WebAccessLog.timestamp >= start - timedelta(seconds=LEAD_SECONDS), WebAccessLog.timestamp <= end,
        ).order_by(WebAccessLog.timestamp, WebAccessLog.id).limit(MAX_ROWS)
    )).all()
    if not rows:
        return None
    tools = Counter()
    methods = Counter()
    statuses = Counter()
    first_seen: dict[str, datetime] = {}
    answered: dict[tuple, int] = {}
    missing: list[str] = []
    ports = set()
    tool_rows = 0
    for row in rows:
        tool = _tool(row.user_agent)
        if tool:
            tools[tool] += 1
            tool_rows += 1
        methods[row.method] += 1
        statuses[str(row.status_code)] += 1
        first_seen.setdefault(row.path, as_utc(row.timestamp))
        if 200 <= row.status_code < 400:
            key = (row.method, row.path, row.status_code)
            answered[key] = answered.get(key, 0) + 1
        elif row.status_code == 404 and row.path not in missing:
            missing.append(row.path)
        port = _port(row.host)
        if port:
            ports.add(port)
    first, last = as_utc(rows[0].timestamp), as_utc(rows[-1].timestamp)
    paths = sorted(first_seen, key=first_seen.get)
    logins = (await session.execute(
        select(AuthEvent.username, AuthEvent.service, AuthEvent.timestamp).where(
            AuthEvent.agent_id == agent_id, AuthEvent.source_ip == source_ip, AuthEvent.status == "success",
            AuthEvent.timestamp >= first - timedelta(hours=24),
        ).order_by(AuthEvent.timestamp.desc()).limit(20)
    )).all()
    successful = {}
    for username, service, stamp in logins:
        successful.setdefault((service, username), as_utc(stamp).isoformat())
    return {
        "request_count": len(rows),
        "tool_request_count": tool_rows,
        "untagged_request_count": len(rows) - tool_rows,
        "tools": [name for name, _ in tools.most_common()],
        "methods": dict(methods.most_common()),
        "status_counts": dict(sorted(statuses.items())),
        "distinct_path_count": len(paths),
        "sample_paths": paths[:SAMPLE],
        "not_found_paths": missing[:SAMPLE],
        "not_found_path_count": len(missing),
        "answered": [
            {"method": method, "path": path, "http_status": status, "count": count}
            for (method, path, status), count in sorted(answered.items(), key=lambda item: -item[1])[:SAMPLE]
        ],
        "target_ports": sorted(ports),
        "first_request_at": first.isoformat(),
        "last_request_at": last.isoformat(),
        "duration_seconds": round((last - first).total_seconds(), 1),
        "is_service_scan": tool_rows > 0 and len(paths) >= SCAN_MIN_PATHS,
        "scan_threshold_paths": SCAN_MIN_PATHS,
        "successful_logins_from_source": [
            {"service": service, "username": username, "last_success_at": stamp}
            for (service, username), stamp in successful.items()
        ],
        "response_headers_recorded": False,
        "event_ids": [row.id for row in rows][-MAX_EVENT_IDS:],
    }


def scan_title(summary: dict, source_ip: str, agent_id: str, score: float) -> str:
    tools = ", ".join(summary.get("tools") or []) or "automated client"
    ports = summary.get("target_ports") or []
    where = f" to port {', '.join(map(str, ports))}" if ports else ""
    return f"Web service scan ({tools}) from {source_ip}{where} on Agent '{agent_id}' (Score: {score})"
