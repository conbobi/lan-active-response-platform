from collections import defaultdict, deque
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models.web_access_log import WebAccessLog
from app.repositories.auth_event_repository import AuthEventRepository
from app.services.detection.behavior_evidence import (
    BRUTE_FORCE, REPEATED, SQLI, TOKEN, address, evidence_ids, http_fields, observed_time,
    signature_indicators, stable_id,
)
from app.services.detection.risk_rules.base import RiskRule


def normalize_auth_event(event: dict) -> dict | None:
    status = str(event.get("status") or "").lower().strip()
    if not status and isinstance(event.get("success"), bool):
        status = "success" if event["success"] else "failed"
    if status not in {"failed", "success", "error"}:
        return None
    try:
        count = int(event.get("count", 1))
    except (TypeError, ValueError, OverflowError):
        return None
    if not 1 <= count <= 2_147_483_647:
        return None
    service = str(event.get("service") or "ssh").lower().strip()
    service = service if TOKEN.fullmatch(service) and len(service) <= 32 else "unknown"
    username = event.get("username")
    http = http_fields(event)
    if service == "flask_web" or http:
        indicators = set(http.get("payload_indicators", [])) | signature_indicators(username)
        if indicators:
            http["payload_indicators"] = sorted(indicators)
            username = None
    observed = observed_time(event.get("timestamp"))
    method = event.get("auth_method")
    return {
        **http, "service": "ssh" if service == "sshd" else service,
        "source_ip": address(event.get("source_ip")) or "unknown",
        "username": username if isinstance(username, str) and TOKEN.fullmatch(username) else "unknown",
        "status": status, "count": count, "timestamp": observed,
        "timestamp_source": event.get("timestamp_source") if event.get("timestamp_source") in
        ("application", "log", "agent_receipt", "manager_receipt", "legacy_receipt") else
        ("log" if observed is not None else "manager_receipt"),
        "auth_method": method if method in ("password", "publickey") else None,
        "evidence_id": event.get("evidence_id") if isinstance(event.get("evidence_id"), str) else None,
        # Application-side authentication evidence (web app only); None when not reported.
        "auth_result": status if service == "flask_web" else None,
        "credential_match": event["credential_match"] if type(event.get("credential_match")) is bool else None,
        "suspected_auth_bypass": (event["suspected_auth_bypass"] if type(event.get("suspected_auth_bypass")) is bool
                                  else None),
    }


def _timed_credential(event):
    return (event["count"] == 1 and event["timestamp_source"] in {"log", "application"}
            and event["username"] != "unknown" and event["auth_method"] == "password")


def _burst(events, limit, seconds):
    window = deque()
    for event in events:
        now = event["timestamp"]
        while window and now - window[0] > timedelta(seconds=seconds):
            window.popleft()
        window.append(now)
        if len(window) >= limit and window[0] < now:
            return True
    return False


def _evidence(kind, events, window, agent_id, criteria=None):
    first, last = events[0], events[-1]
    source_ids = evidence_ids(events)
    fields = next((row for row in reversed(events) if row.get("payload_indicators")), last)
    account_names = {event["username"] for event in events if event["username"] != "unknown"}
    result = {
        "evidence_id": stable_id("auth_group_", agent_id, kind, first["service"], first["source_ip"], *sorted(source_ids)),
        "evidence_type": "authentication", "source": "auth_events", "source_event_ids": source_ids,
        "agent_id": agent_id, "classification": kind, "service": first["service"],
        "source_ip": first["source_ip"],
        "username": next(iter(account_names)) if len(account_names) == 1 else None,
        "account_count": len(account_names),
        "authentication_status": sorted({event["status"] for event in events}),
        "failed_attempts": sum(event["count"] for event in events if event["status"] == "failed"),
        "successful_attempts": sum(event["count"] for event in events if event["status"] == "success"),
        "error_attempts": sum(event["count"] for event in events if event["status"] == "error"),
        "first_attempt_at": first["timestamp"].isoformat(), "last_attempt_at": last["timestamp"].isoformat(),
        "detection_window_seconds": window,
        "time_basis": sorted({event["timestamp_source"] for event in events}),
        "payload_indicators": sorted({value for event in events for value in event.get("payload_indicators", [])}),
    }
    for key in ("request_id", "request_method", "request_path", "http_status", "user_agent", "http_event_id"):
        if fields.get(key) is not None:
            result[key] = fields[key]
    if kind == SQLI:
        result["indicator_source_event_ids"] = evidence_ids([event for event in events if event.get("payload_indicators")])
        result["indicator_event_count"] = len(result["indicator_source_event_ids"])
        result["exploitation_outcome"] = "undetermined"
    if criteria:
        result["brute_force_criteria"] = criteria
    return result


async def _attach_http(session, agent_id, events):
    candidates = {
        stable_id("wlog_", agent_id, item["request_id"]): item for item in events
        if item.get("request_id") and item.get("request_path")
    }
    if not candidates:
        return
    rows = await session.scalars(select(WebAccessLog).where(
        WebAccessLog.agent_id == agent_id, WebAccessLog.id.in_(candidates),
    ))
    for row in rows:
        item = candidates[row.id]
        recorded_at = observed_time(row.timestamp)
        try:
            metadata = json.loads(row.raw_message or "{}")
        except (TypeError, ValueError):
            continue
        if (isinstance(metadata, dict) and metadata.get("service") == item["service"]
                and row.src_ip == item["source_ip"] and row.method == item.get("request_method")
                and row.path == item["request_path"] and recorded_at is not None
                and abs(recorded_at - item["timestamp"]) <= timedelta(seconds=5)):
            item["http_event_id"] = row.id
            if row.status_code is not None and 100 <= row.status_code < 600:
                item["http_status"] = row.status_code


class BruteForceRule(RiskRule):
    """Publish the strongest supported auth finding per service/source cohort."""

    rule_id = "brute_force"  # Configuration key for existing installations.
    name = "Authentication Evidence"
    description = "Correlates repeated failures, credential attempts and observed web probes."
    enabled = True
    weight = 1.0
    base_score = 30.0
    category = "identity"
    config = {"threshold": 5, "critical_threshold": 15, "window_seconds": 60}

    async def evaluate(self, telemetry, context):
        threshold = max(1, int(self.config.get("threshold", 5)))
        critical = max(8, threshold, int(self.config.get("critical_threshold", 15)))
        window = min(3600, max(1, int(self.config.get("window_seconds", 60))))
        fallback = context.get("auth_history_before") or datetime.now(timezone.utc)
        current = []
        seen = set()
        for raw in telemetry.get("auth_events") or []:
            item = normalize_auth_event(raw) if isinstance(raw, dict) else None
            if item is None or item["source_ip"] == "unknown":
                continue
            key = item["evidence_id"]
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            item["timestamp"] = item["timestamp"] or fallback
            current.append(item)
        if not current:
            try:
                count = int(telemetry.get("failed_login_attempts") or 0)
            except (TypeError, ValueError, OverflowError):
                count = 0
            return (min(50.0, self.base_score), "Unattributed authentication failure count") if count >= threshold else (0.0, "")
        agent_id = context.get("agent_id")
        session = context.get("session")
        current.sort(key=lambda item: item["timestamp"])
        latest = {(event["service"], event["source_ip"]): event["timestamp"] for event in current}
        failing = {(event["service"], event["source_ip"]) for event in current if event["status"] == "failed"}
        history = []
        if session is not None and context.get("auth_history_before") is not None:
            history = await AuthEventRepository(session).get_attempt_window(
                agent_id, min(latest.values()) - timedelta(seconds=window),
                max(latest.values()), {key[0] for key in latest}, {key[1] for key in latest}, seen,
                {event["username"] for event in current if _timed_credential(event)},
            )
            await _attach_http(session, agent_id, current)
        groups = defaultdict(list)
        past = [item for raw in history if (item := normalize_auth_event(raw))]
        for item in [*past, *current]:
            key = item["service"], item["source_ip"]
            if key in latest and latest[key] - timedelta(seconds=window) <= item["timestamp"] <= latest[key]:
                groups[key].append(item)
        findings = []
        for key, events in groups.items():
            events.sort(key=lambda item: item["timestamp"])
            failures = sum(e["count"] for e in events if e["status"] == "failed")
            web_probe = any(
                row.get("payload_indicators") and (
                    key[0] == "flask_web" or (row.get("request_method") and row.get("request_path"))
                )
                for row in events
            )
            if web_probe:
                findings.append((75.0, _evidence(SQLI, events, window, agent_id)))
                continue
            if failures < threshold:
                continue
            accounts = defaultdict(list)
            for event in events:
                if _timed_credential(event):
                    accounts[event["username"]].append(event)
            matched = False
            for rows in accounts.values():
                attempts = [event for event in rows if event["status"] == "failed"]
                if _burst(attempts, critical, window) or _burst(attempts, max(8, threshold), 10):
                    score = 85.0 if any(event["status"] == "success" and event["timestamp"] > attempts[-1]["timestamp"] for event in rows) else 75.0
                    findings.append((score, _evidence(BRUTE_FORCE, rows, window, agent_id, "password_burst_same_account_source")))
                    matched = True
            if not matched and key in failing:
                findings.append((55.0, _evidence(REPEATED, events, window, agent_id)))
        # A shared target account can be targeted across sources. Exclude cohorts
        # with observed SQL syntax so their failures cannot inflate this pattern.
        probes = {
            (item["service"], item["source_ip"]) for item in [*past, *current] if item.get("payload_indicators")
        }
        target_times = {
            (item["service"], item["username"]): item["timestamp"] for item in current
            if item["status"] == "failed" and _timed_credential(item)
        }
        by_target = defaultdict(list)
        for item in [*past, *current]:
            target = (item["service"], item["username"])
            if (target in target_times and _timed_credential(item) and item["status"] == "failed"
                    and (item["service"], item["source_ip"]) not in probes
                    and target_times[target] - timedelta(seconds=window) <= item["timestamp"] <= target_times[target]):
                by_target[target].append(item)
        for rows in by_target.values():
            rows.sort(key=lambda item: item["timestamp"])
            sources = sorted({item["source_ip"] for item in rows})
            if len(sources) >= 3 and _burst(rows, critical, window):
                evidence = _evidence(BRUTE_FORCE, rows, window, agent_id, "distributed_password_burst_same_account")
                evidence.update(source_ip=None, source_ips=sources)
                findings.append((65.0, evidence))
        if not findings:
            return 0.0, ""
        findings.sort(key=lambda hit: hit[0], reverse=True)
        context.setdefault("behavior_findings", {})[self.rule_id] = findings
        score, best = findings[0]
        reason = f"{best['classification']} on {best['service']} from {best['source_ip']}: {best['failed_attempts']} recorded failures"
        return score * self.base_score / 30.0, reason
