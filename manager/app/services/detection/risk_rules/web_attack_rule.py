import re

from app.services.detection.behavior_evidence import (
    SQLI, SQLI_TOOL, SQLI_PROBE, SQLI_SUSPECTED, SQLI_CONFIRMED, AUTOMATED_HTTP, UNKNOWN,
    SQLI_TOOL_UA, TOOL_UA, address, http_fields, observed_time, stable_id,
)
from app.services.detection.risk_rules.base import RiskRule

RE_PATH_TRAVERSAL = re.compile(
    r'(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow|hosts)|/proc/self/|windows/win\.ini', re.I
)


def inspect_web_log(log, agent_id):
    http = http_fields(log)
    if not http.get("request_method") or not http.get("request_path"):
        return None
    ua = http.get("user_agent") or ""
    sqli_tool = SQLI_TOOL_UA.search(ua)
    tool = TOOL_UA.search(ua)
    payload = http.get("payload_indicators")
    # An access record alone cannot establish an application-side outcome.
    if payload:
        kind, score = SQLI_PROBE, 75.0
    elif sqli_tool:
        kind, score = SQLI_TOOL, 60.0
    elif tool:
        kind, score = AUTOMATED_HTTP, 55.0
    else:
        return None
    event_id = log.get("evidence_id")
    observed = observed_time(log.get("timestamp"))
    evidence = {
        **http, "evidence_id": stable_id("http_group_", agent_id, kind, event_id),
        "evidence_type": "http", "source": "web_access_logs",
        "source_event_ids": [event_id] if isinstance(event_id, str) else [],
        "agent_id": agent_id, "classification": kind, "service": log.get("service") or log.get("host") or "web",
        "source_ip": address(log.get("src_ip") or log.get("client_ip")),
        "first_attempt_at": observed.isoformat() if observed else None,
        "last_attempt_at": observed.isoformat() if observed else None,
        "time_basis": [log.get("timestamp_source") or ("log" if observed else "manager_receipt")],
    }
    tool_match = sqli_tool or tool
    if tool_match:
        evidence["automation_hint"] = tool_match[1].lower()
    if kind in (SQLI, SQLI_PROBE):
        evidence["exploitation_outcome"] = "undetermined"
    elif kind == SQLI_SUSPECTED:
        evidence["exploitation_outcome"] = "suspected"
    elif kind == SQLI_CONFIRMED:
        evidence["exploitation_outcome"] = "confirmed"
    elif kind == SQLI_TOOL:
        evidence["exploitation_outcome"] = "no_payload_in_request"
    return score, evidence


class WebAttackRule(RiskRule):
    """Detect Web probing and weak automation hints from observed requests."""

    rule_id = "web_attack"
    name = "Web Application Attack Detection (NDR)"
    description = "Detects SQL injection indicators, traversal patterns and scanner User-Agent hints."
    enabled = True
    weight = 1.0
    base_score = 40.0
    category = "network"

    async def evaluate(self, telemetry, context):
        logs = telemetry.get("web_logs") or ([telemetry["web_log"]] if isinstance(telemetry.get("web_log"), dict) else [])
        if not logs and ("path" in telemetry or "url" in telemetry):
            logs = [telemetry]
        findings = []
        traversal = False
        agent_id = context.get("agent_id")
        for log in logs:
            if not isinstance(log, dict):
                continue
            hit = inspect_web_log(log, agent_id)
            if hit:
                findings.append(hit)
            path = log.get("path")
            traversal |= isinstance(path, str) and bool(RE_PATH_TRAVERSAL.search(path))
        if findings:
            findings.sort(key=lambda item: item[0], reverse=True)
            context.setdefault("behavior_findings", {})[self.rule_id] = findings
            score, evidence = findings[0]
            reason = evidence["classification"]
            if evidence.get("automation_hint"):
                reason += " (" + evidence["automation_hint"] + ")"
            return score, reason
        if traversal:
            return 90.0, "HTTP path traversal pattern observed"
        return 0.0, ""
