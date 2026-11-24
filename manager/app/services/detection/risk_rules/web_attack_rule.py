import re

from app.services.detection.behavior_evidence import (
    SQLI, UNKNOWN, TOOL_UA, address, http_fields, observed_time, stable_id,
)
from app.services.detection.risk_rules.base import RiskRule

RE_PATH_TRAVERSAL = re.compile(
    r'(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow|hosts)|/proc/self/|windows/win\.ini', re.I
)


def inspect_web_log(log, agent_id):
    http = http_fields(log)
    if not http.get("request_method") or not http.get("request_path"):
        return None
    tool = TOOL_UA.search(http.get("user_agent") or "")
    if http.get("payload_indicators"):
        kind, score = SQLI, 75.0
    elif tool:
        kind, score = UNKNOWN, 55.0
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
    if tool:
        evidence["automation_hint"] = tool[1].lower()
    if kind == SQLI:
        evidence["exploitation_outcome"] = "undetermined"
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
