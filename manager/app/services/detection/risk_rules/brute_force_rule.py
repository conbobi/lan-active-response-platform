from collections import defaultdict
from ipaddress import ip_address
from typing import Any, Dict, Tuple

from app.repositories.auth_event_repository import AuthEventRepository
from app.services.detection.risk_rules.base import RiskRule


def normalize_auth_event(event: dict) -> dict | None:
    status = str(event.get("status") or "").strip().lower()
    if not status and isinstance(event.get("success"), bool):
        status = "success" if event["success"] else "failed"
    if status not in {"failed", "success"}:
        return None

    try:
        count = int(event.get("count", 1))
    except (TypeError, ValueError, OverflowError):
        return None
    if not 1 <= count <= 2_147_483_647:
        return None

    try:
        parsed_ip = ip_address(str(event.get("source_ip") or "").strip())
        source = str(getattr(parsed_ip, "ipv4_mapped", None) or parsed_ip)
    except ValueError:
        source = "unknown"

    service = str(event.get("service") or "ssh").strip().lower()[:32] or "ssh"
    return {
        "service": "ssh" if service == "sshd" else service,
        "source_ip": source,
        "username": (str(event.get("username") or "").strip() or "unknown")[:64],
        "status": status,
        "count": count,
        "auth_method": str(event.get("auth_method") or "").strip().lower(),
    }


class BruteForceRule(RiskRule):
    """Correlate authentication failures and subsequent logins within each service."""

    rule_id = "brute_force"
    name = "Brute Force Authentication Detection"
    description = "Detects targeted or distributed brute force authentication attempts and credential stuffing."
    enabled = True
    weight = 1.0
    base_score = 30.0
    category = "identity"
    config = {"threshold": 5, "critical_threshold": 15, "window_seconds": 60}

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        threshold = max(1, int(self.config.get("threshold", 5)))
        critical_threshold = max(threshold, int(self.config.get("critical_threshold", 15)))
        window_seconds = max(1, int(self.config.get("window_seconds", 60)))

        events = []
        for raw_event in telemetry.get("auth_events") or []:
            event = normalize_auth_event(raw_event) if isinstance(raw_event, dict) else None
            if event and event["source_ip"] != "unknown":
                events.append(event)

        if not events:
            # The risk-evaluate API also accepts an aggregate count without identity.
            count = int(telemetry.get("failed_login_attempts") or 0)
            if count >= threshold:
                return min(50.0, self.base_score), f"{count} failed logins reported without source attribution"
            return 0.0, ""

        by_source = defaultdict(int)
        by_account = defaultdict(int)
        by_user = defaultdict(int)
        user_sources = defaultdict(set)
        history_before = context.get("auth_history_before")
        if history_before is not None:
            history = await AuthEventRepository(context["session"]).get_failed_attempt_groups(
                context["agent_id"], history_before, window_seconds, {event["service"] for event in events}
            )
            for service, source, user, count in history:
                if source == "unknown" or count <= 0:
                    continue
                by_source[service, source] += count
                if user != "unknown":
                    by_account[service, source, user] += count
                    by_user[service, user] += count
                    user_sources[service, user].add(source)

        best_score, reason = 0.0, ""
        for event in events:
            service, source, user = event["service"], event["source_ip"], event["username"]
            source_key = (service, source)
            account_key = (service, source, user)
            user_key = (service, user)
            score, detail = 0.0, ""

            if event["status"] == "success":
                prior_failures = by_account[account_key]
                if prior_failures >= threshold and event["auth_method"] != "publickey":
                    score = 85.0
                    detail = (
                        f"{service} login for '{user}' from {source} after {prior_failures} "
                        "failed attempts for the same account and source"
                    )
            else:
                count = event["count"]
                by_source[source_key] += count
                if user != "unknown":
                    by_account[account_key] += count
                    by_user[user_key] += count
                    user_sources[user_key].add(source)

                source_total = by_source[source_key]
                user_total = by_user[user_key]
                source_count = len(user_sources[user_key])
                if source_total >= critical_threshold:
                    score = 75.0
                    detail = f"Brute force on {service} from {source}: {source_total} failed logins"
                elif user_total >= threshold and source_count >= 3:
                    score = 65.0
                    detail = f"Distributed brute force on {service} account '{user}': {user_total} failed logins from {source_count} sources"
                elif source_total >= threshold:
                    score = 55.0
                    detail = f"Brute force on {service} from {source}: {source_total} failed logins"

            if score > best_score:
                best_score, reason = score, detail

        return best_score * self.base_score / 30.0, reason
