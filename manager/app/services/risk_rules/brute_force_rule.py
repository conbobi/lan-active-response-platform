from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class BruteForceRule(RiskRule):
    """
    Risk rule detecting brute force authentication attacks (SSH / RDP / Local auth).
    Evaluates both batch auth_events in telemetry and database sliding window counters.
    """
    rule_id = "brute_force"
    name = "Brute Force Authentication Detection"
    description = "Detects multiple failed login attempts in a short timeframe or successful login following repeated failures."
    enabled = True
    weight = 1.0
    base_score = 30.0
    category = "identity"

    DEFAULT_CONFIG = {
        "threshold": 5,
        "critical_threshold": 15,
        "window_seconds": 60
    }

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        threshold = int(self.config.get("threshold", 5))
        critical_threshold = int(self.config.get("critical_threshold", 15))

        auth_events: List[Dict[str, Any]] = telemetry.get("auth_events", [])
        failed_count = int(telemetry.get("failed_login_attempts", 0))
        has_success_after_fail = False

        targeted_users = set()
        source_ips = set()

        # Parse telemetry auth_events
        for evt in auth_events:
            status = str(evt.get("status", "")).lower()
            cnt = int(evt.get("count", 1))
            u = evt.get("username")
            s_ip = evt.get("source_ip")
            if u:
                targeted_users.add(str(u))
            if s_ip and s_ip != "unknown":
                source_ips.add(str(s_ip))

            if status == "failed":
                failed_count += cnt
            elif status == "success" and failed_count > 0:
                has_success_after_fail = True

        # Fallback check DB sliding window if session provided
        session = context.get("session")
        agent_id = context.get("agent_id") or telemetry.get("agent_id")
        if session and agent_id and failed_count < threshold:
            try:
                from app.repositories.auth_event_repository import AuthEventRepository
                repo = AuthEventRepository(session)
                window_sec = int(self.config.get("window_seconds", 60))
                db_fails = await repo.count_failed_attempts(agent_id=agent_id, window_seconds=window_sec)
                failed_count = max(failed_count, db_fails)
            except Exception:
                pass

        if failed_count == 0 and not has_success_after_fail:
            return 0.0, ""

        users_str = f" [Users: {', '.join(list(targeted_users)[:3])}]" if targeted_users else ""
        ips_str = f" from {', '.join(list(source_ips)[:2])}" if source_ips else ""

        # Case 1: Success after multiple failed attempts -> Breach!
        if has_success_after_fail and failed_count >= threshold:
            score = min(100.0, 85.0 * self.base_score / 30.0)
            return score, f"CRITICAL: Successful authentication breach following {failed_count} failed attempts{users_str}{ips_str}"

        # Case 2: Heavy continuous brute force
        if failed_count >= critical_threshold:
            score = min(100.0, 75.0 * self.base_score / 30.0)
            return score, f"Aggressive brute force attack detected: {failed_count} failed attempts{users_str}{ips_str}"

        # Case 3: Threshold met
        if failed_count >= threshold:
            score = min(50.0, self.base_score + (failed_count - threshold) * 2.0)
            return score, f"Brute force activity detected: {failed_count} failed login attempts{users_str}{ips_str}"

        return 0.0, ""
