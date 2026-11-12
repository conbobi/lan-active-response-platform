from typing import Any, Dict, Tuple, List, Set
from collections import defaultdict
from app.services.detection.risk_rules.base import RiskRule


class BruteForceRule(RiskRule):
    """
    Risk rule detecting brute force authentication attacks (SSH / RDP / Local auth).
    Triggers when:
    1. >= 5 failed logins from same IP in short window (score: 55)
    2. >= 10 failed logins on same user (score: 50)
    3. Distributed attack: >= 3 distinct IPs targeting same user (score: 65)
    4. Successful login following repeated failures (breach! score: 85)
    """
    rule_id = "brute_force"
    name = "Brute Force Authentication Detection"
    description = "Detects targeted or distributed brute force authentication attempts and credential stuffing."
    enabled = True
    weight = 1.0
    base_score = 30.0
    category = "identity"

    FAILED_LOGIN_THRESHOLD = 5
    FAILED_USERNAME_THRESHOLD = 10
    DISTRIBUTED_IP_THRESHOLD = 3

    DEFAULT_CONFIG = {
        "threshold": 5,
        "critical_threshold": 15,
        "window_seconds": 60
    }

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        threshold = int(self.config.get("threshold", self.FAILED_LOGIN_THRESHOLD))
        critical_threshold = int(self.config.get("critical_threshold", 15))

        auth_events: List[Dict[str, Any]] = telemetry.get("auth_events", [])
        failed_count = int(telemetry.get("failed_login_attempts", 0))
        has_success_after_fail = False

        by_ip: Dict[str, int] = defaultdict(int)
        by_user: Dict[str, int] = defaultdict(int)
        user_ips: Dict[str, Set[str]] = defaultdict(set)

        for evt in auth_events:
            status = str(evt.get("status", "")).lower()
            is_failed = (status == "failed") or (evt.get("success") is False)
            cnt = int(evt.get("count", 1))

            u = str(evt.get("username") or "unknown").strip()
            s_ip = str(evt.get("source_ip") or "unknown").strip()

            if is_failed:
                failed_count += cnt
                if s_ip and s_ip != "unknown":
                    by_ip[s_ip] += cnt
                if u and u != "unknown":
                    by_user[u] += cnt
                    if s_ip and s_ip != "unknown":
                        user_ips[u].add(s_ip)
            elif (status == "success" or evt.get("success") is True) and failed_count > 0:
                has_success_after_fail = True

        # Fallback check DB sliding window if context session provided and count below threshold
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

        # Check 1: Success after multiple failed attempts -> Breach!
        if has_success_after_fail and failed_count >= threshold:
            reason = f"CRITICAL: Successful authentication breach following {failed_count} failed attempts"
            return 85.0 * self.base_score / 30.0, reason

        # Check 2: Distributed brute force attack (multiple IPs -> same user)
        for user, ips in user_ips.items():
            if len(ips) >= self.DISTRIBUTED_IP_THRESHOLD:
                ips_sample = ", ".join(list(ips)[:3])
                reason = f"Distributed brute force on user '{user}': {len(ips)} source IPs ({ips_sample})"
                return 65.0 * self.base_score / 30.0, reason

        # Check 3: Brute force by IP
        for ip, count in by_ip.items():
            if count >= self.FAILED_LOGIN_THRESHOLD:
                reason = f"Brute force from IP {ip}: {count} failed logins"
                return 55.0 * self.base_score / 30.0, reason

        # Check 4: Brute force by username
        for user, count in by_user.items():
            if count >= self.FAILED_USERNAME_THRESHOLD:
                reason = f"Brute force on user '{user}': {count} failed attempts"
                return 50.0 * self.base_score / 30.0, reason

        # Check 5: Heavy total failures
        if failed_count >= critical_threshold:
            return 75.0 * self.base_score / 30.0, f"Aggressive brute force attack detected: {failed_count} failed attempts"

        # Check 6: Generic threshold met
        if failed_count >= threshold:
            score = min(50.0, self.base_score + (failed_count - threshold) * 2.0)
            return score, f"Brute force activity detected: {failed_count} failed login attempts"

        return 0.0, ""
