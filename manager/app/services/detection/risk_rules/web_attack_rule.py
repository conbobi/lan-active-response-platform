import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import unquote

from app.services.detection.risk_rules.base import RiskRule


class WebAttackRule(RiskRule):
    """
    NDR Risk Rule detecting Web-based attacks against applications exposed via
    Cloudflare Tunnel, Nginx, or directly:
    1. Web Authentication Brute Force (T1110): >= 5 POST /login attempts within 10s.
    2. Malicious Scanning & Exploit Tools: User-Agent matching Hydra, sqlmap, nikto,
       gobuster, ffuf, dirbuster, nmap, metasploit, havoc, etc.
    3. Web Application Exploits (T1190): Path Traversal (../, /etc/passwd) and
       SQL Injection (' OR 1=1, UNION SELECT, sleep).
    """
    rule_id = "web_attack"
    name = "Web Application Attack Detection (NDR)"
    description = (
        "Detects web-based attacks including login brute force (T1110), "
        "attack tool User-Agents (Hydra, sqlmap, nikto), path traversal, and SQL injection (T1190)."
    )
    enabled = True
    weight = 1.0
    base_score = 40.0
    category = "network"

    # Known offensive security and attack tool User-Agent signatures (case-insensitive)
    MALICIOUS_USER_AGENTS = [
        "hydra",
        "sqlmap",
        "nikto",
        "nmap",
        "gobuster",
        "dirbuster",
        "ffuf",
        "wfuzz",
        "metasploit",
        "havoc",
        "acunetix",
        "masscan",
        "commix",
        "burpcollaborator",
        "zgrab",
    ]

    # Path traversal regex signatures
    RE_PATH_TRAVERSAL = re.compile(
        r'(?:(?:\.\.(?:/|\\|%2f|%252f|%5c)){2,}|/etc/(?:passwd|shadow|hosts)|/proc/self/|windows/win\.ini|\bcmd\.exe\b)',
        re.IGNORECASE
    )

    # SQL Injection regex signatures
    RE_SQLI = re.compile(
        r"(?:(?:\'|\"|%27)\s*(?:or|and)\s*(?:[\'\"0-9a-z]+\s*=\s*[\'\"0-9a-z]+|1\s*=\s*1|true\b)"
        r"|\bunion\s+(?:all\s+)?select\b"
        r"|--\s*$"
        r"|/\*.*\*/"
        r"|\bsleep\s*\(\s*\d+\s*\)"
        r"|\bbenchmark\s*\(\s*\d+"
        r"|\bwaitfor\s+delay\b)",
        re.IGNORECASE
    )

    # Sliding window tracker for login brute force: { (agent_id, src_ip): [timestamps] }
    _ip_login_timestamps: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    @classmethod
    def record_login_attempt(cls, agent_id: str, src_ip: str, ts: Optional[float] = None) -> int:
        """Records a login attempt and returns count within last 10 seconds."""
        now = ts or time.time()
        key = (agent_id or "default", src_ip or "unknown")
        # Keep only timestamps within last 10 seconds
        cls._ip_login_timestamps[key] = [
            t for t in cls._ip_login_timestamps[key] if now - t <= 10.0
        ]
        cls._ip_login_timestamps[key].append(now)
        return len(cls._ip_login_timestamps[key])

    @classmethod
    def get_login_count(cls, agent_id: str, src_ip: str, now: Optional[float] = None) -> int:
        n = now or time.time()
        key = (agent_id or "default", src_ip or "unknown")
        cls._ip_login_timestamps[key] = [
            t for t in cls._ip_login_timestamps[key] if n - t <= 10.0
        ]
        return len(cls._ip_login_timestamps[key])

    @classmethod
    def reset_tracker(cls):
        cls._ip_login_timestamps.clear()

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        """
        Evaluates web telemetry against web attack rules.
        Supports single log event, batch of web_logs, or sliding-window DB lookups.
        """
        logs_to_check: List[Dict[str, Any]] = []

        if isinstance(telemetry.get("web_logs"), list):
            logs_to_check.extend(telemetry["web_logs"])
        if isinstance(telemetry.get("web_log"), dict):
            logs_to_check.append(telemetry["web_log"])

        # If telemetry itself contains web request fields
        if ("path" in telemetry or "url" in telemetry) and ("src_ip" in telemetry or "method" in telemetry or "user_agent" in telemetry):
            logs_to_check.append(telemetry)

        agent_id = context.get("agent_id") or telemetry.get("agent_id") or "unknown"
        session = context.get("session")

        max_score = 0.0
        reasons: List[str] = []

        for log in logs_to_check:
            src_ip = str(log.get("src_ip") or log.get("client_ip") or "unknown").strip()
            user_agent = str(log.get("user_agent") or "").strip()
            path = unquote(str(log.get("path") or log.get("url") or "/")).strip()
            raw_msg = unquote(str(log.get("raw_message") or log.get("raw_log") or ""))
            method = str(log.get("method") or log.get("http_method") or "GET").upper().strip()

            # 1. Malicious User-Agent Check
            ua_lower = user_agent.lower()
            for tool_sig in self.MALICIOUS_USER_AGENTS:
                if tool_sig in ua_lower:
                    tool_score = 85.0
                    reason_msg = (
                        f"[Malicious Web Scanner/Tool] Detected offensive tool User-Agent '{user_agent}' "
                        f"targeting {method} {path} from IP {src_ip}"
                    )
                    if tool_score > max_score:
                        max_score = tool_score
                    if reason_msg not in reasons:
                        reasons.append(reason_msg)
                    break

            # 2. Web Application Exploit Check (Path Traversal & SQLi) - T1190
            check_str = f"{path} {raw_msg}"
            traversal_match = self.RE_PATH_TRAVERSAL.search(check_str)
            if traversal_match:
                exploit_score = 90.0
                reason_msg = (
                    f"[T1190 - Exploit Public-Facing Application] Path Traversal attack pattern "
                    f"'{traversal_match.group(0)}' detected in {method} {path} from IP {src_ip}"
                )
                if exploit_score > max_score:
                    max_score = exploit_score
                if reason_msg not in reasons:
                    reasons.append(reason_msg)

            sqli_match = self.RE_SQLI.search(check_str)
            if sqli_match:
                exploit_score = 90.0
                reason_msg = (
                    f"[T1190 - Exploit Public-Facing Application] SQL Injection pattern "
                    f"'{sqli_match.group(0)}' detected in {method} {path} from IP {src_ip}"
                )
                if exploit_score > max_score:
                    max_score = exploit_score
                if reason_msg not in reasons:
                    reasons.append(reason_msg)

            # 3. Web Authentication Brute Force Check - T1110
            is_login_path = any(k in path.lower() for k in ("/login", "/auth", "/signin", "/wp-login", "/session"))
            if method == "POST" and is_login_path and src_ip != "unknown":
                # Check explicit count or update in-memory sliding window
                explicit_count = log.get("login_count")
                if explicit_count is not None:
                    count = int(explicit_count)
                else:
                    count = self.record_login_attempt(agent_id, src_ip)

                # Optional DB sliding window check
                if session and count < 5:
                    try:
                        from app.repositories.web_access_log_repository import WebAccessLogRepository
                        repo = WebAccessLogRepository(session)
                        db_count = await repo.count_recent_login_requests(agent_id, src_ip, window_seconds=10)
                        if db_count > count:
                            count = db_count
                    except Exception:
                        pass

                if count >= 15:
                    bf_score = 95.0
                    reason_msg = (
                        f"[T1110 - Brute Force] Critical login brute-force attack: "
                        f"{count} POST {path} requests within 10s from IP {src_ip}"
                    )
                    if bf_score > max_score:
                        max_score = bf_score
                    if reason_msg not in reasons:
                        reasons.append(reason_msg)
                elif count >= 5:
                    bf_score = 80.0
                    reason_msg = (
                        f"[T1110 - Brute Force] High-frequency web login attempts: "
                        f"{count} POST {path} requests within 10s from IP {src_ip}"
                    )
                    if bf_score > max_score:
                        max_score = bf_score
                    if reason_msg not in reasons:
                        reasons.append(reason_msg)

        if max_score > 0:
            return round(max_score, 2), " | ".join(reasons)

        return 0.0, ""

