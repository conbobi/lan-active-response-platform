import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AuthMonitor:
    """
    Monitors Linux authentication logs (SSH, PAM, Web Application logins)
    for failed and successful authentication events.
    Supports multi-file tracking and preserves seek pointers per file.
    """

    LOG_PATHS = [
        "/tmp/auth.log",                         # Simulated/test log path
        "/tmp/web_auth.log",                     # Web auth log for lab testing
        "/home/webuser/vulnerable_web/auth.log", # Flask web auth log
        "/var/log/vulnerable_web/auth.log",      # Production web auth log
        "/var/log/auth.log",                     # Ubuntu/Debian SSH/PAM
        "/var/log/secure",                       # CentOS/RHEL/Fedora
    ]

    FAILED_SSH_RE = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2",
        re.IGNORECASE
    )
    ACCEPTED_SSH_RE = re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2",
        re.IGNORECASE
    )
    FAILED_PAM_RE = re.compile(
        r"pam_unix\(\S+:auth\): authentication failure;.*rhost=(?P<ip>\S*)\s+user=(?P<user>\S*)",
        re.IGNORECASE
    )
    WEB_AUTH_RE = re.compile(
        r"\[WEB_AUTH\]\s+status=(?P<status>\S+)\s+username=(?P<user>\S+)\s+ip=(?P<ip>\S+)(?:\s+service=(?P<svc>\S+))?",
        re.IGNORECASE
    )

    def __init__(self, agent_id: str = "agent"):
        self.agent_id = agent_id
        self.file_positions: Dict[str, int] = {}
        # Initialize file positions to EOF for existing files
        for p in self.LOG_PATHS:
            if os.path.exists(p) and os.path.isfile(p):
                try:
                    self.file_positions[p] = os.path.getsize(p)
                except Exception:
                    self.file_positions[p] = 0

    def _get_active_files(self) -> List[str]:
        return [p for p in self.LOG_PATHS if os.path.exists(p) and os.path.isfile(p)]

    def get_new_events(self) -> List[Dict[str, Any]]:
        """Read newly appended lines from all active auth log files and extract auth events."""
        events: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        active_files = self._get_active_files()
        for log_path in active_files:
            last_pos = self.file_positions.get(log_path, 0)
            try:
                curr_size = os.path.getsize(log_path)
                if curr_size < last_pos:
                    # Log rotation or truncation
                    last_pos = 0

                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    self.file_positions[log_path] = f.tell()

                for line in lines:
                    line_str = line.strip()
                    if not line_str:
                        continue

                    # 1. Check Web Auth JSON format: {"service": "flask_web", "username": "admin", ...}
                    if line_str.startswith("{") and ("username" in line_str or "user" in line_str):
                        try:
                            payload = json.loads(line_str)
                            svc = payload.get("service") or payload.get("app") or "flask_web"
                            u = payload.get("username") or payload.get("user") or "unknown"
                            s_ip = payload.get("source_ip") or payload.get("ip") or payload.get("client_ip") or "unknown"
                            st = str(payload.get("status") or "failed").lower()
                            events.append({
                                "agent_id": self.agent_id,
                                "service": svc,
                                "source_ip": s_ip,
                                "username": u,
                                "status": "success" if st in ("success", "ok", "authenticated") else "failed",
                                "count": int(payload.get("count", 1)),
                                "timestamp": payload.get("timestamp") or now_iso
                            })
                            continue
                        except Exception:
                            pass

                    # 2. Check Web Auth tag: [WEB_AUTH] status=failed username=admin ip=1.2.3.4
                    m_web = self.WEB_AUTH_RE.search(line_str)
                    if m_web:
                        st = m_web.group("status").lower()
                        events.append({
                            "agent_id": self.agent_id,
                            "service": m_web.group("svc") or "flask_web",
                            "source_ip": m_web.group("ip"),
                            "username": m_web.group("user"),
                            "status": "success" if st in ("success", "ok", "authenticated") else "failed",
                            "count": 1,
                            "timestamp": now_iso
                        })
                        continue

                    # 3. Check Failed SSH
                    m_fail = self.FAILED_SSH_RE.search(line_str)
                    if m_fail:
                        events.append({
                            "agent_id": self.agent_id,
                            "service": "ssh",
                            "source_ip": m_fail.group("ip"),
                            "username": m_fail.group("user"),
                            "status": "failed",
                            "count": 1,
                            "timestamp": now_iso
                        })
                        continue

                    # 4. Check Accepted SSH
                    m_succ = self.ACCEPTED_SSH_RE.search(line_str)
                    if m_succ:
                        events.append({
                            "agent_id": self.agent_id,
                            "service": "ssh",
                            "source_ip": m_succ.group("ip"),
                            "username": m_succ.group("user"),
                            "status": "success",
                            "count": 1,
                            "timestamp": now_iso
                        })
                        continue

                    # 5. Check PAM failure
                    m_pam = self.FAILED_PAM_RE.search(line_str)
                    if m_pam:
                        ip = m_pam.group("ip") or "127.0.0.1"
                        user = m_pam.group("user") or "unknown"
                        events.append({
                            "agent_id": self.agent_id,
                            "service": "pam",
                            "source_ip": ip,
                            "username": user,
                            "status": "failed",
                            "count": 1,
                            "timestamp": now_iso
                        })

            except Exception as e:
                logger.error(f"Error reading auth log '{log_path}': {e}")

        return events


global_auth_monitor = AuthMonitor()
