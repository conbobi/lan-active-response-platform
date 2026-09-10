import os
import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AuthMonitor:
    """
    Monitors Linux authentication logs (/var/log/auth.log, /var/log/secure, /tmp/auth.log)
    for failed and successful authentication events (SSH, RDP, PAM).
    Preserves file seek pointers to ensure each event is read only once.
    """

    LOG_PATHS = [
        "/tmp/auth.log",       # Simulated/test log path
        "/var/log/auth.log",   # Ubuntu/Debian
        "/var/log/secure",     # CentOS/RHEL/Fedora
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

    def __init__(self, agent_id: str = "agent"):
        self.agent_id = agent_id
        self.active_log_path: Optional[str] = self._detect_log_file()
        self.file_pos: int = 0
        if self.active_log_path and os.path.exists(self.active_log_path):
            # Start at end of file on startup
            try:
                self.file_pos = os.path.getsize(self.active_log_path)
            except Exception:
                self.file_pos = 0

    def _detect_log_file(self) -> Optional[str]:
        for p in self.LOG_PATHS:
            if os.path.exists(p):
                return p
        return None

    def get_new_events(self) -> List[Dict[str, Any]]:
        """Read newly appended lines from log file and extract auth events."""
        if not self.active_log_path or not os.path.exists(self.active_log_path):
            self.active_log_path = self._detect_log_file()
            if not self.active_log_path:
                return []

        events: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            curr_size = os.path.getsize(self.active_log_path)
            if curr_size < self.file_pos:
                # Log rotation detected
                self.file_pos = 0

            with open(self.active_log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.file_pos)
                lines = f.readlines()
                self.file_pos = f.tell()

            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue

                # Check Failed SSH
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

                # Check Accepted SSH
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

                # Check PAM failure
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
            logger.error(f"Error reading auth log '{self.active_log_path}': {e}")

        return events


global_auth_monitor = AuthMonitor()
