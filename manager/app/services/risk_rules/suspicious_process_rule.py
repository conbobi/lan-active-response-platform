import os
import re
import socket
from pathlib import Path
from typing import Any, Dict, Tuple, List, Set
from app.services.risk_rules.base import RiskRule

TEMP_DIRECTORIES = ("/tmp/", "/dev/shm/", "/var/tmp/")
INTERPRETERS = {"python", "python3", "bash", "sh", "zsh", "perl", "ruby", "php"}


def is_name_in_blacklist(name: str, exe: str, cmdline: str, blacklist: List[str]) -> bool:
    """
    Check if process name, executable basename, or command line matches any blacklist entry.
    Uses word-boundary checks to prevent substring false positives (e.g. 'nc' matching 'async' or 'function').
    """
    if not blacklist:
        return False

    normalized_bl = {s.lower().removesuffix(".exe").strip() for s in blacklist if s}

    # 1. Exact name match (stripping .exe)
    name_clean = name.lower().removesuffix(".exe").strip()
    if name_clean:
        if name_clean in normalized_bl:
            return True
        if any(name_clean.startswith(f"{b}.") for b in normalized_bl):
            return True

    # 2. Exe basename match
    if exe:
        exe_clean = Path(exe).name.lower().removesuffix(".exe").strip()
        if exe_clean:
            if exe_clean in normalized_bl:
                return True
            if any(exe_clean.startswith(f"{b}.") for b in normalized_bl):
                return True

    # 3. Cmdline word-boundary match
    if cmdline:
        for b in normalized_bl:
            pattern = rf"(?:\A|[^a-zA-Z0-9_\-\.]){re.escape(b)}(?:\.exe)?(?:\Z|[^a-zA-Z0-9_\-\.])"
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True

    return False


def is_running_from_temp(p_dict: Dict[str, Any]) -> bool:
    """
    Check if process executable or executed script is located in /tmp, /dev/shm, or /var/tmp.
    """
    for field in ("exe", "path", "exe_path", "cwd"):
        val = str(p_dict.get(field) or "").strip().lower()
        if any(val.startswith(td) or val == td.rstrip("/") for td in TEMP_DIRECTORIES):
            return True

    cmdline = str(p_dict.get("cmdline") or "").strip().lower()
    if cmdline:
        parts = cmdline.split()
        if parts:
            first_tok = parts[0]
            if any(first_tok.startswith(td) for td in TEMP_DIRECTORIES):
                return True
            first_name = Path(first_tok).name.removesuffix(".exe")
            if first_name in INTERPRETERS:
                for arg in parts[1:]:
                    if arg.startswith("-"):
                        continue
                    if any(arg.startswith(td) for td in TEMP_DIRECTORIES):
                        return True
                    break
    return False


def extract_outbound_network_entities(telemetry: Dict[str, Any]) -> Tuple[Set[int], Set[str]]:
    """
    Extract set of PIDs and process names that have outbound network connections
    (non-loopback destination, non-LISTEN status, ignoring Manager IP and agent heartbeat port 8000).
    """
    outbound_pids: Set[int] = set()
    outbound_proc_names: Set[str] = set()

    ignored_ips = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
    manager_ip = os.getenv("MANAGER_IP", "").strip()
    if manager_ip:
        ignored_ips.add(manager_ip)

    try:
        ignored_ips.add(socket.gethostbyname("manager"))
    except Exception:
        pass

    try:
        ignored_ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass

    for conn in telemetry.get("network_connections", []):
        c_dict = conn if isinstance(conn, dict) else conn.model_dump() if hasattr(conn, "model_dump") else getattr(conn, "__dict__", {})
        dst_ip = str(c_dict.get("dst_ip") or "").strip()
        dst_port = int(c_dict.get("dst_port") or 0)
        status = str(c_dict.get("status") or "").upper()

        # Ignore local, docker DNS (127.0.0.11), manager IP, and manager port 8000/8002
        if dst_ip.startswith("127.") or dst_ip in ignored_ips or dst_port in (8000, 8002):
            continue

        if dst_ip and status != "LISTEN":
            pid = c_dict.get("pid")
            if pid is not None:
                try:
                    outbound_pids.add(int(pid))
                except (ValueError, TypeError):
                    pass
            p_name = str(c_dict.get("process_name") or c_dict.get("name") or "").strip().lower()
            if p_name:
                outbound_proc_names.add(p_name)

    return outbound_pids, outbound_proc_names


def has_outbound_network(
    p_dict: Dict[str, Any],
    outbound_pids: Set[int],
    outbound_proc_names: Set[str]
) -> bool:
    """
    Check if process has an active outbound network connection.
    """
    # 1. Explicit flag on process dictionary
    if p_dict.get("has_outbound_network") or p_dict.get("has_outbound") or p_dict.get("has_network"):
        return True

    # 2. PID correlation from telemetry network_connections
    pid = p_dict.get("pid")
    if pid is not None:
        try:
            if int(pid) in outbound_pids:
                return True
        except (ValueError, TypeError):
            pass

    # 3. Process name correlation if network_connections specifically named it
    name = str(p_dict.get("name") or "").strip().lower()
    if name and name in outbound_proc_names:
        return True

    # 4. Nested connections in process dict
    for conn_key in ("connections", "network_connections"):
        proc_conns = p_dict.get(conn_key)
        if isinstance(proc_conns, list):
            for c in proc_conns:
                if isinstance(c, dict):
                    dst = str(c.get("dst_ip") or "").strip()
                    status = str(c.get("status") or "").upper()
                    if dst and dst not in {"127.0.0.1", "0.0.0.0", "localhost", "::1"} and status != "LISTEN":
                        return True

    return False


class SuspiciousProcessRule(RiskRule):
    rule_id = "suspicious_process"
    name = "Suspicious Process & Threat Intel Hash"
    description = "Detects known malicious binaries, suspicious flags, and Threat Intelligence hash matches."
    enabled = True
    weight = 1.0
    category = "os"

    DEFAULT_SUSPICIOUS_NAMES = [
        "mimikatz",
        "psexec",
        "nc",
        "ncat",
        "nmap",
        "chisel",
        "lazagne",
        "vssadmin",
        "ransomware_sim",
        "meterpreter",
        "cobaltstrike",
    ]

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        processes = telemetry.get("process_list", [])
        if not processes:
            return 0.0, ""

        suspicious_list = self.config.get("suspicious_names", self.DEFAULT_SUSPICIOUS_NAMES)
        suspicious_proc_count = 0
        threat_hash_count = 0
        proc_names: List[str] = []

        threat_intel_service = context.get("threat_intel_service")
        whitelist_service = context.get("whitelist_service")
        agent_id = context.get("agent_id")

        outbound_pids, outbound_proc_names = extract_outbound_network_entities(telemetry)

        for proc in processes:
            p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
            name = str(p_dict.get("name", "")).strip().lower()
            exe = str(p_dict.get("exe") or p_dict.get("path") or p_dict.get("exe_path") or "").strip()
            cmdline = str(p_dict.get("cmdline", "")).strip().lower()
            p_hash = p_dict.get("hash")

            # Skip the LARP agent process itself
            if "agent.py" in cmdline or name == "agent.py":
                continue

            # Check whitelist first
            if whitelist_service:
                try:
                    if await whitelist_service.is_whitelisted(agent_id=agent_id, process_name=name, path=exe):
                        continue
                except Exception:
                    pass

            # 4 conditions:
            # 1. Tên trong blacklist
            c1_blacklist = is_name_in_blacklist(name, exe, cmdline, suspicious_list)

            # 2. Chạy từ /tmp, /dev/shm, /var/tmp
            c2_temp_dir = is_running_from_temp(p_dict)

            # 3. Có kết nối mạng ra ngoài
            c3_outbound = has_outbound_network(p_dict, outbound_pids, outbound_proc_names)

            # 4. Hash khớp Threat Intel
            c4_threat_intel = False
            if p_hash and threat_intel_service:
                try:
                    intel_res = await threat_intel_service.check_hash(p_hash)
                    if intel_res and intel_res.get("is_malicious"):
                        c4_threat_intel = True
                        threat_hash_count += 1
                except Exception:
                    pass

            # Only count as suspicious if at least one condition is met
            if c1_blacklist or c2_temp_dir or c3_outbound or c4_threat_intel:
                suspicious_proc_count += 1
                display_name = p_dict.get("name") or name or "suspicious_process"
                if display_name not in proc_names:
                    proc_names.append(display_name)

        score = 0.0
        reasons = []

        if suspicious_proc_count > 0:
            score += min(45.0, suspicious_proc_count * 25.0)
            reasons.append(f"Found {suspicious_proc_count} suspicious processes: {', '.join(proc_names)}")

        if threat_hash_count > 0:
            score += 40.0
            reasons.append(f"Matched {threat_hash_count} malicious file hashes with Threat Intelligence")

        if score > 0:
            return score * self.base_score, "; ".join(reasons)

        return 0.0, ""
