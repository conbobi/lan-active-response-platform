"""Normalize recorded signals without retaining request bodies, credentials or query values."""
import hashlib
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import unquote, urlsplit

from app.core.agent_health import as_utc

REPEATED = "repeated_auth_failures"
BRUTE_FORCE = "authentication_brute_force"
SQLI = "sqli_probing"
SCAN = "network_service_scanning"
UNKNOWN = "unknown_automated_activity"
BEHAVIORS = {REPEATED, BRUTE_FORCE, SQLI, SCAN, UNKNOWN}
INDICATORS = {
    "sql_boolean_expression": re.compile(r"""['"]\s*\)?\s*(?:and|or)\s+[\s('"\d]+[^\s]{0,40}\s*=""", re.I),
    "sql_query_operator": re.compile(r"\bunion\s+(?:all\s+)?select\b|\bselect\s+(?:case|concat|char)\b|\border\s+by\s+\d+\s*--", re.I),
    "sql_delay_function": re.compile(r"\b(?:pg_sleep|sleep|benchmark|dbms_pipe\.receive_message)\s*\(|\bwaitfor\s+delay\b", re.I),
    "sql_error_expression": re.compile(r"\b(?:extractvalue|updatexml)\s*\(", re.I),
}
TOOL_UA = re.compile(r"(?:^|[^\w])(hydra|sqlmap|nikto|nmap|gobuster|dirbuster|ffuf|wfuzz|metasploit|havoc|acunetix|masscan|commix|burpcollaborator|zgrab)(?:[^\w]|$)", re.I)
TOKEN = re.compile(r"[A-Za-z0-9_.:@+\\-]{1,64}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")
HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def signature_indicators(value) -> set[str]:
    if not isinstance(value, str):
        return set()
    return {name for name, pattern in INDICATORS.items() if pattern.search(value[:4096])}


def valid_indicators(value) -> set[str]:
    return {item for item in value if isinstance(item, str) and item in INDICATORS} if isinstance(value, list) else set()


def stable_id(prefix: str, *parts) -> str:
    return prefix + hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()[:40]


def address(value) -> str | None:
    try:
        parsed = ip_address(str(value))
    except ValueError:
        return None
    return str(getattr(parsed, "ipv4_mapped", None) or parsed)


def observed_time(value, fallback=None):
    parsed = as_utc(value)
    if parsed is not None:
        return parsed
    if type(value) in (float, int):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError):
            return fallback
    return fallback


def http_fields(data: dict) -> dict:
    url = data.get("request_path") or data.get("path") or data.get("url") or ""
    url = url[:4096] if isinstance(url, str) else ""
    try:
        parsed = urlsplit(url)
        if parsed.netloc and parsed.scheme not in {"http", "https"}:
            return {}
    except ValueError:
        return {}
    path = parsed.path if parsed.path.startswith("/") else None
    if path is not None and (len(path) > 256 or any(ord(ch) < 32 for ch in path)):
        path = None
    if path:
        path = "/".join("[redacted]" if len(segment) > 48 else segment for segment in path.split("/"))
    method = str(data.get("request_method") or data.get("method") or data.get("http_method") or "").upper()
    ua = data.get("user_agent")
    ua = ua[:256] if isinstance(ua, str) and ua.isprintable() else None
    status = data.get("http_status") or data.get("status_code")
    status = int(status) if str(status).isascii() and str(status).isdigit() and len(str(status)) == 3 else None
    request_id = data.get("request_id")
    indicators = valid_indicators(data.get("payload_indicators"))
    if path:
        indicators |= signature_indicators(unquote(parsed.path))
        indicators |= signature_indicators(unquote(parsed.query))
    return {k: v for k, v in {
        "request_method": method if method in HTTP_METHODS else None, "request_path": path,
        "http_status": status if status and 100 <= status < 600 else None, "user_agent": ua,
        "request_id": request_id if isinstance(request_id, str) and REQUEST_ID.fullmatch(request_id) else None,
        "payload_indicators": sorted(indicators) if indicators else None,
    }.items() if v is not None}


def technique_for(evidence: dict) -> str | None:
    kind = evidence.get("classification")
    if not evidence.get("source_event_ids"):
        return None
    if kind == BRUTE_FORCE and evidence.get("brute_force_criteria") in (
        "password_burst_same_account_source", "distributed_password_burst_same_account",
    ):
        return "T1110"
    port_values = evidence.get("destination_ports")
    ports = {port for port in port_values if type(port) is int and 0 < port <= 65535} if isinstance(port_values, list) else set()
    if kind == SCAN and evidence.get("direction") == "inbound" and len(ports) >= 8:
        return "T1046"
    path = evidence.get("request_path")
    method = evidence.get("request_method")
    if (kind == SQLI and isinstance(method, str) and method in HTTP_METHODS
            and isinstance(path, str) and path.startswith("/")
            and valid_indicators(evidence.get("payload_indicators"))):
        return "T1190"
    return None


def evidence_ids(events: list[dict]) -> list[str]:
    return list(dict.fromkeys(item["evidence_id"] for item in events if item.get("evidence_id")))
