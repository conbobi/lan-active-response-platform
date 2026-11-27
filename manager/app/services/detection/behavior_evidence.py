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
SQLI_TOOL = "sqli_tool_indicator"
SQLI_PROBE = "sqli_probe_observed"
SQLI_SUSPECTED = "sqli_exploitation_suspected"
SQLI_CONFIRMED = "sqli_exploitation_confirmed"
SCAN = "network_service_scanning"
AUTOMATED_HTTP = "automated_http_activity"
UNKNOWN = "unknown_automated_activity"
BEHAVIORS = {
    REPEATED, BRUTE_FORCE, SQLI, SCAN, UNKNOWN,
    SQLI_TOOL, SQLI_PROBE, SQLI_SUSPECTED, SQLI_CONFIRMED, AUTOMATED_HTTP,
}
INDICATORS = {
    "sql_boolean_expression": re.compile(r"""['"]\s*\)?\s*(?:and|or)\s+[\s('"\d]+[^\s]{0,40}\s*=""", re.I),
    "sql_query_operator": re.compile(r"\bunion\s+(?:all\s+)?select\b|\bselect\s+(?:case|concat|char)\b|\border\s+by\s+\d+\s*--", re.I),
    "sql_delay_function": re.compile(r"\b(?:pg_sleep|sleep|benchmark|dbms_pipe\.receive_message)\s*\(|\bwaitfor\s+delay\b", re.I),
    "sql_error_expression": re.compile(r"\b(?:extractvalue|updatexml)\s*\(", re.I),
}
SQLI_TOOL_UA = re.compile(
    r"(?:^|[^\w])(sqlmap|commix|sqlninja|havij|bbqsql|jsql)(?:[^\w]|$)", re.I
)
TOOL_UA = re.compile(
    r"(?:^|[^\w])(hydra|sqlmap|nikto|nmap|gobuster|dirbuster|ffuf|wfuzz|metasploit|havoc|acunetix|masscan|commix|burpcollaborator|zgrab|curl|python-requests|wget|sqlninja|havij|bbqsql|jsql)(?:[^\w]|$)",
    re.I
)
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
    body_val = data.get("body") or data.get("payload") or data.get("post_data") or data.get("form_data")
    if isinstance(body_val, str):
        indicators |= signature_indicators(unquote(body_val))
    elif isinstance(body_val, dict):
        for val in body_val.values():
            if isinstance(val, str):
                indicators |= signature_indicators(unquote(val))
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
    activity = evidence.get("activity_summary")
    if (kind in (AUTOMATED_HTTP, SQLI_TOOL) and isinstance(activity, dict)
            and type(activity.get("tool_request_count")) is int and activity["tool_request_count"] > 0
            and type(activity.get("distinct_path_count")) is int
            and activity["distinct_path_count"] >= activity.get("scan_threshold_paths", 5) >= 5):
        return "T1595"
    path = evidence.get("request_path")
    method = evidence.get("request_method")
    payload_ind = valid_indicators(evidence.get("payload_indicators"))
    if (kind in (SQLI, SQLI_PROBE, SQLI_SUSPECTED, SQLI_CONFIRMED) and isinstance(method, str) and method in HTTP_METHODS
            and isinstance(path, str) and path.startswith("/")
            and payload_ind):
        return "T1190"
    return None


def evidence_ids(events: list[dict]) -> list[str]:
    return list(dict.fromkeys(item["evidence_id"] for item in events if item.get("evidence_id")))


SHELL_INDICATORS = {"shell_command_separator", "shell_pipe", "shell_and_or", "shell_background",
                    "shell_substitution", "shell_redirection"}
EXECUTION_RESULTS = {"not_started", "running", "completed", "timeout", "error"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


def _pid(value):
    return value if type(value) is int and 0 < value < 2**31 else None


def _text(value, limit):
    return value[:limit] if isinstance(value, str) and value.isprintable() else None


def app_observation(data: dict) -> dict:
    """Validated application-side fields of a web observation (vulnerable_web telemetry).

    Everything is optional; unknown keys and malformed values are dropped, never trusted.
    """
    out = {}
    event_id = data.get("event_id")
    if isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{32}", event_id):
        out["app_event_id"] = event_id
    for key in ("process_pid", "parent_pid"):
        if _pid(data.get(key)):
            out[key] = data[key]
    event = data.get("app_event")
    if not isinstance(event, dict):
        return out
    if event.get("type") == "file_upload":
        upload = {"type": "file_upload", "stored": event.get("stored") is True}
        path = _text(event.get("upload_path"), 512)
        if path and path.startswith("/"):
            upload["upload_path"] = path
        if type(event.get("upload_size")) is int and 0 <= event["upload_size"] < 2**40:
            upload["upload_size"] = event["upload_size"]
        if isinstance(event.get("upload_sha256"), str) and SHA256.fullmatch(event["upload_sha256"]):
            upload["upload_sha256"] = event["upload_sha256"]
        for key in ("outside_upload_dir", "script_or_binary"):
            if type(event.get(key)) is bool:
                upload[key] = event[key]
        ext = _text(event.get("extension"), 16)
        if ext and re.fullmatch(r"\.[a-z0-9]{0,15}", ext):
            upload["extension"] = ext
        name = _text(event.get("client_filename"), 255)
        if name:
            upload["client_filename"] = name
        out["app_event"] = upload
    elif event.get("type") == "shell_command":
        command = {"type": "shell_command"}
        if event.get("parameter") in ("ip",):
            command["parameter"] = event["parameter"]
        if type(event.get("parameter_length")) is int and 0 <= event["parameter_length"] < 2**20:
            command["parameter_length"] = event["parameter_length"]
        if isinstance(event.get("parameter_sha256"), str) and SHA256.fullmatch(event["parameter_sha256"]):
            command["parameter_sha256"] = event["parameter_sha256"]
        indicators = event.get("shell_indicators")
        if isinstance(indicators, list):
            command["shell_indicators"] = sorted({i for i in indicators if i in SHELL_INDICATORS})
        files = event.get("referenced_upload_files")
        if isinstance(files, list):
            command["referenced_upload_files"] = [f for f in files if isinstance(f, str) and SAFE_NAME.fullmatch(f)][:8]
        if event.get("execution_result") in EXECUTION_RESULTS:
            command["execution_result"] = event["execution_result"]
        if _pid(event.get("child_pid")):
            command["child_pid"] = event["child_pid"]
        if isinstance(event.get("child_spawned_at"), (int, float)) and 0 < event["child_spawned_at"] < 4e9:
            command["child_spawned_at"] = float(event["child_spawned_at"])
        if type(event.get("exit_code")) is int and -256 < event["exit_code"] < 256:
            command["exit_code"] = event["exit_code"]
        if isinstance(event.get("duration_s"), (int, float)) and 0 <= event["duration_s"] < 86400:
            command["duration_s"] = float(event["duration_s"])
        out["app_event"] = command
    return out
