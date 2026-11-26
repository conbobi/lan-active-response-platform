"""Single Sigma evaluation path shared by the Detection Engine and the rule validator.

Both callers normalize events to one canonical shape and use the same support check, field matcher
and safe-process policy, so a given event and rule always produce the same verdict in validation
and at runtime. The Agent schema is unchanged: parent name/exe/cmdline are filled in from the same
process snapshot by PID.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

# Sigma field (lower case) → canonical event key.
FIELD_ALIASES = {
    "commandline": "cmdline", "cmdline": "cmdline",
    "image": "exe", "exe": "exe", "process": "exe",
    "processname": "name", "name": "name",
    "processid": "pid", "pid": "pid",
    "parentprocessid": "parent_pid", "parent_pid": "parent_pid",
    "parentimage": "parent_exe", "parent_exe": "parent_exe",
    "parentprocessname": "parent_name", "parent_name": "parent_name",
    "parentcommandline": "parent_cmdline", "parent_cmdline": "parent_cmdline",
    "destinationport": "dst_port", "dst_port": "dst_port",
    "destinationip": "dst_ip", "dst_ip": "dst_ip",
    "sourceport": "src_port", "src_port": "src_port",
    "sourceip": "src_ip", "src_ip": "src_ip",
    "targetfilename": "file_path", "file_path": "file_path",
}
PARENT_KEYS = {"parent_pid", "parent_exe", "parent_name", "parent_cmdline"}
SUPPORTED_MODIFIERS = {"contains", "endswith", "startswith", "re", "regex", "in"}

SAFE_PROCESSES = ['python3', 'python', 'node', 'bash', 'sh', 'xfwm4', 'systemd', 'dbus-daemon', 'xfce4-panel']
SUSPICIOUS_DIRS = ('/tmp', '/dev/shm', '/var/tmp')
REVERSE_SHELL_PAYLOAD = (r"/dev/tcp/", r"\bbash\s+-[a-zA-Z]*i", r"\bsh\s+-[a-zA-Z]*i", r"\bpty\.spawn", r"\bsocket\.socket")
SHELL_TECHNIQUES = {"T1059", "T1059.004", "T1059.001", "T1059.003"}


def _text(value) -> str:
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return "" if value is None else str(value)


def normalize_event(raw: dict) -> dict:
    """Canonical event; original keys are kept so downstream evidence code still finds them."""
    event = dict(raw)
    event["name"] = _text(raw.get("name") or raw.get("process_name") or raw.get("process")) or None
    event["exe"] = _text(raw.get("exe") or raw.get("exe_path") or raw.get("Image") or raw.get("image")) or None
    event["cmdline"] = _text(raw.get("cmdline") or raw.get("CommandLine") or raw.get("command_line"))
    pid = raw.get("pid")
    ppid = raw.get("parent_pid", raw.get("ppid"))
    event["pid"] = pid
    event["parent_pid"] = ppid
    for key, aliases in (("parent_name", ("parent_name", "parent")), ("parent_exe", ("parent_exe", "ParentImage")),
                         ("parent_cmdline", ("parent_cmdline", "ParentCommandLine"))):
        value = next((raw.get(a) for a in aliases if raw.get(a)), None)
        event[key] = _text(value) if value is not None else None
    return event


def normalize_snapshot(events: Iterable[dict]) -> list[dict]:
    """Normalize a process snapshot and fill parent metadata from the same snapshot by PID.

    Only a parent present in the same snapshot is used, and only when its PID is unique there;
    when the parent is missing (exited, or outside the Agent's per-cycle cap) the fields stay None
    and parent criteria cannot match.
    """
    normalized = [normalize_event(e) for e in events if isinstance(e, dict)]
    by_pid: dict[Any, list[dict]] = {}
    for event in normalized:
        if event.get("pid") is not None:
            by_pid.setdefault(event["pid"], []).append(event)
    for event in normalized:
        parents = by_pid.get(event.get("parent_pid")) or []
        if len(parents) == 1 and parents[0] is not event:
            parent = parents[0]
            event["parent_name"] = event.get("parent_name") or parent.get("name") or None
            event["parent_exe"] = event.get("parent_exe") or parent.get("exe") or None
            event["parent_cmdline"] = event.get("parent_cmdline") or parent.get("cmdline") or None
            event.setdefault("parent_process_start_time", parent.get("process_start_time"))
    return normalized


def check_support(rule: Any) -> tuple[bool, str]:
    """Can the engine execute the Sigma rule exactly as written? (one selection, field criteria)."""
    if not isinstance(rule, dict):
        return False, "Sigma phải là một mapping YAML"
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return False, "Thiếu khối detection"
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    if set(blocks) != {"selection"}:
        extra = sorted(set(blocks) - {"selection"})
        return False, ("Detection Engine chỉ hỗ trợ một khối 'selection'"
                       + (f"; không hỗ trợ: {', '.join(map(str, extra))}" if extra else ""))
    condition = str(detection.get("condition", "selection")).strip()
    if condition != "selection":
        return False, f"Detection Engine chỉ hỗ trợ condition 'selection', không hỗ trợ '{condition}'"
    selection = blocks["selection"]
    if not isinstance(selection, dict) or not selection:
        return False, "Khối selection phải là danh sách trường không rỗng (dạng keyword list chưa được hỗ trợ)"
    category = logsource_category(rule)
    if not any(kind in category for kind in ("process", "endpoint", "network", "file")):
        return False, f"Logsource '{category}' không có telemetry tương ứng trên Agent"
    for key, value in selection.items():
        parts = [part.strip().lower() for part in str(key).split("|")]
        unsupported = [m for m in parts[1:] if m not in SUPPORTED_MODIFIERS]
        if unsupported:
            return False, f"Modifier không được hỗ trợ: {', '.join(unsupported)} (trường {parts[0]})"
        if parts[0] not in FIELD_ALIASES:
            return False, f"Trường '{parts[0]}' không có trong telemetry của Agent"
        values = value if isinstance(value, list) else [value]
        if any(isinstance(v, (dict, list)) for v in values):
            return False, f"Giá trị lồng nhau cho trường '{parts[0]}' chưa được hỗ trợ"
    return True, "Detection Engine hỗ trợ rule này"


def logsource_category(rule: dict) -> str:
    logsource = rule.get("logsource") or {}
    return str(logsource.get("category") or logsource.get("product") or "process_creation").lower()


def match_field(key_spec: str, expected: Any, event: dict) -> bool:
    parts = key_spec.split("|")
    field_name = parts[0].strip().lower()
    modifiers = [m.strip().lower() for m in parts[1:]]
    actual_key = FIELD_ALIASES.get(field_name, field_name)
    actual_value = event.get(actual_key)
    if actual_value is None and actual_key in ("exe", "name"):
        actual_value = event.get("name") or event.get("exe")

    # An unknown parent never matches; low PIDs other than init are not traced.
    if actual_key in PARENT_KEYS:
        if actual_value is None or str(actual_value).strip().lower() in ("", "0", "none", "null", "unknown", "-1"):
            return False
        if actual_key == "parent_pid":
            try:
                val_int = int(actual_value)
                if val_int < 100 and val_int != 1 and str(expected).strip() not in (str(val_int), "systemd"):
                    return False
            except (ValueError, TypeError):
                pass
    if actual_value is None:
        return False

    actual_str = str(actual_value).lower()
    expected_str = str(expected).lower()
    for mod in modifiers:
        if mod == "contains" and expected_str not in actual_str:
            return False
        if mod == "endswith" and not actual_str.endswith(expected_str):
            return False
        if mod == "startswith" and not actual_str.startswith(expected_str):
            return False
        if mod in ("re", "regex"):
            try:
                if not re.search(str(expected), str(actual_value), re.IGNORECASE):
                    return False
            except re.error:
                return False
        if mod == "in":
            values = [str(x).lower() for x in actual_value] if isinstance(actual_value, list) else None
            if (expected_str not in values) if values is not None else (expected_str not in actual_str):
                return False
    if not modifiers:
        if isinstance(actual_value, (int, float)) and isinstance(expected, (int, float)):
            return actual_value == expected
        return actual_str == expected_str
    return True


def match_selection(selection: dict, event: dict) -> bool:
    for key, expected in selection.items():
        if isinstance(expected, list):
            if not any(match_field(key, v, event) for v in expected):
                return False
        elif isinstance(expected, dict):
            return False  # nested criteria unsupported: fail closed
        elif not match_field(key, expected, event):
            return False
    return True


def is_safe_process(event: dict) -> bool:
    """Process name in SAFE_PROCESSES and executable outside temporary directories."""
    if not isinstance(event, dict):
        return False
    proc_name = str(event.get("process_name") or event.get("name") or event.get("process")
                    or event.get("Image") or "").strip().lower()
    base_name = proc_name.replace("\\", "/").split("/")[-1]
    safe_set = {p.lower() for p in SAFE_PROCESSES}
    if base_name in safe_set or proc_name in safe_set:
        exe_path = str(event.get("exe") or event.get("exe_path") or event.get("path")
                       or event.get("Image") or "").strip().lower()
        if not any(exe_path.startswith(d) or f"{d}/" in exe_path for d in SUSPICIOUS_DIRS):
            return True
    return False


def is_reverse_shell_rule(mitre: Iterable[str], name: str) -> bool:
    if any(str(t).upper() in SHELL_TECHNIQUES for t in mitre or ()):
        return True
    lowered = (name or "").lower()
    return any(k in lowered for k in ("reverse shell", "unix shell", "command execution", "shell spawned",
                                      "interactive shell"))


def suppressed(rule: dict, event: dict, *, mitre=(), name="") -> bool:
    """Safe-process policy: common interpreters/shells are ignored unless the rule pins the parent
    (e.g. a web server spawning a shell) or it is a shell rule with a reverse-shell payload."""
    if not is_safe_process(event):
        return False
    selection = (rule.get("detection") or {}).get("selection") or {}
    if any(FIELD_ALIASES.get(str(k).split("|")[0].strip().lower()) in PARENT_KEYS for k in selection):
        return False
    if is_reverse_shell_rule(mitre, name) and any(
            re.search(pat, str(event.get("cmdline") or ""), re.IGNORECASE) for pat in REVERSE_SHELL_PAYLOAD):
        return False
    return True


def candidates(rule: dict, telemetry: dict) -> list[dict]:
    category = logsource_category(rule)
    procs = telemetry.get("process_list") or telemetry.get("processes") or []
    conns = telemetry.get("network_connections") or telemetry.get("conns") or []
    if "process" in category or "endpoint" in category:
        return normalize_snapshot(procs)
    if "network" in category:
        return [normalize_event(c) for c in conns if isinstance(c, dict)]
    if "file" in category:
        return [normalize_event(f) for f in (telemetry.get("file_changes") or telemetry.get("fim_alerts") or [])
                if isinstance(f, dict)]
    return normalize_snapshot(procs) + [normalize_event(c) for c in conns if isinstance(c, dict)]


def matching_events(rule: dict, events: list[dict], *, mitre=(), name="") -> list[dict]:
    """Events (already normalized) that the rule matches after the safe-process policy."""
    supported, _ = check_support(rule)
    if not supported:
        return []
    selection = rule["detection"]["selection"]
    return [event for event in events
            if match_selection(selection, event) and not suppressed(rule, event, mitre=mitre, name=name)]
