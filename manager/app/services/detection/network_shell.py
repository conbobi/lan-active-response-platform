"""Score observed shell and socket evidence without assigning a connection initiator."""
import hashlib
import ipaddress
import json
import posixpath

RULE_ID = "builtin_linux_network_shell"
SHELLS = {"bash", "dash", "sh", "ash", "ksh", "zsh", "fish"}
SHARED_IPV4 = ipaddress.ip_network("100.64.0.0/10")
SERVICE_PROCESSES = {"apache2", "httpd", "nginx", "php", "php-fpm", "gunicorn", "uwsgi", "flask"}


def connection_key(event):
    key = tuple(event.get(field) for field in ("protocol", "src_ip", "src_port", "dst_ip", "dst_port"))
    return key if all(value is None or type(value) in (str, int) for value in key) else None


def _address(value):
    if not isinstance(value, str):
        raise ValueError("Invalid socket address")
    address = ipaddress.ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def _identity(holder):
    pid = holder.get("pid")
    start = holder.get("process_start_time")
    path = holder.get("exe_path")
    return (type(pid) is int and 0 < pid < 2**31 and type(start) in (int, float)
            and 0 < start < 2**53 and isinstance(path, str) and path.startswith("/"))


def _process_snapshot(holder):
    return {
        "pid": holder["pid"], "parent_pid": holder.get("parent_pid"),
        "process_start_time": holder["process_start_time"], "exe_path": holder["exe_path"],
        "name": holder.get("process_name") or posixpath.basename(holder["exe_path"]),
        "cmdline": holder.get("cmdline"), "uid": holder.get("uid"),
        "terminal": holder.get("terminal"),
        "interactive": holder.get("interactive") is True, "pty_requested": holder.get("pty_requested") is True,
        "stdio_fds": holder.get("stdio_fds", []), "socket_fds": holder.get("socket_fds", []),
    }


def _related(holder, field):
    items = holder.get(field)
    if not isinstance(items, list):
        return []
    known = {holder["pid"]: holder["process_start_time"]}
    child = holder
    related = []
    for item in items[:12]:
        if not isinstance(item, dict) or not _identity(item) or item["pid"] in known:
            continue
        if field == "ancestry":
            if child.get("parent_pid") != item["pid"] or child["process_start_time"] < item["process_start_time"]:
                break
            child = item
        else:
            parent = item.get("parent_pid")
            if type(parent) is not int or parent not in known or known[parent] > item["process_start_time"]:
                continue
        known[item["pid"]] = item["process_start_time"]
        related.append(item)
    return related


def _classify_holder(event, holder):
    ancestry = _related(holder, "ancestry")
    descendants = _related(holder, "descendants")
    unexpected_parent = any(
        (name := posixpath.basename(item["exe_path"])) in SERVICE_PROCESSES
        or name.startswith(("python", "php"))
        for item in ancestry
    )
    python_relatives = [item for item in (*ancestry, *descendants)
                        if posixpath.basename(item["exe_path"]).startswith("python")]
    python_pids = {item["pid"] for item in python_relatives}
    pty = any(item.get("pty_requested") is True for item in python_relatives) or any(
        item.get("parent_pid") in python_pids and str(item.get("terminal") or "").startswith("/dev/pts/")
        and posixpath.basename(item["exe_path"]) in SHELLS for item in descendants
    )
    stdio = holder.get("stdio_fds")
    fds = holder.get("socket_fds")
    direct_stdio = (isinstance(stdio, list) and isinstance(fds, list)
                    and 0 in stdio and 0 in fds and any(fd in stdio and fd in fds for fd in (1, 2)))
    interactive = holder.get("interactive") is True
    outbound = event.get("direction") == "outbound"
    bidirectional = all(type(event.get(field)) is int and event[field] > 0 for field in ("bytes_sent", "bytes_received"))

    high = direct_stdio and (outbound or interactive or unexpected_parent or pty or bidirectional)
    if not high and not (direct_stdio or (interactive and (unexpected_parent or pty))):
        return None

    signals = [("Established TCP connection with a remote peer", 16), ("Shell holds the verified socket inode", 20)]
    for present, reason, points in (
        (direct_stdio, "Same socket on shell stdin and an output stream", 30),
        (interactive, "Interactive shell argument observed", 7),
        (unexpected_parent, "Interpreter or web-service ancestor observed", 8),
        (pty, "Python PTY request or related shell terminal observed", 7),
        (outbound, "Outbound handshake observed", 8),
        (bidirectional, "TCP byte counters observed in both directions", 4),
    ):
        if present:
            signals.append((reason, points))

    return {
        "classification": "High-Confidence Reverse Shell" if high else "Suspected Reverse Shell",
        "severity": "high" if high else "medium",
        "confidence": min(0.99, 0.90 + 0.03 * outbound + 0.02 * unexpected_parent + 0.02 * pty + 0.01 * bidirectional)
                      if high else (0.65 if direct_stdio else 0.55),
        "risk_score": min(100 if high else 69, sum(points for _, points in signals)),
        "signals": [{"reason": reason, "score": points} for reason, points in signals],
        "process": _process_snapshot(holder),
        "ancestry": [_process_snapshot(item) for item in ancestry],
        "descendants": [_process_snapshot(item) for item in descendants],
    }


def detect_network_shell(event):
    if not isinstance(event, dict) or event.get("protocol") != "TCP" or event.get("status") != "ESTABLISHED":
        return None
    if event.get("direction") == "inbound" or event.get("attribution") not in {
        "inode_verified", "inode_verified_partial", "holders_truncated",
    }:
        return None
    inode = event.get("inode")
    holders = event.get("holders")
    if (not isinstance(inode, str) or len(inode) > 20 or not inode.isascii()
            or not inode.isdecimal() or not inode.strip("0")):
        return None
    if not isinstance(holders, list):
        return None
    try:
        local, remote = _address(event["src_ip"]), _address(event["dst_ip"])
    except (KeyError, ValueError, TypeError):
        return None
    if any(address.is_loopback or address.is_unspecified or address.is_multicast for address in (local, remote)):
        return None
    if any(type(event.get(key)) is not int or not 0 < event[key] <= 65535 for key in ("src_port", "dst_port")):
        return None

    verified = [holder for holder in holders[:16] if isinstance(holder, dict) and _identity(holder)]
    matches = [match for holder in verified if holder["pid"] > 2 and posixpath.basename(holder["exe_path"]) in SHELLS
               and isinstance(holder.get("socket_fds"), list) and holder["socket_fds"]
               and (match := _classify_holder(event, holder))]
    if not matches:
        return None

    matches.sort(key=lambda match: (match["severity"] == "high", match["risk_score"]), reverse=True)
    best = matches[0]
    top_processes = [match["process"] for match in matches
                     if (match["severity"], match["risk_score"]) == (best["severity"], best["risk_score"])]
    identities = sorted({(proc["pid"], proc["process_start_time"]) for proc in top_processes})
    primary = best["process"] if len(identities) == 1 else None
    direction = event.get("direction", "unknown")
    network = {key: event[key] for key in (
        "src_port", "dst_port", "protocol", "status", "inode", "socket_id", "observed_at", "first_seen",
        "bytes_sent", "bytes_received", "observation_count", "attribution",
    ) if key in event}
    network.update(src_ip=str(local), dst_ip=str(remote), direction=direction,
                   pid=primary["pid"] if primary else None, process_name=primary["name"] if primary else "unknown",
                   process_start_time=primary["process_start_time"] if primary else None, originator_pid=None,
                   holders=[_process_snapshot(holder) for holder in verified])
    if event.get("overlay") == "tailscale" and event.get("interfaces") == ["tailscale0"]:
        network["overlay"] = "tailscale"
    if isinstance(remote, ipaddress.IPv4Address) and remote in SHARED_IPV4:
        network["category"] = "shared_cgnat"
    key = [RULE_ID, "TCP", str(local), event["src_port"], str(remote), event["dst_port"], identities]
    entity = hashlib.sha256(json.dumps(key, separators=(",", ":")).encode()).hexdigest()
    story = f'{best["classification"]}. TCP [{local}]:{event["src_port"]} → [{remote}]:{event["dst_port"]} ({direction}).'
    if primary:
        story += f' Socket holder: {primary["name"]} (PID {primary["pid"]}).'
    else:
        story += " Multiple shell holders have equally strong evidence."
    return {
        **best, "rule_id": RULE_ID, "entity": entity, "process": primary,
        "ancestry": best["ancestry"] if primary else [], "descendants": best["descendants"] if primary else [],
        "network": network, "story": story,
    }
