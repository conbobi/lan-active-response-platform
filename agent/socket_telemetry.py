"""Correlate observed Linux sockets with verified process instances."""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import logging
import os
import time

import psutil

from network_monitor import socket_rows

logger = logging.getLogger(__name__)
SHELLS = {"bash", "dash", "sh", "ash", "ksh", "zsh", "fish"}
SOCKET_LIMIT = 100
HOLDER_LIMIT = 16


def _optional(read, default=None):
    try:
        return read()
    except psutil.AccessDenied:
        return default


def _process(pid, sample_started):
    proc = psutil.Process(pid)
    with proc.oneshot():
        start = proc.create_time()
        if start > sample_started:
            raise psutil.NoSuchProcess(pid)
        ppid = proc.ppid()
        argv = _optional(proc.cmdline, [])
        attrs = {
            "pid": pid, "parent_pid": ppid, "process_start_time": start,
            "process_name": proc.name()[:128], "exe_path": (_optional(proc.exe, "") or "")[:1024],
            "cmdline": " ".join(argv)[:2048], "uid": _optional(lambda: proc.uids().real),
            "euid": _optional(lambda: proc.uids().effective), "username": (_optional(proc.username) or None),
            "terminal": _optional(proc.terminal),
            "interactive": any(arg == "-i" for arg in argv[1:]),
            "pty_requested": any("pty.spawn(" in arg for arg in argv[1:]),
        }
    if psutil.Process(pid).create_time() != start or proc.ppid() != ppid:
        raise psutil.NoSuchProcess(pid)
    return attrs


def _ancestry(child, cache=None):
    """Verified parent chain at observation time (a parent must have started before its child)."""
    ancestors = []
    seen = {child.get("pid")}
    for _ in range(8):
        pid = child.get("parent_pid")
        if not pid or pid in seen or child.get("process_start_time") is None:
            break
        try:
            key = (pid, child["process_start_time"])
            parent = cache[key] if cache is not None and key in cache else _process(pid, child["process_start_time"])
            if cache is not None:
                cache[key] = parent
        except (psutil.Error, OSError):
            break
        ancestors.append(parent)
        seen.add(pid)
        child = parent
    return ancestors


def _descendants(root, sample_started):
    descendants = []
    pending = [root]
    while pending and len(descendants) < 12:
        parent = pending.pop(0)
        try:
            proc = psutil.Process(parent["pid"])
            if proc.create_time() != parent["process_start_time"]:
                continue
            children = proc.children()[:12 - len(descendants)]
        except psutil.Error:
            continue
        for child in children:
            try:
                observed = _process(child.pid, sample_started)
            except (psutil.Error, OSError):
                continue
            if observed["parent_pid"] == parent["pid"] and observed["process_start_time"] >= parent["process_start_time"]:
                descendants.append(observed)
                pending.append(observed)
    return descendants


def socket_holders(row, sample_started, cache=None):
    if not row.get("inode") or row["inode"] == "0":
        return [], "unverified_socket"
    if not row["owners"]:
        return [], "owner_unavailable"

    descriptors = defaultdict(set)
    for pid, fd in row["owners"]:
        descriptors[int(pid)].add(int(fd))

    target = f"socket:[{row['inode']}]"
    holders = []
    denied = False
    for pid, fds in sorted(descriptors.items())[:HOLDER_LIMIT]:
        if pid == os.getpid():
            continue
        try:
            process = _process(pid, sample_started)
            stdio = set()
            for fd in range(3):
                try:
                    if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                        stdio.add(fd)
                except PermissionError:
                    denied = True
                except FileNotFoundError:
                    continue
            # Recheck a descriptor reported by ss after reading process metadata.
            verified = []
            for fd in sorted(fds | stdio):
                try:
                    if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                        verified.append(fd)
                except PermissionError:
                    denied = True
                except FileNotFoundError:
                    continue
            if not fds.intersection(verified):
                continue
            if psutil.Process(pid).create_time() != process["process_start_time"]:
                continue
            process["socket_fds"] = verified[:32]
            process["stdio_fds"] = sorted(stdio.intersection(verified))
            process["socket_stdio"] = 0 in process["stdio_fds"] and bool({1, 2}.intersection(process["stdio_fds"]))
            shell = os.path.basename(process["exe_path"]) in SHELLS
            # Parent chain for every verified holder: an orphaned payload keeps PPID 1 once its
            # launcher exits, so the chain must be captured while it still exists.
            process["ancestry"] = [{k: v for k, v in a.items() if k not in ("terminal",)}
                                   for a in _ancestry(process, cache)]
            if shell:
                process["descendants"] = _descendants(process, sample_started)
            holders.append(process)
        except (psutil.AccessDenied, PermissionError):
            denied = True
        except (psutil.NoSuchProcess, OSError):
            continue
    if holders and len(descriptors) > HOLDER_LIMIT:
        return holders, "holders_truncated"
    if holders:
        return holders, "inode_verified_partial" if denied or len(holders) != len(descriptors) else "inode_verified"
    return [], "access_denied" if denied else "owner_changed_or_exited"


def collect_connections(tracker, activity=None):
    started = time.time()
    observed_at = datetime.fromtimestamp(started, timezone.utc)
    if activity is not None:
        activity.update(version=1, captured_at=observed_at.isoformat(), complete=False)
    errors = {}
    try:
        rows = socket_rows(errors)
    except (psutil.Error, OSError) as error:
        logger.warning("Socket telemetry unavailable: %s", error)
        return []
    if errors:
        logger.debug("Socket telemetry fallback: %s", errors["ss"])

    try:
        interface_ips = defaultdict(set)
        for interface, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                interface_ips[address.address.split("%")[0]].add(interface)
    except OSError as error:
        logger.debug("Interface attribution unavailable: %s", error)
        interface_ips = {}

    listeners = {(row["family"], row["src_ip"], row["src_port"]) for row in rows if row["status"] == "LISTEN"}
    ancestry_cache = {}
    connections = []
    for row in rows:
        if not row["dst_ip"] or row["status"] == "LISTEN":
            continue
        try:
            remote = ipaddress.ip_address(row["dst_ip"])
        except ValueError:
            continue
        if getattr(remote, "ipv4_mapped", None):
            remote = remote.ipv4_mapped
        if remote.is_loopback or remote.is_unspecified or remote.is_multicast:
            continue
        holders, attribution = socket_holders(row, started, ancestry_cache)
        if row["owners"] and all(int(pid) == os.getpid() for pid, _ in row["owners"]):
            continue
        direction = {"SYN-SENT": "outbound", "SYN-RECV": "inbound"}.get(row["status"], "unknown")
        direction_basis = "handshake_state" if direction != "unknown" else None
        if direction == "unknown" and row["protocol"] == "TCP":
            wildcard = "::" if row["family"] == "IPv6" else "0.0.0.0"
            if any((row["family"], host, row["src_port"]) in listeners for host in (row["src_ip"], wildcard)):
                direction, direction_basis = "inbound", "local_listener"
            elif row["status"] == "ESTAB" and listeners:
                # An accepted TCP connection always uses a listening local port; without one we dialled out.
                direction, direction_basis = "outbound", "no_local_listener"
        interfaces = sorted(interface_ips.get(row["src_ip"], ()))
        owner = holders[0] if len(holders) == 1 and attribution == "inode_verified" else {}
        connections.append({
            **{key: value for key, value in row.items() if key != "owners"},
            "pid": owner.get("pid"), "parent_pid": owner.get("parent_pid"),
            "process_name": owner.get("process_name", "unknown"), "exe_path": owner.get("exe_path", ""),
            "process_start_time": owner.get("process_start_time"),
            "socket_stdio": owner.get("socket_stdio", False),
            # stdin+stdout bound to a network socket: a shell, or an interpreter acting as one, that dialled out.
            "is_suspicious": any(holder["socket_stdio"] and (os.path.basename(holder["exe_path"]) in SHELLS
                                                             or direction == "outbound") for holder in holders),
            "direction": direction, "direction_basis": direction_basis, "interfaces": interfaces,
            "overlay": "tailscale" if interfaces == ["tailscale0"] else None,
            "status": "ESTABLISHED" if row["status"] == "ESTAB" else row["status"],
            "holders": holders, "originator_pid": None, "attribution": attribution,
            "attribution_reason": "multiple_holders" if len(holders) > 1 else attribution,
            "observed_at": observed_at.isoformat(),
        })
    tracked = tracker.process_connections(connections, now_dt=observed_at, preserve_direction=True)
    tracked.sort(key=lambda event: (
        any(holder["socket_stdio"] for holder in event["holders"]),
        any(os.path.basename(holder["exe_path"]) in SHELLS for holder in event["holders"]),
        event["exe_path"].startswith(("/tmp/", "/dev/shm/", "/var/tmp/")),
    ), reverse=True)
    if activity is not None:
        activity["complete"] = not errors and len(tracked) <= SOCKET_LIMIT
    return tracked[:SOCKET_LIMIT]
