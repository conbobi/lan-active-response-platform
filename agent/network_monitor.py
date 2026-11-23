"""Collect local sockets and Linux network state for Agent Details."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import os
import platform
import re
import socket
import threading
import time
import uuid

import psutil

from connection_tracker import ConnectionTracker
from network_events import collect_events
from network_sources import CollectionError, ROW_LIMIT, collect_firewall, run, run_json, stable_id


def _endpoint(value, family):
    host, _, port = value.rpartition(":")
    host = host.strip("[]").split("%")[0]
    return ("::" if family == "IPv6" else "0.0.0.0") if host in {"", "*"} else host, int(port) if port.isdecimal() else 0


def parse_ss(output, family):
    rows = []
    for line in output.splitlines():
        fields = line.split(maxsplit=6)
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            continue
        protocol, state, _, _, local, remote, *extra = fields
        local_ip, local_port = _endpoint(local, family)
        remote_ip, remote_port = _endpoint(remote, family)
        if not local_port:
            continue
        details = extra[0] if extra else ""
        inode = re.search(r"\bino:(\d+)", details)
        cookie = re.search(r"\bsk:([\da-f]+)", details)
        owners = re.findall(r"\bpid=(\d+),fd=(\d+)", details)
        rows.append({"protocol": protocol.upper(), "status": state, "family": family,
                     "src_ip": local_ip, "src_port": local_port, "dst_ip": remote_ip if remote_port else None,
                     "dst_port": remote_port or None, "owners": owners, "inode": inode[1] if inode else None,
                     "socket_id": f"{family}:{cookie[1]}" if cookie and cookie[1] != "0" else None})
        for counter in ("bytes_sent", "bytes_received"):
            match = re.search(rf"\b{counter}:(\d+)", details)
            if match:
                rows[-1][counter] = int(match[1])
    return rows


def _psutil_sockets():
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr:
            continue
        tcp = conn.type == socket.SOCK_STREAM
        rows.append({"protocol": "TCP" if tcp else "UDP", "status": {"ESTABLISHED": "ESTAB", "SYN_SENT": "SYN-SENT", "SYN_RECV": "SYN-RECV", "TIME_WAIT": "TIME-WAIT", "CLOSE_WAIT": "CLOSE-WAIT"}.get(conn.status, conn.status) if tcp else ("UNCONN" if not conn.raddr else "CONNECTED"),
                     "family": "IPv6" if conn.family == socket.AF_INET6 else "IPv4", "src_ip": conn.laddr.ip,
                     "src_port": conn.laddr.port, "dst_ip": conn.raddr.ip if conn.raddr else None,
                     "dst_port": conn.raddr.port if conn.raddr else None,
                     "owners": [(conn.pid, conn.fd)] if conn.pid and conn.fd >= 0 else [], "inode": None, "socket_id": None})
    return rows


def socket_rows(errors):
    try:
        return [row for flag, family in (("-4", "IPv4"), ("-6", "IPv6"))
                for row in parse_ss(run("ss", "-H", "-O", flag, "-tunapei"), family)]
    except (CollectionError, OSError) as error:
        errors["ss"] = str(error)
        return _psutil_sockets()


def _process(row, sample_started):
    if not row.get("owners"):
        return {"pid": None, "attribution": "unknown"}
    if not row.get("inode"):
        return {"pid": None, "attribution": "unverified_socket"}
    target = f"socket:[{row['inode']}]"
    candidates = {}
    socket_changed = False
    for pid_val, fd_val in row["owners"]:
        try:
            pid = int(pid_val)
            fd = int(fd_val)
            link = f"/proc/{pid}/fd/{fd}"
            proc = psutil.Process(pid)
            start = proc.create_time()
            if start > sample_started or os.readlink(link) != target:
                socket_changed = True
                continue
            with proc.oneshot():
                name = proc.name()
                try:
                    exe, owner = proc.exe(), proc.username()
                except psutil.AccessDenied:
                    exe, owner = None, None
            if psutil.Process(pid).create_time() == start and os.readlink(link) == target:
                candidates[pid] = {
                    "pid": pid, "process_start_time": start, "process_name": name[:120],
                    "exe_path": exe[:500] if exe else None, "process_owner": owner, "attribution": "inode_verified"
                }
        except (psutil.Error, OSError):
            continue
    if candidates:
        if len({pid for pid, _ in row["owners"]}) > 1:
            return {"pid": None, "attribution": "shared_socket", "holders": list(candidates.values())}
        return next(iter(candidates.values()))
    if socket_changed:
        return {"pid": None, "attribution": "socket_changed"}
    if len(row["owners"]) > 1:
        return {"pid": None, "attribution": "shared_socket"}
    return {"pid": None, "attribution": "unknown"}


def bind_scope(host):
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "Unknown"
    if addr.is_unspecified:
        return f"All IPv{addr.version} interfaces"
    if addr.is_loopback or (getattr(addr, "ipv4_mapped", None) and addr.ipv4_mapped.is_loopback):
        return "Loopback only"
    return "Specific interface"


class NetworkMonitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.tracker = ConnectionTracker(max_history=1000, include_loopback=True)
        self.sections = {}
        self.last_full = 0
        self.last_events = 0
        self.sockets_sampled = False

    def _sockets(self, errors):
        sample_started = time.time()
        rows = socket_rows(errors)
        counts = Counter()
        for row in rows:
            row["bind_scope"] = bind_scope(row["src_ip"])
            row["direction"] = {"SYN-SENT": "outbound", "SYN-RECV": "inbound"}.get(row["status"], "unknown")
            bound = row["status"] == "LISTEN" or row["protocol"] == "UDP"
            counts["ports"] += bound
            counts["tcp"] += row["protocol"] == "TCP" and bool(row["dst_ip"])
            counts["udp"] += row["protocol"] == "UDP"
            counts["active_view"] += bool(row["dst_ip"]) or row["status"] == "LISTEN"
            counts["non_loopback"] += bound and row["bind_scope"] != "Loopback only"
        ports, active, listeners = [], [], []
        rows.sort(key=lambda row: (row["protocol"], row["src_ip"], row["src_port"], row["dst_ip"] or "", row["dst_port"] or 0, row["socket_id"] or ""))
        for row in rows:
            is_port = row["status"] == "LISTEN" or row["protocol"] == "UDP"
            to_ports = is_port and len(ports) < ROW_LIMIT
            to_active = bool(row["dst_ip"]) and len(active) < ROW_LIMIT
            if not (to_ports or to_active):
                continue
            row.update(_process(row, sample_started))
            row.pop("owners")
            row["id"] = row["socket_id"] or stable_id(row["protocol"], row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"], row["inode"])
            if to_ports:
                ports.append(row)
            if to_active:
                active.append(row)
            elif row["status"] == "LISTEN":
                listeners.append(row)
        tracked = self.tracker.process_connections(active, preserve_direction=True, baseline=not self.sockets_sampled)
        self.sockets_sampled = True
        now = datetime.now(timezone.utc)
        groups = defaultdict(lambda: {"currently_observed": 0, "new_connections": 0, "processes": set(), "ports": set()})
        for row in rows:
            if row["dst_ip"]:
                group = groups[row["dst_ip"]]
                group["currently_observed"] += 1
                group["ports"].add(row["dst_port"])
                if row.get("pid"):
                    group["processes"].add(f"{row['process_name']} ({row['pid']})")
        for row in self.tracker.get_connection_history():
            if row["dst_ip"] not in groups:
                continue
            group = groups[row["dst_ip"]]
            group["new_connections"] += row["new_connection_count"]
            group.setdefault("first_seen", row["first_seen"])
            group["last_seen"] = max(group.get("last_seen", row["last_seen"]), row["last_seen"])
        for row in tracked:
            row["duration_seconds"] = round((now - datetime.fromisoformat(row["first_seen"])).total_seconds(), 1)
        groups = sorted(groups.items(), key=lambda item: (-item[1]["currently_observed"], item[0]))
        return counts, ports, (tracked + listeners)[:ROW_LIMIT], [dict(group, remote_ip=ip, processes=sorted(group["processes"])[:50],
                                           ports=sorted(group["ports"])[:100]) for ip, group in groups[:ROW_LIMIT]]

    def collect(self, agent_id, full=False, command_id=None):
        with self.lock:
            return self._collect(agent_id, full, command_id)

    def _collect(self, agent_id, full, command_id):
        stamp = datetime.now(timezone.utc).isoformat()
        base = {"agent_id": agent_id, "schema_version": 1, "timestamp": stamp, "collected_at": stamp,
                "snapshot_id": uuid.uuid4().hex, "platform": platform.system().lower(), "command_id": command_id}
        if base["platform"] != "linux":
            return dict(base, status="unsupported", sections={})
        now = time.monotonic()
        if full or not self.sections or now - self.last_full >= 120:
            self.last_full = now
            self._inventory(stamp)
        if full or not self.last_events or now - self.last_events >= 60:
            self.last_events = now
            self.sections["events"] = dict(collect_events(), collected_at=stamp)
        errors = {}
        try:
            counts, ports, active, groups = self._sockets(errors)
        except (CollectionError, OSError, psutil.Error) as error:
            errors["sockets"] = str(error)
            counts, ports, active, groups = {}, [], [], []
        self.sections["ports"] = {"rows": ports, "total": counts.get("ports"), "errors": errors, "collected_at": stamp}
        self.sections["connections"] = {"rows": active, "groups": groups, "total": counts.get("active_view"),
                                        "errors": errors, "collected_at": stamp}
        firewall = self.sections["firewall"]
        for row in ports:
            candidates = [item["id"] for item in firewall["rules"] if str(item.get("destination_port")) == str(row["src_port"])
                          and item.get("protocol") in {None, row["protocol"].lower()} and item.get("direction") in {None, "in"}]
            row["firewall_matches"] = candidates[:10]
        interfaces = self.sections["interfaces"]["rows"]
        gateways = [row for row in self.sections["routes"]["rows"] if row.get("dst") == "default"]
        primary = sorted((route for route in gateways if str(route.get("table", "main")) in {"main", "254"}),
                         key=lambda row: (row["family"] != "IPv4", row.get("metric", 0)))
        primary_if = primary[0].get("dev") if primary else None
        addresses = [(row.get("ifname"), addr) for row in interfaces for addr in row.get("addr_info", [])]
        private = []
        for family_if, addr in sorted(addresses, key=lambda pair: pair[0] != primary_if):
            ip = addr.get("local")
            if addr.get("family") == "inet" and ip and any(ipaddress.ip_address(ip) in network for network in PRIVATE_NETWORKS):
                private.append(ip)
        counters = psutil.net_io_counters()
        self.sections["overview"] = {
            "private_ipv4": private, "ipv6": [addr["local"] for _, addr in addresses if addr.get("family") == "inet6"],
            "gateways": gateways[:100], "primary_interface": primary_if,
            "listening_sockets": counts.get("ports"), "active_tcp_connections": counts.get("tcp"),
            "udp_sockets": counts.get("udp"), "non_loopback_services": counts.get("non_loopback"),
            "firewall_status": firewall["status"], "firewall_provider": firewall["provider"],
            "firewall_rule_count": firewall.get("rule_count") if firewall["provider"] != "unavailable" else None,
            "blocked_events": self.sections["events"]["blocked"], "rx_bytes": counters.bytes_recv if counters else None,
            "tx_bytes": counters.bytes_sent if counters else None, "external_reachability": "unverified",
            "aws_security_group": "Unknown / Not integrated", "aws_network_acl": "Unknown / Not integrated",
            "aws_vpc_routing": "Unknown / Not integrated", "aws_public_ip_translation": "Unknown / Not integrated",
            "collected_at": stamp,
        }
        partial = any(section.get("errors") for section in self.sections.values())
        return dict(base, status="partial" if partial else "ok", sections=self.sections.copy())

    def _inventory(self, stamp):
        def query(section, sources):
            rows, errors = [], {}
            for family, args in sources:
                try:
                    rows.extend(dict(item, **({"family": family} if family else {})) for item in run_json("ip", "-j", *args))
                except (CollectionError, OSError, TypeError, ValueError) as error:
                    errors[family or section] = str(error)
            result = {"rows": rows[:ROW_LIMIT], "total": len(rows), "errors": errors, "collected_at": stamp}
            self.sections[section] = result
            return result["rows"]
        interfaces = query("interfaces", [(None, ("addr", "show"))])
        counters = psutil.net_io_counters(pernic=True)
        for row in interfaces:
            row["admin_state"] = "UP" if "UP" in row.get("flags", []) else "DOWN"
            counter = counters.get(row["ifname"])
            if counter:
                row.update(rx_bytes=counter.bytes_recv, tx_bytes=counter.bytes_sent)
        for section, command in (("routes", ("route", "show", "table", "all")), ("policy", ("rule", "show")), ("neighbors", ("neigh", "show"))):
            query(section, [(family, (flag, *command)) for family, flag in (("IPv4", "-4"), ("IPv6", "-6"))])
        firewall, nat = collect_firewall()
        self.sections.update(firewall=dict(firewall, collected_at=stamp), nat=dict(nat, collected_at=stamp))


PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
