"""Host IP blocking with an nftables table owned by LARP (inet larp_blocklist).

Ownership: every rule LARP adds lives in its own table and carries a comment
``larp-block:<block_id>`` (or ``larp-verify:<unblock_id>:<deadline>``). Nothing outside this
table is read-modify-written; the system ruleset, UFW, Docker and Tailscale chains are untouched
and the table is never flushed. Unblock deletes only the rules of one block_id.

Safety: a target is refused when it is this host, loopback/link-local, a gateway or resolver, the
Manager (resolved and connected), Tailscale's resolver or any endpoint tailscaled is talking to,
the peer of an established SSH session, an endpoint of this Agent process, or inside
LARP_PROTECTED_CIDRS. The Manager must be reachable before a block and is re-checked after it; if
the management path broke, the rules just added are removed again.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

import psutil

from network_sources import CollectionError, run

TABLE = "larp_blocklist"
FAMILY = "inet"
CHAINS = ("input", "output")
PRIORITY = -160  # before the filter-priority chains of UFW/iptables-nft/Tailscale; policy accept
BLOCK_ID = re.compile(r"[0-9a-f]{32}\Z")
TAILSCALE_RESOLVERS = ("100.100.100.100", "fd7a:115c:a1e0::53")
VERIFY_WINDOW_MAX = 3600

Runner = Callable[..., str]


class Blocklist:
    def __init__(self, runner: Runner = run, manager_url: Optional[str] = None, websocket_peer=None,
                 probe: Optional[Callable[[], Dict[str, Any]]] = None):
        self.run = runner
        self.manager_url = manager_url or os.getenv("MANAGER_URL", "")
        self.websocket_peer = websocket_peer
        self.probe = probe or self.probe_manager

    # ── nftables primitives ─────────────────────────────────────────────────────────────────
    def _nft(self, *args, script: Optional[str] = None) -> str:
        if script is not None:
            return self.run("nft", "-f", "-", input_data=script.encode())
        return self.run("nft", *args)

    def ensure_table(self):
        lines = [f"add table {FAMILY} {TABLE}"]
        for chain in CHAINS:
            lines.append(f"add chain {FAMILY} {TABLE} {chain} {{ type filter hook {chain} priority {PRIORITY}; policy accept; }}")
        self._nft(script="\n".join(lines) + "\n")

    def rules(self) -> List[Dict[str, Any]]:
        try:
            data = json.loads(self._nft("-j", "list", "table", FAMILY, TABLE))
        except CollectionError as error:
            if "No such file" in str(error) or "does not exist" in str(error):
                return []
            raise
        except ValueError as error:
            raise CollectionError("nft: invalid JSON") from error
        out = []
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not isinstance(rule, dict) or rule.get("table") != TABLE:
                continue
            parsed = {"chain": rule.get("chain"), "handle": rule.get("handle"), "comment": rule.get("comment") or "",
                      "ip": None, "direction": None, "packets": 0, "bytes": 0, "verdict": None}
            for expr in rule.get("expr", []):
                match = expr.get("match") if isinstance(expr, dict) else None
                if match and isinstance(match.get("left"), dict) and "payload" in match["left"]:
                    field = match["left"]["payload"].get("field")
                    if field in ("saddr", "daddr") and isinstance(match.get("right"), str):
                        parsed["ip"], parsed["direction"] = match["right"], field
                if isinstance(expr, dict) and "counter" in expr:
                    parsed["packets"] = int(expr["counter"].get("packets", 0))
                    parsed["bytes"] = int(expr["counter"].get("bytes", 0))
                if isinstance(expr, dict) and ("drop" in expr or "reject" in expr or "accept" in expr):
                    parsed["verdict"] = next(k for k in ("drop", "reject", "accept") if k in expr)
            out.append(parsed)
        return out

    def _delete(self, rule):
        self._nft("delete", "rule", FAMILY, TABLE, rule["chain"], "handle", str(rule["handle"]))

    # ── safety ──────────────────────────────────────────────────────────────────────────────
    def manager_endpoint(self):
        url = urlsplit(self.manager_url)
        if not url.hostname:
            raise CollectionError("Manager URL unavailable")
        return url.hostname, url.port or (443 if url.scheme in ("wss", "https") else 80)

    def probe_manager(self) -> Dict[str, Any]:
        """TCP reachability of the Manager endpoint (the management path) from this host."""
        host, port = self.manager_endpoint()
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=4):
                return {"reachable": True, "endpoint": f"{host}:{port}", "ms": round((time.monotonic() - started) * 1000)}
        except OSError as error:
            return {"reachable": False, "endpoint": f"{host}:{port}", "error": type(error).__name__}

    def protected(self) -> Dict[str, str]:
        """Addresses that must never be blocked, with why."""
        out: Dict[str, str] = {}

        def add(value, reason):
            try:
                out.setdefault(str(ipaddress.ip_address(str(value).split("%")[0])), reason)
            except ValueError:
                pass

        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                add(address.address, "địa chỉ của chính máy này")
        try:
            for route in json.loads(self.run("ip", "-j", "route", "show", "default")):
                add(route.get("gateway"), "default gateway")
        except (CollectionError, ValueError):
            pass
        for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            try:
                for line in Path(path).read_text().splitlines():
                    if line.startswith("nameserver"):
                        add(line.split()[1], "DNS resolver")
            except (OSError, IndexError):
                continue
        try:
            host, port = self.manager_endpoint()
            for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                add(info[4][0], "Manager (kênh quản trị)")
        except (CollectionError, OSError):
            pass
        if isinstance(self.websocket_peer, tuple):
            add(self.websocket_peer[0], "đầu kết nối WebSocket tới Manager")
        for value in TAILSCALE_RESOLVERS:
            add(value, "Tailscale MagicDNS")
        ssh_ports, tailscaled = set(), set()
        for proc in psutil.process_iter(["pid", "name"]):
            name = (proc.info.get("name") or "")
            if name == "tailscaled":
                tailscaled.add(proc.info["pid"])
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError):
            connections = []
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.pid:
                try:
                    if psutil.Process(conn.pid).name() in ("sshd", "sshd-session"):
                        ssh_ports.add(conn.laddr.port)
                except psutil.Error:
                    continue
        for conn in connections:
            if not conn.raddr:
                continue
            if conn.pid in tailscaled:
                add(conn.raddr.ip, "Tailscale coordination/DERP đang kết nối")
            elif conn.pid == os.getpid():
                add(conn.raddr.ip, "kết nối của chính Agent")
            elif conn.status == psutil.CONN_ESTABLISHED and conn.laddr.port in ssh_ports:
                add(conn.raddr.ip, "phiên SSH quản trị đang mở")
        return out

    def refusal(self, ip: str) -> Optional[str]:
        address = ipaddress.ip_address(ip)
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            return "Địa chỉ đặc biệt (loopback/link-local/multicast) không được chặn"
        for cidr in filter(None, (c.strip() for c in os.getenv("LARP_PROTECTED_CIDRS", "").split(","))):
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return f"Nằm trong danh sách bảo vệ {cidr}"
            except ValueError:
                continue
        reason = self.protected().get(str(address))
        return f"Địa chỉ được bảo vệ: {reason}" if reason else None

    def sessions(self, ip: str) -> List[Dict[str, Any]]:
        out = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.raddr.ip == ip and conn.status == psutil.CONN_ESTABLISHED:
                    out.append({"pid": conn.pid, "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote_port": conn.raddr.port})
        except (psutil.Error, OSError):
            pass
        return out[:20]

    # ── operations ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _target(ip) -> str:
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError as error:
            raise CollectionError("Địa chỉ IP không hợp lệ (chỉ chấp nhận một host)") from error
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address)

    def _owned(self, rules, prefix, ident):
        return [r for r in rules if r["comment"] == f"{prefix}:{ident}" or r["comment"].startswith(f"{prefix}:{ident}:")]

    def block(self, block_id: str, ip: str) -> Dict[str, Any]:
        if not BLOCK_ID.fullmatch(str(block_id)):
            raise CollectionError("block_id không hợp lệ")
        ip = self._target(ip)
        family = "ip" if ipaddress.ip_address(ip).version == 4 else "ip6"
        existing = self._owned(self.rules(), "larp-block", block_id)
        if existing:  # idempotent replay: same block_id never adds rules twice
            return self._receipt("already_applied", block_id, ip, existing, self.probe(), self.probe())
        refusal = self.refusal(ip)
        if refusal:
            return {"status": "failed", "code": "PROTECTED_TARGET", "message": refusal, "ip": ip}
        before = self.probe()
        if not before.get("reachable"):
            return {"status": "failed", "code": "MANAGEMENT_UNVERIFIED", "ip": ip, "management_before": before,
                    "message": "Không xác minh được kênh quản trị tới Manager; không áp dụng chặn"}
        sessions_before = self.sessions(ip)
        self.ensure_table()
        comment = f"larp-block:{block_id}"
        self._nft(script="\n".join((
            f'add rule {FAMILY} {TABLE} input {family} saddr {ip} counter drop comment "{comment}"',
            f'add rule {FAMILY} {TABLE} output {family} daddr {ip} counter drop comment "{comment}"',
        )) + "\n")
        applied = self._owned(self.rules(), "larp-block", block_id)
        after = self.probe()
        if not after.get("reachable"):
            for rule in applied:
                self._delete(rule)
            left = self._owned(self.rules(), "larp-block", block_id)
            return {"status": "failed", "code": "CONNECTIVITY_GUARD_ROLLBACK", "ip": ip, "management_before": before,
                    "management_after": after, "rolled_back": not left,
                    "message": "Mất kết nối tới Manager sau khi chặn; đã gỡ rule vừa thêm"}
        receipt = self._receipt("applied", block_id, ip, applied, before, after)
        receipt["sessions_before"] = sessions_before
        return receipt

    def _receipt(self, outcome, block_id, ip, rules, before, after):
        chains = {r["chain"] for r in rules if r["verdict"] == "drop" and r["ip"] == ip}
        verified = set(CHAINS) <= chains
        return {
            "status": "success" if verified else "failed", "outcome": outcome, "block_id": block_id, "ip": ip,
            "backend": "nftables", "table": f"{FAMILY} {TABLE}",
            "rules": [{k: r[k] for k in ("chain", "handle", "comment", "packets", "bytes")} for r in rules],
            "rule_verified": verified, "chains": sorted(chains), "management_before": before, "management_after": after,
            "sessions_after": self.sessions(ip), "observed_at": time.time(),
            **({} if verified else {"code": "RULE_NOT_VERIFIED", "message": "Rule chặn không có đủ ở input và output"}),
        }

    def unblock(self, block_id: str, unblock_id: str, ip: str, verify_seconds: int = 300) -> Dict[str, Any]:
        if not BLOCK_ID.fullmatch(str(block_id)) or not BLOCK_ID.fullmatch(str(unblock_id)):
            raise CollectionError("block_id/unblock_id không hợp lệ")
        ip = self._target(ip)
        family = "ip" if ipaddress.ip_address(ip).version == 4 else "ip6"
        rules = self.rules()
        mine = self._owned(rules, "larp-block", block_id)
        for rule in mine:
            self._delete(rule)
        after = self.rules()
        remaining = self._owned(after, "larp-block", block_id)
        others = sorted({r["comment"].split(":", 1)[1] for r in after
                         if r["ip"] == ip and r["comment"].startswith("larp-block:") and r not in remaining})
        verify = None
        # Restoration can only be observed once no LARP rule still drops this address.
        if not remaining and not others and not self._owned(after, "larp-verify", unblock_id):
            deadline = int(time.time()) + max(30, min(int(verify_seconds), VERIFY_WINDOW_MAX))
            self.ensure_table()
            # Counter only (no verdict): counts packets from the client that now pass LARP's chain.
            self._nft(script=f'add rule {FAMILY} {TABLE} input {family} saddr {ip} counter '
                             f'comment "larp-verify:{unblock_id}:{deadline}"\n')
            verify = {"deadline": deadline}
        return {
            "status": "success" if not remaining else "failed", "block_id": block_id, "unblock_id": unblock_id, "ip": ip,
            "outcome": "removed" if mine else "already_removed", "removed_rules": len(mine),
            "rule_absent_verified": not remaining, "other_larp_blocks": others, "verification_counter": verify,
            "listening_tcp_ports": self.listening_ports(), "observed_at": time.time(),
            **({} if not remaining else {"code": "RULE_STILL_PRESENT", "message": "Rule vẫn còn sau khi gỡ"}),
        }

    def listening_ports(self) -> List[int]:
        try:
            return sorted({c.laddr.port for c in psutil.net_connections(kind="tcp") if c.status == psutil.CONN_LISTEN})[:64]
        except (psutil.Error, OSError):
            return []

    def status(self) -> Dict[str, Any]:
        """Current LARP rules with counters; expired verification counters are removed (after reporting)."""
        rules = self.rules()
        blocks: Dict[str, Dict[str, Any]] = {}
        verifies: Dict[str, Dict[str, Any]] = {}
        now = time.time()
        for rule in rules:
            if rule["comment"].startswith("larp-block:"):
                entry = blocks.setdefault(rule["comment"].split(":", 1)[1], {"ip": rule["ip"], "chains": [],
                                                                             "packets": 0, "bytes": 0})
                entry["chains"].append(rule["chain"])
                entry["packets"] += rule["packets"]
                entry["bytes"] += rule["bytes"]
            elif rule["comment"].startswith("larp-verify:"):
                _, unblock_id, deadline = (rule["comment"].split(":") + ["0"])[:3]
                verifies[unblock_id] = {"ip": rule["ip"], "packets": rule["packets"], "deadline": int(deadline or 0),
                                        "expired": int(deadline or 0) <= now}
                if int(deadline or 0) <= now:
                    self._delete(rule)
        for entry in blocks.values():
            entry["complete"] = set(CHAINS) <= set(entry["chains"])
            entry["sessions"] = len(self.sessions(entry["ip"])) if entry["ip"] else 0
        return {"backend": "nftables", "table_present": bool(rules) or self._table_present(), "blocks": blocks,
                "verifications": verifies, "listening_tcp_ports": self.listening_ports(), "observed_at": now}

    def _table_present(self) -> bool:
        try:
            return f"table {FAMILY} {TABLE}" in self._nft("list", "tables")
        except CollectionError:
            return False
