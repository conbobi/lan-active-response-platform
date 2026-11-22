from datetime import datetime, timezone
from pathlib import Path
import copy
import os
import shutil
import subprocess
import sys
import time

import pytest

import firewall_control as control
from connection_tracker import ConnectionTracker
from network_events import file_events, parse_firewall_event
from network_monitor import NetworkMonitor, _process, bind_scope, parse_ss
from network_sources import CollectionError, collect_firewall, iptables_rules, nft_rules, parse_ufw, parse_ufw_added, run
from network_channel import NetworkChannel


def test_ufw_active_status_and_rules():
    parsed = parse_ufw(
        "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)",
        "[ 1] 22/tcp                     ALLOW IN    192.0.2.5\n"
        "[ 2] 8443/tcp (v6)              REJECT IN   Anywhere (v6)  # larp-" + "a" * 32,
    )
    assert parsed["status"] == "active"
    assert parsed["defaults"] == {"incoming": "deny", "outgoing": "allow", "routed": "disabled"}
    assert parsed["rules"][0]["destination_port"] == "22"
    assert parsed["rules"][1]["family"] == "IPv6"
    assert parsed["rules"][1]["management"] == "LARP"


@pytest.mark.parametrize(("output", "expected"), [("Status: inactive", "inactive"), ("Status: active", "active"), ("invalid", "unknown")])
def test_ufw_empty_user_rules(output, expected):
    assert parse_ufw(output, f"{output}\n(None)") == {
        "provider": "ufw", "status": expected, "defaults": {}, "logging": None, "rules": [],
    }


def test_inactive_configured_rules_are_visible():
    assert not parse_ufw_added("Added user rules:\n(None)")
    rows = parse_ufw_added("ufw allow from 192.0.2.5 to any port 22 proto tcp\nufw allow 443/tcp")
    assert [(row["source"], row["destination_port"], row["protocol"]) for row in rows] == [
        ("192.0.2.5", "22", "tcp"), (None, "443", "tcp"),
    ]
    assert rows[0]["configured_only"]


def test_nftables_and_iptables_backend_detection(monkeypatch):
    def command(name, *args):
        if name == "nft":
            return '{"nftables":[{"chain":{"family":"inet","table":"local","name":"input","hook":"input","policy":"drop"}}]}'
        if name in {"iptables", "ip6tables"}:
            return "iptables 1.8.10 (legacy)"
        if name.endswith("-save"):
            return "*filter\n:INPUT ACCEPT [1:1]\nCOMMIT"
        raise CollectionError("UFW unavailable")
    monkeypatch.setattr("network_sources.run", command)
    firewall, _ = collect_firewall()
    assert firewall["kernel_backends"] == ["nftables", "iptables (legacy)"]
    assert firewall["kernel_policies"] == {"inet/local/input": "drop"}
    assert firewall["provider"] == "nftables"


def test_missing_utilities_and_separate_ufw_state(monkeypatch):
    def unavailable(*_):
        raise CollectionError("utility unavailable")
    monkeypatch.setattr("network_sources.run", unavailable)
    firewall, _ = collect_firewall()
    assert (firewall["provider"], firewall["status"], firewall["kernel_status"]) == ("unavailable", "unknown", "unknown")
    monkeypatch.setattr("network_sources.ufw_snapshot", lambda: parse_ufw("Status: inactive", ""))
    monkeypatch.setattr("network_sources.run_json", lambda *_: {
        "nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "policy": "drop"}}],
    })
    firewall, _ = collect_firewall()
    assert (firewall["status"], firewall["kernel_status"]) == ("inactive", "active")


def test_ss_listeners_udp_and_missing_owner():
    row, = parse_ss("tcp LISTEN 0 511 0.0.0.0:5000 0.0.0.0:* ino:123 sk:1", "IPv4")
    assert (row["src_port"], bind_scope(row["src_ip"])) == (5000, "All IPv4 interfaces")
    assert _process(row, time.time()) == {"pid": None, "attribution": "unknown"}
    row, = parse_ss("tcp LISTEN 0 511 [::]:22 [::]:* users:((\"sshd\",pid=123,fd=7)) ino:44 sk:2", "IPv6")
    assert (row["src_ip"], row["src_port"], row["owners"]) == ("::", 22, [("123", "7")])
    row, = parse_ss("udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*", "IPv4")
    assert row["status"] == "UNCONN"
    assert bind_scope(row["src_ip"]) == "Loopback only"


def test_descriptor_reuse_rejects_process_attribution(monkeypatch):
    row, = parse_ss("tcp LISTEN 0 511 [::]:22 [::]:* users:((\"sshd\",pid=123,fd=7)) ino:44 sk:2", "IPv6")
    monkeypatch.setattr("network_monitor.psutil.Process", lambda _: type("Proc", (), {"create_time": lambda _: 10})())
    monkeypatch.setattr("network_monitor.os.readlink", lambda _: "socket:[45]")
    assert _process(row, 11)["attribution"] == "socket_changed"
    assert _process(row, 9)["pid"] is None


def test_tracker_distinguishes_persistence_and_pid_reuse():
    tracker = ConnectionTracker()
    sample = {"pid": 7, "process_name": "daemon", "process_start_time": 10, "src_ip": "192.0.2.1",
              "src_port": 12345, "dst_ip": "203.0.113.3", "dst_port": 443}
    assert len(tracker.process_connections([sample, sample])) == 1
    assert tracker.process_connections([sample])[0]["observation_count"] == 2
    assert len(tracker.get_connection_history()) == 1
    assert tracker.process_connections([dict(sample, process_start_time=20)])[0]["is_new"]
    assert len(tracker.get_connection_history()) == 2


def test_multiple_default_routes_and_unknown_external_exposure(monkeypatch):
    def ip(*args):
        if "addr" in args:
            return [{"ifname": "ens5", "flags": ["UP"], "addr_info": [{"family": "inet", "local": "10.0.0.10"}]}]
        if "route" in args and "-4" in args:
            return [{"dst": "default", "gateway": "10.0.0.2", "dev": "ens5", "metric": 10},
                    {"dst": "default", "gateway": "10.1.0.1", "dev": "ens6", "metric": 100}]
        if "route" in args:
            return [{"dst": "default", "gateway": "fe80::1", "dev": "ens5"}]
        return []
    monkeypatch.setattr("network_monitor.run_json", ip)
    monkeypatch.setattr("network_monitor.run", lambda *_: "tcp LISTEN 0 5 0.0.0.0:5000 0.0.0.0:*")
    monkeypatch.setattr("network_monitor.collect_events", lambda: {"blocked": 0, "rows": []})
    monkeypatch.setattr("network_monitor.collect_firewall", lambda: ({"provider": "ufw", "status": "inactive", "rules": []}, {}))
    sections = NetworkMonitor().collect("agent")["sections"]
    overview = sections["overview"]
    assert len(overview["gateways"]) == 3
    assert overview["primary_interface"] == "ens5"
    assert overview["firewall_status"] == "inactive"
    assert overview["external_reachability"] == "unverified"
    assert overview["aws_security_group"] == "Unknown / Not integrated"


def test_dnat_snat_and_docker_ownership():
    table = "nat"
    document = {"nftables": [
        {"chain": {"family": "ip", "table": table, "name": "prerouting", "hook": "prerouting", "type": "nat"}},
        {"rule": {"family": "ip", "table": table, "chain": "prerouting", "handle": 8, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}},
            {"counter": {"packets": 6, "bytes": 60}}, {"dnat": {"addr": "10.0.0.2", "port": 80}},
        ]}},
    ]}
    _, rows, _ = nft_rules(document)
    assert rows[0]["destination_port"] == 8080
    assert rows[0]["translated_ip"] == "10.0.0.2"
    assert rows[0]["packets"] == 6
    _, rows, _ = iptables_rules(
        "*nat\n[1:60] -A DOCKER -p tcp --dport 5000 -j DNAT --to-destination 172.17.0.2:5000\n"
        "-A POSTROUTING -s 10.0.0.0/24 -j SNAT --to-source 192.0.2.1\n"
        "-A POSTROUTING -j MASQUERADE\n-A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080\nCOMMIT",
        "iptables (legacy)", "IPv4",
    )
    assert [(row["nat_type"], row["management"]) for row in rows] == [
        ("DNAT", "Docker"), ("SNAT", "Host"), ("MASQUERADE", "Host"), ("REDIRECT", "Host"),
    ]
    assert rows[1]["translated_ip"] == "192.0.2.1"
    assert rows[3]["translated_port"] == "8080"


def test_kernel_annotation_and_log_rotation(tmp_path):
    text = "[UFW BLOCK] IN=ens5 OUT= SRC=203.0.113.8 DST=10.0.0.2 PROTO=TCP SPT=42800 DPT=22"
    timestamp = "2026-11-22T00:01:09+00:00"
    event = parse_firewall_event(text, timestamp, "journal:one")
    assert (event["action"], event["destination_port"], event["in_interface"]) == ("DROP", 22, "ens5")
    assert parse_firewall_event(text.replace("SRC=203.0.113.8", "SRC=no"), timestamp, "journal:two") is None
    path = tmp_path / "ufw.log"
    path.write_text(f"{timestamp} host {text}\n")
    position, [row] = file_events(path, None)
    assert row["destination"] == "10.0.0.2"
    assert file_events(path, position)[1] == []
    path.rename(tmp_path / "ufw.log.1")
    with (tmp_path / "ufw.log.1").open("a") as handle:
        handle.write(f"{timestamp} host {text}\n")
    path.write_text(f"{timestamp} host {text.replace('DPT=22', 'DPT=443')}\n")
    _, rows = file_events(path, position)
    assert [row["destination_port"] for row in rows] == [22, 443]


@pytest.mark.parametrize("params", [
    {"port": 65536}, {"port": 0}, {"port": "80"}, {"port": 22}, {"port": 53},
    {"source": "192.0.2.0/33"}, {"source": "192.0.2.1;touch /tmp/invalid"},
    {"interface": "ens5;whoami"}, {"protocol": "tcp --force"}, {"action": "allow;id"},
])
def test_control_rejects_invalid_parameters(params):
    rule = {"operation": "add_rule", "port": 8443, "protocol": "tcp", "action": "allow", **params}
    with pytest.raises((CollectionError, ValueError)):
        control._command(rule, "a" * 32, {"status": "active", "rules": []}, 22)


def test_valid_args_and_allowlisted_interface(monkeypatch):
    monkeypatch.setattr(control.socket, "if_nameindex", lambda: [(2, "ens5")])
    args = control._command({"operation": "add_rule", "port": 8443, "protocol": "tcp", "action": "allow",
                             "source": "192.0.2.0/24", "interface": "ens5"}, "a" * 32,
                            {"status": "active", "rules": []}, 22)
    assert args == ["allow", "in", "on", "ens5", "proto", "tcp", "from", "192.0.2.0/24", "to", "any",
                    "port", "8443", "comment", "larp-" + "a" * 32]


@pytest.fixture
def local_state(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_DIRECTORY", str(tmp_path))
    monkeypatch.setattr(control, "_boot", lambda: "boot")
    monkeypatch.setattr(control, "_now", lambda: 100)
    return tmp_path


def test_duplicate_delivery_and_expiry(local_state, monkeypatch):
    monkeypatch.setattr(control, "_profile", lambda: ([], 22, 90))
    monkeypatch.setattr(control, "run", lambda name, option, *_: "active" if option == "is-active" else "enabled")
    params = {"operation": "enable", "reason": "approval", "confirmed": True}
    first = control.request("a" * 32, params, 130)
    assert control.request("a" * 32, params, 130) == first
    with pytest.raises(CollectionError, match="expired"):
        control.request("b" * 32, params, 90)
    with pytest.raises(CollectionError, match="earlier"):
        control.request("b" * 32, params, 130)


def test_worker_rolls_back_after_connectivity_failure(local_state, monkeypatch):
    inactive = {"status": "inactive", "rules": [], "defaults": {}, "logging": "off"}
    active = dict(inactive, status="active")
    configuration = {"enabled": "no"}
    commands = []
    def run_command(name, *args, **_):
        commands.append((name, *args))
        if args == ("--force", "enable"):
            configuration["enabled"] = "yes"
        if args == ("--force", "disable"):
            configuration["enabled"] = "no"
    def probe():
        if configuration["enabled"] == "yes":
            raise CollectionError("Manager unreachable")
    monkeypatch.setattr(control, "_profile", lambda: ([], 22, 90))
    monkeypatch.setattr(control, "_kernel_scope", lambda *_, **__: [])
    monkeypatch.setattr(control, "_check_ssh_rules", lambda *_: None)
    monkeypatch.setattr(control, "_capture", lambda: copy.deepcopy(configuration))
    monkeypatch.setattr(control, "_restore", configuration.update)
    monkeypatch.setattr(control, "static_fingerprint", lambda: "approved")
    monkeypatch.setattr(control, "_manager_probe", probe)
    monkeypatch.setattr(control, "ufw_snapshot", lambda: active if configuration["enabled"] == "yes" else inactive)
    monkeypatch.setattr(control, "run", run_command)
    control._write_state({"id": "a" * 32, "status": "queued", "boot_id": "boot", "deadline": 190,
                          "params": {"operation": "enable"}, "command_expiry": 130})
    control.worker()
    state = control.read_transaction()
    assert state["status"] == "rolled_back"
    assert state["error"] == "Manager unreachable"
    assert configuration["enabled"] == "no"
    assert commands == [("ufw", "--dry-run", "--force", "enable"), ("ufw", "--force", "enable"),
                        ("ufw", "--force", "disable")]


def test_expired_transaction_recovery_refuses_overwriting_external_change(local_state, monkeypatch):
    control._write_state({"id": "b" * 32, "status": "awaiting_commit", "boot_id": "boot", "deadline": 90,
                          "backup": {"config": "old"}, "static_hash": "pinned",
                          "after_hash": control._fingerprint({"config": "changed by LARP"})})
    monkeypatch.setattr(control, "_capture", lambda: {"config": "changed by local admin"})
    monkeypatch.setattr(control, "static_fingerprint", lambda: "pinned")
    control.worker()
    assert control.read_transaction()["status"] == "rollback_failed"
    assert "independently" in control.read_transaction()["error"]


def test_containment_is_protected(monkeypatch):
    monkeypatch.setattr(control, "run", lambda name, *_: "" if "legacy" in name else "(nf_tables)")
    monkeypatch.setattr(control, "run_json", lambda *_: {"nftables": [{"table": {"name": "larp_containment", "family": "inet"}}]})
    with pytest.raises(CollectionError, match="Independent firewall policy"):
        control._kernel_scope()


@pytest.mark.asyncio
async def test_network_ack_follows_correlated_snapshot():
    channel = NetworkChannel("test")
    async def send(message):
        messages.append(message)
    async def scan(send_message, command_id):
        snapshot = {"snapshot_id": "b" * 32, "command_id": command_id}
        await send_message({"type": "NETWORK_SNAPSHOT", "payload": snapshot})
        return snapshot
    channel._snapshot = scan
    messages = []
    command = {"agent_id": "test", "schema_version": 1, "command_id": "a" * 32, "action": "network_refresh",
               "expires_at": datetime.fromtimestamp(time.time() + 30, timezone.utc).isoformat()}
    await channel._handle(send, command)
    await channel._handle(send, command)
    assert [item["type"] for item in messages] == ["NETWORK_SNAPSHOT", "NETWORK_ACK"]
    assert messages[1]["payload"]["snapshot_id"] == messages[0]["payload"]["snapshot_id"]


def test_subprocess_output_timeout_and_shell_safety():
    assert run("printf", "%s", "$(false); invalid") == "$(false); invalid"
    with pytest.raises(CollectionError, match="output limit"):
        run("printf", "%s", "a" * 100, limit=10)
    with pytest.raises(CollectionError, match="timed out"):
        run("sleep", "1", timeout=0.01)


@pytest.mark.skipif(not shutil.which("unshare") or not shutil.which("nft"), reason="Network namespace tools unavailable")
def test_scoped_containment_preserves_independent_rules_in_namespace():
    if subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"], capture_output=True).returncode:
        pytest.skip("Unprivileged namespaces unavailable")
    code = """
import os
import tempfile
from commands.scoped_isolation import scoped_isolation
from network_sources import run, run_json

os.environ['STATE_DIRECTORY'] = tempfile.mkdtemp()
run('nft', 'add', 'table', 'inet', 'test_independent')
scoped_isolation('isolate', 'wss://127.0.0.1/ws/agent', None)
tables = lambda: {item['table']['name'] for item in run_json('nft', '-j', 'list', 'tables')['nftables'] if 'table' in item}
assert tables() == {'test_independent', 'larp_containment'}
scoped_isolation('unisolate', 'wss://127.0.0.1/ws/agent', None)
assert tables() == {'test_independent'}
"""
    result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable, "-c", code],
                            capture_output=True, text=True, timeout=10,
                            env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)})
    assert result.returncode == 0, result.stderr
