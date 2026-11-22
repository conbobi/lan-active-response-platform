"""P0 regression coverage. All mutations operate on fixture state or private namespaces."""
import ipaddress
import multiprocessing
import os
import signal
import time

import pytest

import firewall_control as control
from firewall_management import discover_ssh_port, validate_anchors
from network_sources import CollectionError, collect_firewall

NET = ipaddress.ip_network("192.0.2.9/32")
PORT = 2222
TX = "a" * 32
ESTABLISHED = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
OUTBOUND = ("-p udp --dport 53 -j ACCEPT", "-p tcp --dport 53 -j ACCEPT", "-p tcp --dport 443 -j ACCEPT")


def anchors(prefix, ssh=None):
    lines = [f"-A {prefix}-before-input {ESTABLISHED}"]
    if ssh:
        lines.insert(0, f"-A {prefix}-before-input -s {ssh} -p tcp --dport {PORT} -j ACCEPT")
    lines.extend(f"-A {prefix}-before-output {match}" for match in (ESTABLISHED, *OUTBOUND))
    return "\n".join(lines)


def test_discover_actual_ssh_port_and_validate_anchors(monkeypatch):
    monkeypatch.delenv("LARP_UFW_SSH_PORT", raising=False)
    def read(command, family, *_args, **_options):
        assert command == "ss"
        if family == "-6":
            return ""
        return 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=43,fd=3))'
    monkeypatch.setattr("firewall_management.run", read)
    assert discover_ssh_port([NET]) == PORT
    monkeypatch.setenv("LARP_UFW_SSH_PORT", "22")
    with pytest.raises(CollectionError, match="differs"):
        discover_ssh_port([NET])
    validate_anchors("ACCEPT", anchors("ufw", NET), anchors("ufw6"), [NET], PORT, 443)


@pytest.mark.parametrize("missing", ["ssh", "outgoing", "precedence"])
def test_missing_protected_rule_cannot_pass_preflight(missing):
    v4 = anchors("ufw", None if missing == "ssh" else NET)
    if missing == "precedence":
        v4 = "-A ufw-before-input -j DROP\n" + v4
    if missing == "outgoing":
        v4 = v4.replace(OUTBOUND[-1], "-j DROP")
    with pytest.raises(CollectionError, match="protected"):
        validate_anchors("ACCEPT", v4, anchors("ufw6"), [NET], PORT, 443)


def test_socket_activated_ssh_keeps_real_listener_port(monkeypatch):
    def read(command, *args, **_options):
        if command == "systemctl":
            return "Listen=[::]:2222 (Stream)\nActiveState=active"
        if args[0] == "-4":
            return ""
        return 'LISTEN 0 128 [::]:2222 [::]:* users:(("systemd",pid=1,fd=9)) v6only:0'
    monkeypatch.setattr("firewall_management.run", read)
    assert discover_ssh_port([NET]) == PORT


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_DIRECTORY", str(tmp_path / "state"))
    monkeypatch.setenv("LARP_UFW_STATIC_SHA256", "pinned")
    files = [tmp_path / key for key in ("defaults", "conf", "rules", "rules6")]
    for path in files:
        path.write_text("initial")
    files[1].write_text("ENABLED=no\n")
    runtime = tmp_path / "runtime"
    runtime.write_text("inactive")
    boot = ["old-boot"]
    now = [100]
    pending = []
    commands = []
    monkeypatch.setattr(control, "CONFIG_FILES", files)
    monkeypatch.setattr(control, "_boot", lambda: boot[0])
    monkeypatch.setattr(control, "_now", lambda: now[0])
    monkeypatch.setattr(control, "_profile", lambda: ([NET], PORT, 60))
    monkeypatch.setattr(control, "_check_recovery_units", lambda: None)
    monkeypatch.setattr(control, "static_fingerprint", lambda: "pinned")
    monkeypatch.setattr(control, "_kernel_scope", lambda *_, **__: [])
    monkeypatch.setattr(control, "_check_user_rules", lambda *_: None)
    monkeypatch.setattr(control, "_trusted_read", lambda path: (path.read_bytes(), 0o600))
    monkeypatch.setattr(control, "ufw_snapshot", lambda: {
        "status": runtime.read_text(), "rules": [], "defaults": {"outgoing": "allow"}, "logging": "off",
    })

    def run(name, *args, **_):
        commands.append((name, *args))
        if name == "systemctl":
            pending.append(args)
            return ""
        assert name == "ufw"
        if args in {("--force", "enable"), ("--force", "disable")}:
            state = control._read_state()
            assert state.get("backup") and state.get("deadline") == 160
            assert state["status"] in {"applying", "rolling_back"}
            enabled = args[-1] == "enable"
            files[1].write_text(f"ENABLED={'yes' if enabled else 'no'}\n")
            runtime.write_text("active" if enabled else "inactive")
        return ""

    def probe(networks, port, timeout=6):
        assert networks == [NET] and port == PORT and 0 < timeout <= 6
        if (tmp_path / "disconnected").exists():
            raise CollectionError("Management connection lost")
        return {"source": str(NET.network_address), "port": port}

    monkeypatch.setattr(control, "run", run)
    monkeypatch.setattr(control, "_manager_probe", probe)
    return tmp_path, runtime, boot, now, commands, files


def queue(operation="enable", **fields):
    return control.request(TX, {"operation": operation, "reason": "Regression", "confirmed": True, **fields}, 140)


def test_enable_requires_fresh_ssh_and_explicit_commit(host, monkeypatch):
    _, runtime, _, _, commands, _ = host
    assert queue()["status"] == "queued"
    assert runtime.read_text() == "inactive"
    control.apply_worker()
    assert runtime.read_text() == "active"
    assert control.read_transaction()["status"] == "awaiting_commit"
    assert commands == [("systemctl", "start", "--no-block", control.APPLY_SERVICE), ("ufw", "--force", "enable")]
    commit = {"operation": "commit", "reason": "Verified", "confirmed": True, "transaction_id": TX}
    with pytest.raises(CollectionError, match="SSH verification"):
        control.request("b" * 32, commit, 140)
    monkeypatch.setattr(control, "_require_live_ssh_approval", lambda networks, port, applied: (
        (networks, port, applied) == ([NET], PORT, 100) or pytest.fail("wrong discovered endpoint")
    ))
    control.approve(TX)
    assert control.request("b" * 32, commit, 140)["status"] == "committed"


def test_enable_with_no_ssh_allow_is_rejected_without_mutation(host, monkeypatch):
    def unprotected():
        validate_anchors("ACCEPT", anchors("ufw"), anchors("ufw6"), [NET], PORT, 443)
    monkeypatch.setattr(control, "_profile", unprotected)
    with pytest.raises(CollectionError, match="protected SSH"):
        queue()
    assert host[1].read_text() == "inactive"
    assert host[4] == []


@pytest.mark.parametrize("direction", ["incoming", "outgoing", "routed"])
def test_remote_default_policy_changes_are_rejected(host, direction):
    queue("set_policy", direction=direction, action="deny")
    control.apply_worker()
    assert control.read_transaction()["status"] == "failed"
    assert "local administration" in control.read_transaction()["error"]
    assert all(cmd[0] != "ufw" for cmd in host[4])


def test_delete_protected_ssh_rule_is_rejected():
    snapshot = {"status": "active", "rules": [{"id": "protected", "management": "LARP",
                                             "destination_port": str(PORT), "order": 1}]}
    with pytest.raises(CollectionError, match="SSH port is protected"):
        control._command({"operation": "delete_rule", "rule_id": "protected"}, TX, snapshot, PORT)


def test_disconnect_while_waiting_causes_immediate_rollback(host):
    directory, runtime, _, _, _, files = host
    original = {file: file.read_bytes() for file in files}
    queue()
    control.apply_worker()
    assert runtime.read_text() == "active"
    (directory / "disconnected").touch()
    control.worker()
    assert control.read_transaction()["status"] == "rolled_back"
    assert runtime.read_text() == "inactive"
    assert {file: file.read_bytes() for file in files} == original


def test_rollback_survives_agent_process_termination(host):
    context = multiprocessing.get_context("fork")
    def agent_process():
        queue()
        time.sleep(60)

    process = context.Process(target=agent_process)
    process.start()
    deadline = time.monotonic() + 5
    try:
        while control.read_transaction().get("status") != "queued" and time.monotonic() < deadline:
            time.sleep(0.01)
        control.apply_worker()
        _, runtime, _, now, _, _ = host
        assert runtime.read_text() == "active"
        assert control.read_transaction()["status"] == "awaiting_commit"
    finally:
        process.kill()
        process.join(5)
    assert process.exitcode == -signal.SIGKILL

    now[0] = 160
    independent = context.Process(target=control.worker)
    independent.start()
    independent.join(5)
    assert independent.exitcode == 0
    assert runtime.read_text() == "inactive"
    assert control.read_transaction()["status"] == "rolled_back"


def test_reboot_restores_files_before_ufw_and_never_replays(host):
    _, runtime, boot, _, commands, files = host
    queue()
    control.apply_worker()
    assert runtime.read_text() == "active"
    boot[0] = "new-boot"
    control.recover_boot()
    assert files[1].read_text() == "ENABLED=no\n"
    assert control.read_transaction()["status"] == "boot_restored"
    assert not any(cmd == ("ufw", "--force", "disable") for cmd in commands)
    runtime.write_text("inactive")  # The standard UFW unit starts using restored configuration.
    control.worker()
    control.apply_worker()
    assert control.read_transaction()["status"] == "rolled_back"
    assert commands.count(("ufw", "--force", "enable")) == 1


@pytest.mark.parametrize("reboot", [True, False])
def test_expired_and_rebooted_queued_commands_are_never_applied(host, reboot):
    _, runtime, boot, now, commands, _ = host
    queue()
    if reboot:
        boot[0] = "new-boot"
        control.recover_boot()
    else:
        now[0] = 141
    control.apply_worker()
    assert control.read_transaction()["status"] == "failed"
    assert runtime.read_text() == "inactive"
    assert all(cmd[0] != "ufw" for cmd in commands)


def test_capture_is_read_only_even_with_inactive_ufw(monkeypatch):
    commands = []
    def read(name, *args, **_):
        commands.append((name, *args))
        if name == "nft":
            return '{"nftables": []}'
        if name == "ufw":
            return "Status: inactive" if args[0] == "status" else "(None)"
        return "(nf_tables)" if args == ("-V",) else ""
    monkeypatch.setattr("network_sources.run", read)
    assert collect_firewall()[0]["status"] == "inactive"
    assert set(commands) <= {("nft", "-j", "list", "ruleset"), ("iptables", "-V"), ("ip6tables", "-V"),
                             ("iptables-save", "-c"), ("ip6tables-save", "-c"), ("ufw", "show", "added"),
                             ("ufw", "status", "verbose"), ("ufw", "status", "numbered")}


def test_failed_or_missing_recovery_units_never_dispatch(host, monkeypatch):
    def missing():
        raise CollectionError("Independent rollback unavailable")
    monkeypatch.setattr(control, "_check_recovery_units", missing)
    with pytest.raises(CollectionError, match="rollback unavailable"):
        queue()
    assert host[4] == []
