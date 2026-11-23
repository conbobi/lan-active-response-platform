"""Exercise actual UFW with a TCP management listener on a private veth link."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


def test_ufw_enable_and_rollback_preserve_access_in_private_namespaces(tmp_path):
    if not all(shutil.which(name) for name in ("unshare", "nsenter", "mount", "ufw", "ip", "nft")):
        pytest.skip("UFW and Linux network namespace utilities are required")
    templates = Path("/usr/share/ufw")
    if not (templates / "before.rules").is_file():
        pytest.skip("UFW rule templates are unavailable")
    ns = ["unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "--mount-proc"]
    result = subprocess.run([*ns, "true"], capture_output=True, timeout=5)
    if result.returncode:
        pytest.skip("Private user, network and mount namespaces are unavailable")

    script = r"""
from contextlib import ExitStack
import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import firewall_control as control
from firewall_management import validate_anchors
from network_sources import CollectionError, run, ufw_snapshot

assert os.readlink("/proc/self/ns/net") != os.environ["HOST_NET"]
assert os.readlink("/proc/self/ns/mnt") != os.environ["HOST_MNT"]

scratch = Path(sys.argv[1])
os.umask(0o077)
os.environ["STATE_DIRECTORY"] = str(scratch / "state")
config = scratch / "ufw"
default = scratch / "default"
config.mkdir()
default.mkdir()
(config / "applications.d").mkdir()
for name in ("before.rules", "before6.rules", "after.rules", "after6.rules",
             "before.init", "after.init", "user.rules", "user6.rules"):
    shutil.copyfile(Path("/usr/share/ufw") / name, config / name)
(config / "ufw.conf").write_text("ENABLED=no\nLOGLEVEL=low\n")
(config / "sysctl.conf").write_text("# isolated test; no sysctl changes\n")
shutil.copyfile("/etc/default/ufw", default / "ufw")
runtime_path = scratch / "run"
runtime_path.mkdir()
(runtime_path / "lock").mkdir()
run("mount", "--make-rprivate", "/")
run("mount", "--bind", str(runtime_path), "/run")
run("mount", "--bind", str(config), "/etc/ufw")
run("mount", "--bind", str(default), "/etc/default")
run("ip", "link", "set", "lo", "up")

def terminate(process):
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=3)

with ExitStack() as cleanup:
    peer = subprocess.Popen(["unshare", "--net", sys.executable, "-u", "-c",
                             "import time; print('ready'); time.sleep(90)"], stdout=subprocess.PIPE, text=True)
    cleanup.callback(terminate, peer)
    assert peer.stdout.readline().strip() == "ready"
    run("ip", "link", "add", "larp0", "type", "veth", "peer", "name", "larp1")
    run("ip", "link", "set", "larp1", "netns", str(peer.pid))
    run("ip", "addr", "add", "192.0.2.10/24", "dev", "larp0")
    run("ip", "link", "set", "larp0", "up")

    def invoke_peer(*args):
        return run("nsenter", "--target", str(peer.pid), "--net", *args, timeout=2)

    invoke_peer("ip", "addr", "add", "192.0.2.9/24", "dev", "larp1")
    invoke_peer("ip", "addr", "add", "192.0.2.11/24", "dev", "larp1")
    invoke_peer("ip", "link", "set", "larp1", "up")
    listener = subprocess.Popen([sys.executable, "-u", "-c", (
        "import socket\ns=socket.socket(); s.bind(('192.0.2.10',2222)); s.listen(); print('ready')\n"
        "while True:\n c,_=s.accept(); c.sendall(b'SSH-test'); c.close()"
    )], stdout=subprocess.PIPE, text=True)
    cleanup.callback(terminate, listener)
    assert listener.stdout.readline().strip() == "ready"

    def dial(source):
        program = ("import socket; "
                   "s=socket.create_connection(('192.0.2.10',2222), 0.5, source_address=(%r, 0)); "
                   "assert s.recv(32)==b'SSH-test'" % source)
        invoke_peer(sys.executable, "-c", program)

    for version, path in ((4, config / "before.rules"), (6, config / "before6.rules")):
        prefix = "ufw" if version == 4 else "ufw6"
        anchors = []
        if version == 4:
            anchors.append(f"-A {prefix}-before-input -s 192.0.2.9/32 -p tcp --dport 2222 -j ACCEPT")
        for direction in ("input", "output"):
            anchors.append(f"-A {prefix}-before-{direction} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        for protocol, port in (("udp", 53), ("tcp", 53), ("tcp", 443)):
            anchors.append(f"-A {prefix}-before-output -p {protocol} --dport {port} -j ACCEPT")
        # Retain the stock housekeeping rules below the protected anchors.
        text = path.read_text()
        path.write_text(text.replace(f"-A {prefix}-before-input -i lo ", "\n".join(anchors) + f"\n-A {prefix}-before-input -i lo ", 1))

    network = ipaddress.ip_network("192.0.2.9/32")
    validate_anchors("ACCEPT", (config / "before.rules").read_text(), (config / "before6.rules").read_text(),
                     [network], 2222, 443)

    run("ufw", "allow", "80/tcp")  # Generates both user files while UFW is inactive.
    before = control._capture()
    clean = run("nft", "-j", "list", "ruleset")
    assert ufw_snapshot()["status"] == "inactive"
    assert run("nft", "-j", "list", "ruleset") == clean
    assert control._capture() == before
    dial("192.0.2.9")
    dial("192.0.2.11")

    # This OS sandbox cannot access xtables-legacy. Only that platform gate and the TLS verifier are simulated.
    def private_run(name, *args, **kwargs):
        if name in {"iptables-legacy-save", "ip6tables-legacy-save"}:
            return ""
        return run(name, *args, **kwargs)

    control.run = private_run
    control.discover_ssh_port = lambda networks: 2222  # A TCP test listener stands in for sshd.
    control._check_recovery_units = lambda: None
    os.environ.update(LARP_UFW_STATIC_SHA256=control.static_fingerprint(),
                      LARP_UFW_CONTROL="1", LARP_UFW_SSH_CIDRS=str(network), MANAGER_URL="wss://manager.invalid/ws/agent")
    run("nft", "add", "table", "ip", "nat")
    run("nft", "add", "chain", "ip", "nat", "DOCKER")
    nat_before = run("nft", "-j", "list", "table", "ip", "nat")
    control._manager_probe = lambda *args: dial("192.0.2.9")
    state = {"id": "f" * 32, "version": control.SAFETY_VERSION, "status": "queued", "boot_id": control._boot(),
             "params": {"operation": "enable"}, "command_expiry": time.time() + 45}
    control._write_state(state)
    control.apply_worker()
    assert control.read_transaction()["status"] == "awaiting_commit", control.read_transaction()
    assert ufw_snapshot()["status"] == "active"
    dial("192.0.2.9")
    try:
        dial("192.0.2.11")
    except CollectionError:
        pass
    else:
        raise AssertionError("SSH port was not protected by its approved CIDR")

    # Lose management connectivity after apply, while no Agent or Manager process is running here.
    def lost(*args):
        raise CollectionError("Manager disconnected")
    control._manager_probe = lost
    control.worker()
    assert control.read_transaction()["status"] == "rolled_back", control.read_transaction()
    assert ufw_snapshot()["status"] == "inactive"
    assert control._capture() == before
    assert run("nft", "-j", "list", "table", "ip", "nat") == nat_before
    dial("192.0.2.9")
    dial("192.0.2.11")
    # With an already-active baseline, a temporary disable must restore the original files and filter.
    run("ufw", "--force", "enable", timeout=8)
    active_backup = control._capture()
    state.update(id="e" * 32, status="queued", params={"operation": "disable"}, command_expiry=time.time() + 45)
    control._write_state(state)
    control._manager_probe = lambda *args: dial("192.0.2.9")
    control.apply_worker()
    assert control.read_transaction()["status"] == "awaiting_commit", control.read_transaction()
    assert ufw_snapshot()["status"] == "inactive"
    control._manager_probe = lost
    control.worker()
    assert control.read_transaction()["status"] == "rolled_back", control.read_transaction()
    assert ufw_snapshot()["status"] == "active"
    assert control._capture() == active_backup
    assert run("nft", "-j", "list", "table", "ip", "nat") == nat_before
    dial("192.0.2.9")

"""
    result = subprocess.run([*ns, sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True,
                            timeout=35, env={**os.environ, "PYTHONPATH": str(Path(__file__).parent),
                                             "HOST_NET": os.readlink("/proc/self/ns/net"), "HOST_MNT": os.readlink("/proc/self/ns/mnt")})
    assert result.returncode == 0, result.stderr + result.stdout
