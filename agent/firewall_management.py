"""Read-only discovery and validation of the endpoint's management paths."""
import ipaddress
import os
import re
import shlex
from urllib.parse import urlsplit

from network_sources import CollectionError, run


def manager_url():
    manager = urlsplit(os.environ.get("MANAGER_URL", ""))
    if manager.scheme != "wss" or not manager.hostname or manager.username or not (0 < (manager.port or 443) < 65536):
        raise CollectionError("A TLS Manager URL is required")
    return manager


def _socket_activation_ports():
    try:
        status = run("systemctl", "show", "ssh.socket", "--property=ActiveState", "--property=Listen", timeout=2)
    except CollectionError:
        return set()
    if "ActiveState=active" not in status.splitlines():
        return set()
    return {int(port) for port in re.findall(r":(\d+) \(Stream\)", status)}


def discover_ssh_port(networks):
    listeners = {}
    socket_ports = None
    for family in (4, 6):
        output = run("ss", f"-{family}", "-H", "-ltnpe", timeout=2)
        for line in output.splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) < 6 or fields[0] != "LISTEN":
                continue
            host, _, port = fields[3].rpartition(":")
            if not port.isdecimal():
                continue
            if not re.search(r'"sshd(?:-session)?",pid=\d+', fields[5]):
                if not re.search(r'"systemd",pid=1,fd=\d+', fields[5]):
                    continue
                if socket_ports is None:
                    socket_ports = _socket_activation_ports()
                if int(port) not in socket_ports:
                    continue
            host = host.strip("[]").split("%")[0]
            addr = ipaddress.ip_address(host if host != "*" else ("0.0.0.0" if family == 4 else "::"))
            if addr.is_loopback:
                continue
            versions = listeners.setdefault(int(port), set())
            versions.add(family)
            if family == 6 and addr.is_unspecified and "v6only:0" in fields[5]:
                versions.add(4)
    if len(listeners) != 1:
        raise CollectionError("Exactly one non-loopback SSH listening port must be identified for remote UFW control")
    port, families = next(iter(listeners.items()))
    if not {network.version for network in networks} <= families:
        raise CollectionError("SSH is not listening for every approved IP family")
    expected = os.getenv("LARP_UFW_SSH_PORT")
    if expected is not None and expected != str(port):
        raise CollectionError("Discovered SSH port differs from the enrolled port")
    return port


def validate_anchors(defaults, v4, v6, networks, ssh_port, manager_port):
    """Require exact first rules in both UFW before chains for the recovery traffic."""
    for v, text in ((4, v4), (6, v6)):
        prefix = "ufw-before" if v == 4 else "ufw6-before"
        actual = {direction: [] for direction in ("input", "output")}
        for line in text.splitlines():
            tokens = shlex.split(line, comments=True)
            if len(tokens) >= 2 and tokens[0] == "-A":
                for direction in actual:
                    if tokens[1] == f"{prefix}-{direction}":
                        actual[direction].append(tokens[2:])
        established = ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
        ssh = [["-s", str(network), "-p", "tcp", "--dport", str(ssh_port), "-j", "ACCEPT"]
               for network in networks if network.version == v]
        outgoing = [["-p", proto, "--dport", str(port), "-j", "ACCEPT"]
                    for proto, port in dict.fromkeys((("udp", 53), ("tcp", 53), ("tcp", manager_port)))]
        expected = {"input": [*ssh, established], "output": [established, *outgoing]}
        for direction, rules in expected.items():
            # SSH rules may be ordered independently of the environment variable.
            if direction == "input" and sorted(actual[direction][:len(ssh)]) != sorted(ssh):
                raise CollectionError(f"Missing first-position IPv{v} protected SSH allow rules")
            start = len(ssh) if direction == "input" else 0
            if actual[direction][start:len(rules)] != rules[start:]:
                raise CollectionError(f"Missing first-position IPv{v} protected {direction} rules")
    if defaults != "ACCEPT":
        raise CollectionError("Management requires default outgoing ACCEPT")
