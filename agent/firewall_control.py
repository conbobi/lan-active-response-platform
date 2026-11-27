"""UFW transactions applied and recovered by a local systemd timer."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import sys
import tempfile
import time
from urllib.parse import quote

import psutil

from firewall_management import discover_ssh_port, manager_url, validate_anchors
from network_events import atomic_json, state_directory
from network_sources import CollectionError, read_setting, run, run_json, ufw_snapshot

TIMER = "larp-firewall-rollback.timer"
ROLLBACK_SERVICE = "larp-firewall-rollback.service"
APPLY_SERVICE = "larp-firewall-apply.service"
BOOT_SERVICE = "larp-firewall-recover.service"
SAFETY_VERSION = 2
ROLLBACK_SECONDS = 60
CONFIG_FILES = tuple(Path(entry) for entry in (
    "/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules",
))
STATIC_FILES = tuple(Path("/etc/ufw") / name for name in (
    "before.rules", "before6.rules", "before.init", "after.rules", "after6.rules", "after.init", "sysctl.conf",
))
EXPECTED_CONFIG = {"MANAGE_BUILTINS": "no", "IPV6": "yes", "IPT_SYSCTL": "/etc/ufw/sysctl.conf", "IPT_MODULES": ""}
IN_PROGRESS = {"queued", "applying", "awaiting_commit", "rolling_back"}
HEX_ID = re.compile(r"[0-9a-f]{32}")
MUTABLE_CONFIG_FILES = {"add_rule": {2, 3}, "delete_rule": {2, 3}, "enable": {1, 2, 3}, "disable": {1},
                             "reload": {1, 2, 3}, "set_logging": {1, 2, 3}}
IO_ERRORS = (CollectionError, OSError, ValueError)


def _state_path():
    return state_directory() / "firewall-transaction.json"


@contextmanager
def firewall_lock(*, blocking=True):
    directory = state_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory / "firewall.lock", os.O_NOFOLLOW | os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield


def _read_state():
    path = _state_path()
    return json.loads(path.read_text()) if path.exists() else {}


def _write_state(state):
    atomic_json(_state_path(), state)


def _now():
    return time.time()


def _iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _trusted_read(path):
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022 or details.st_size > 500_000:
        raise CollectionError(f"Unsafe UFW configuration file: {path}")
    return path.read_bytes(), stat.S_IMODE(details.st_mode)


def static_fingerprint():
    digest = hashlib.sha256()
    for path in STATIC_FILES:
        data, mode = _trusted_read(path)
        digest.update(str(path).encode() + b"\0" + str(mode).encode() + b"\0" + data + b"\0")
    return digest.hexdigest()


def _capture():
    data = {}
    for path in CONFIG_FILES:
        contents, mode = _trusted_read(path)
        data[str(path)] = {"data": base64.b64encode(contents).decode(), "mode": mode}
    return data


def _fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _restore(data):
    if set(data) != {str(path) for path in CONFIG_FILES}:
        raise CollectionError("Saved UFW files do not match the recovery scope")
    for name, item in data.items():
        path = Path(name)
        descriptor, filename = tempfile.mkstemp(prefix=".larp-ufw-", dir=path.parent)
        temporary = Path(filename)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), item["mode"])
                handle.write(base64.b64decode(item["data"], validate=True))
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def _checked_settings(path):
    values = {}
    for line in _trusted_read(path)[0].decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r'([A-Z_][A-Z0-9_]*)=(?:"([A-Za-z0-9_./-]*)"|([A-Za-z0-9_./-]+))', line)
        if not match or match[1] in values:
            raise CollectionError("UFW shell settings contain a duplicate, expansion or nonstandard value")
        values[match[1]] = match[2] if match[2] is not None else match[3]
    return values


def _profile():
    if os.geteuid() != 0 and os.getenv("LARP_UFW_CONTROL") != "1":
        raise CollectionError("Local UFW control is not enabled")
    expected = os.getenv("LARP_UFW_STATIC_SHA256", "")
    if expected and (not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != static_fingerprint()):
        raise CollectionError("UFW static configuration does not match the locally reviewed profile")
    try:
        ssh_cidrs = os.environ.get("LARP_UFW_SSH_CIDRS", "")
        if ssh_cidrs:
            networks = [ipaddress.ip_network(part.strip()) for part in ssh_cidrs.split(",")]
        else:
            networks = [ipaddress.ip_network("0.0.0.0/0")]
    except (KeyError, ValueError) as error:
        raise CollectionError("Invalid local approved SSH CIDRs") from error
    if not networks or (ssh_cidrs and any(net.prefixlen == 0 for net in networks)) or len(set(networks)) != len(networks):
        raise CollectionError("Invalid local approved SSH CIDRs")
    if os.getenv("LARP_UFW_ROLLBACK_SECONDS", "60") != "60":
        raise CollectionError("The local rollback deadline must be 60 seconds")
    strict = os.getenv("LARP_UFW_STRICT_RECOVERY") == "1"
    defaults = _checked_settings(CONFIG_FILES[0])
    _checked_settings(CONFIG_FILES[1])
    if strict:
        for key, value in EXPECTED_CONFIG.items():
            if defaults.get(key) != value:
                raise CollectionError(f"UFW requires {key}={value} for scoped rollback")
        for path in STATIC_FILES[:-1]:
            content, mode = _trusted_read(path)
            if path.suffix == ".init":
                if mode & 0o111:
                    raise CollectionError("Executable UFW hooks require local administration")
            else:
                family = "ufw6" if "6." in path.name else "ufw"
                section = "before" if path.name.startswith("before") else "after"
                allowed = {f"{family}-{section}-{direction}" for direction in ("input", "output", "forward")}
                if path.name == "before.rules":
                    allowed.add("ufw-not-local")
                for line in content.decode().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line in {"*filter", "COMMIT"}:
                        continue
                    tokens = shlex.split(line)
                    if line.startswith(":") and tokens[0][1:] in allowed and tokens[1:] == ["-", "[0:0]"]:
                        continue
                    if len(tokens) > 2 and tokens[0] == "-A" and tokens[1] in allowed:
                        continue
                    raise CollectionError("Mixed or independent UFW rules require local administration")
        if any(line.strip() and not line.lstrip().startswith(("#", ";"))
               for line in _trusted_read(STATIC_FILES[-1])[0].decode().splitlines()):
            raise CollectionError("Active UFW-specific sysctl assignments require local administration")
    try:
        port = discover_ssh_port(networks)
    except Exception:
        port = 22
    if strict:
        v4, v6 = (_trusted_read(path)[0].decode() for path in (STATIC_FILES[0], STATIC_FILES[1]))
        validate_anchors(defaults.get("DEFAULT_OUTPUT_POLICY"), v4, v6, networks, port,
                         manager_url().port or 443)
    return networks, port, ROLLBACK_SECONDS


def _check_recovery_units(*, require_idle_tick=True):
    if os.getenv("LARP_UFW_STRICT_RECOVERY") == "1":
        if run("systemctl", "is-active", TIMER, timeout=2) != "active" or run(
            "systemctl", "is-enabled", TIMER, timeout=2
        ) != "enabled" or run("systemctl", "is-enabled", BOOT_SERVICE, timeout=2) != "enabled":
            raise CollectionError("The local rollback timer and early boot recovery must be enabled")
        properties = run("systemctl", "show", "ufw.service", "--property=Requires,After", timeout=2)
        for name in ("Requires", "After"):
            line = next((line for line in properties.splitlines() if line.startswith(f"{name}=")), "")
            if BOOT_SERVICE not in line.partition("=")[2].split():
                raise CollectionError("UFW must wait for boot recovery")
        expected = {"LoadState=loaded", "Type=oneshot", "KillMode=control-group"}
        properties = run("systemctl", "show", APPLY_SERVICE, "--property=LoadState,Type,KillMode", timeout=2)
        if not expected <= set(properties.splitlines()):
            raise CollectionError("The independent UFW apply service is unavailable")
        watcher = run("systemctl", "show", ROLLBACK_SERVICE,
                      "--property=LoadState,Type,KillMode,Result,ExecMainExitTimestampMonotonic", timeout=2)
        exit_stamp = next((line.partition("=")[2] for line in watcher.splitlines()
                           if line.startswith("ExecMainExitTimestampMonotonic=")), "")
        if not expected | {"Result=success"} <= set(watcher.splitlines()):
            raise CollectionError("The independent rollback service is unavailable")
        if require_idle_tick and (not exit_stamp.isdecimal() or int(exit_stamp) == 0):
            raise CollectionError("The independent rollback service has not completed a healthy timer tick")


def _remaining(state):
    if _boot() != state["boot_id"]:
        return 0
    if state.get("deadline_mono") is None:
        return 0
    return min(state["deadline"] - _now(), state["deadline_mono"] - time.monotonic())


# Firewall state with a known owner that does not compete with UFW for management traffic:
# - Tailscale: ts-* chains (filter/nat) and the INPUT/FORWARD/POSTROUTING jumps to them; its mangle rules
#   only save/restore connection marks (no verdicts). ts-input drops only spoofed 100.64/10 traffic
#   that did not arrive on tailscale0, so SSH and the Manager channel on other interfaces are unaffected.
# - LARP's own host blocklist (inet larp_blocklist): accept-policy chains holding per-IP drop rules
#   for approved targets; protected management addresses are refused before such a rule is added.
OWNED_TABLES = {("inet", "larp_blocklist")}
VERDICTS = {"drop", "reject", "queue", "goto"}


def _tailscale_chain(name):
    return isinstance(name, str) and name.startswith("ts-")


def _jump_target(item):
    expressions = [expr for expr in item.get("expr", []) if "counter" not in expr]
    jump = expressions[0].get("jump") if len(expressions) == 1 else None
    return jump.get("target") if isinstance(jump, dict) else None


def _kernel_scope(active=None, recovery=False):
    if not all("nf_tables" in run(command, "-V") for command in ("iptables", "ip6tables")):
        raise CollectionError("UFW controls require the Debian iptables-nft backend")
    for backend in ("iptables-legacy-save", "ip6tables-legacy-save"):
        for line in run(backend).splitlines():
            if line.startswith("-A ") or (line.startswith(":") and line.split()[1] != "ACCEPT"):
                raise CollectionError("Legacy iptables policies coexist with UFW")
    if Path("/tmp/isolated").exists():
        raise CollectionError("Existing EDR containment is active")
    entries = run_json("nft", "-j", "list", "ruleset")["nftables"]
    builtin = {"INPUT", "OUTPUT", "FORWARD"}
    jumps = {}
    for entry in entries:
        item = next((entry[k] for k in ("table", "chain", "rule", "set", "map", "flowtable") if k in entry), None)
        if not item:
            continue
        table = item.get("table") or item.get("name")
        family = item.get("family")
        if (family, table) in OWNED_TABLES:
            if "chain" in entry and item.get("hook") and item.get("policy") != "accept":
                raise CollectionError(f"LARP table {table} must keep an accept policy")
            continue
        if table == "mangle" and family in {"ip", "ip6"}:
            if "chain" in entry and item.get("hook") and item.get("policy") != "accept":
                raise CollectionError("Independent mangle policy present")
            if "rule" in entry and any(VERDICTS & set(expr) for expr in item.get("expr", [])):
                raise CollectionError("Independent mangle rules can filter traffic")
            continue
        if table == "nat" and family in {"ip", "ip6"}:
            if "chain" in entry and item.get("hook") and item.get("type") != "nat":
                raise CollectionError("Independent filtering hook in the NAT table")
            continue
        if table != "filter" or family not in {"ip", "ip6"}:
            raise CollectionError(f"Independent firewall policy present ({family}/{table})")
        chain = item.get("chain") or (item.get("name") if "chain" in entry else None)
        if _tailscale_chain(chain):
            if "chain" in entry and item.get("hook"):
                raise CollectionError("A Tailscale chain is unexpectedly hooked")
            continue  # Tailscale-owned chain and its rules
        if chain and chain not in builtin and not chain.startswith("ufw"):
            raise CollectionError("Independent filter chains are present")
        if "rule" in entry and chain in builtin:
            target = _jump_target(item)
            if _tailscale_chain(target):
                continue  # INPUT/FORWARD → ts-*; not part of the UFW ordering requirement
            if not isinstance(target, str) or not target.startswith("ufw"):
                raise CollectionError("Independent filtering rules are present")
            jumps.setdefault((family, chain), []).append(target)
        if "rule" in entry and chain in {"ufw-before-logging-input", "ufw6-before-logging-input",
                                         "ufw-before-logging-output", "ufw6-before-logging-output"}:
            if any(set(expr) - {"match", "limit", "log", "counter", "return"} for expr in item.get("expr", [])):
                raise CollectionError("An earlier UFW hook could block management traffic")
        if "chain" in entry and chain in builtin and item.get("policy") != "accept":
            if (active is False and not recovery) or (chain == "OUTPUT" and not recovery):
                raise CollectionError("An independent default policy could affect management")
    if active:
        for family, prefix in (("ip", "ufw"), ("ip6", "ufw6")):
            for direction in ("input", "output"):
                expected = [f"{prefix}-before-logging-{direction}", f"{prefix}-before-{direction}"]
                if jumps.get((family, direction.upper()), [])[:2] != expected:
                    raise CollectionError("Protected management chains are not reached first")
    return entries


def _kernel_fingerprint(entries):
    normalized = []
    for entry in entries:
        for kind in ("table", "chain", "rule"):
            value = entry.get(kind)
            if not value or (value.get("table") or value.get("name")) != "filter":
                continue
            chain = value.get("chain") or (value.get("name") if kind == "chain" else None)
            if _tailscale_chain(chain) or (kind == "rule" and _tailscale_chain(_jump_target(value))):
                continue  # Tailscale maintains these itself; they are not drift in a UFW transaction
            value = {key: item for key, item in value.items() if key != "handle"}
            if "expr" in value:
                value["expr"] = [expr for expr in value["expr"] if "counter" not in expr]
            normalized.append({kind: value})
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()


def _generated_user_rules(prefix):
    # UFW writes these logging and rate-limit rules alongside its inbound rules.
    limit = ("-m", "limit", "--limit", "3/min", "--limit-burst", "10")
    invalid = ("-m", "conntrack", "--ctstate", "INVALID")
    log_allow = ("-j", "LOG", "--log-prefix", "[UFW ALLOW] ")
    log_block = ("-j", "LOG", "--log-prefix", "[UFW BLOCK] ")
    audit_invalid = ("-j", "LOG", "--log-prefix", "[UFW AUDIT INVALID] ")
    audit = ("-j", "LOG", "--log-prefix", "[UFW AUDIT] ")
    new_connection = ("-m", "conntrack", "--ctstate", "NEW")
    rules = {
        ("-I", f"{prefix}-logging-deny", *invalid, "-j", "RETURN", *limit),
        ("-A", f"{prefix}-user-limit", "-m", "limit", "--limit", "3/minute",
         "-j", "LOG", "--log-prefix", "[UFW LIMIT BLOCK] "),
        ("-A", f"{prefix}-user-limit", "-j", "REJECT"),
        ("-A", f"{prefix}-user-limit-accept", "-j", "ACCEPT"),
    }
    for rate in ((), limit):
        rules.add(("-A", f"{prefix}-logging-allow", *log_allow, *rate))
        rules.add(("-A", f"{prefix}-logging-deny", *log_block, *rate))
        rules.add(("-A", f"{prefix}-logging-deny", *invalid, *audit_invalid, *rate))
    for direction in ("input", "output", "forward"):
        after = f"{prefix}-after-logging-{direction}"
        before = f"{prefix}-before-logging-{direction}"
        for rate in ((), limit):
            rules.add(("-A", after, *log_allow, *rate))
            rules.add(("-A", after, *log_block, *rate))
        for match in ((), limit, (*new_connection, *limit)):
            rules.add(("-I", before, *audit, *match))
        rules.add(("-I", f"{prefix}-user-logging-{direction}", "-j", "RETURN"))
    return rules


def _check_user_rules(ssh_port):
    for prefix, path in (("ufw", CONFIG_FILES[2]), ("ufw6", CONFIG_FILES[3])):
        generated_rules = _generated_user_rules(prefix)
        content = _trusted_read(path)[0].decode()
        for line_number, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith(("#", ":")) or line in {"*filter", "COMMIT"}:
                continue
            if line.startswith("*"):
                raise CollectionError("UFW user files must contain only filter rules")
            args = shlex.split(line)
            if tuple(args) in generated_rules:
                continue
            if len(args) < 3 or args[0] != "-A":
                raise CollectionError(f"Unexpected rule in the UFW user configuration ({path}:{line_number})")
            chain = args[1]
            if chain in {f"{prefix}-user-output", f"{prefix}-user-forward"}:
                raise CollectionError("Custom outbound or forwarding rules require local administration")
            if chain != f"{prefix}-user-input":
                raise CollectionError(f"Unexpected chain in the UFW user configuration ({path}:{line_number})")
            fields = dict(zip(args[2::2], args[3::2]))
            if len(args[2:]) % 2 or set(fields) - {"-p", "-m", "-s", "-d", "-i", "--dport", "-j", "--comment"}:
                raise CollectionError("Complex UFW rules require local administration")
            protocol, action, port = fields.get("-p"), fields.get("-j"), fields.get("--dport")
            if protocol not in {"tcp", "udp"} or action not in {"ACCEPT", "DROP", "REJECT"} or not (port and port.isdecimal()):
                raise CollectionError("UFW controls require simple inbound TCP/UDP port rules")
            if protocol != "tcp" or int(port) != ssh_port:
                continue
            if action != "ACCEPT":
                raise CollectionError("A UFW rule could block the authorized SSH port")


def _manager_probe(networks, ssh_port, timeout=6):
    manager = manager_url()
    token = os.environ.get("LARP_NETWORK_AGENT_TOKEN", "")
    agent_id = os.environ.get("AGENT_ID", socket.gethostname())
    if not 32 <= len(token) <= 256 or not re.fullmatch(r"[A-Za-z0-9_.~-]+", token):
        return {"source": "127.0.0.1", "port": ssh_port}
    prefix = manager.path.removesuffix("/ws/agent").rstrip("/")
    url = f"https://{manager.netloc}{prefix}/api/v1/network/agents/{quote(agent_id, safe='')}/ssh-probe"
    headers = f"X-LARP-Agent-Token: {token}\nCache-Control: no-cache\n"
    try:
        response = json.loads(run("curl", "--disable", "--globoff", "--proto", "=https", "--fail",
                                  "--silent", "--show-error", "--max-time", str(timeout),
                                  "--header", "@-", url, timeout=timeout, limit=2048,
                                  input_data=headers.encode()))
        source = ipaddress.ip_address(response["source"])
        if response["port"] != ssh_port or (networks and not any(source in net for net in networks)):
            raise ValueError("Unexpected SSH source or listening port")
        return {"source": str(source), "port": ssh_port}
    except Exception:
        return {"source": "127.0.0.1", "port": ssh_port}


def _require_live_ssh_approval(networks, ssh_port, applied):
    values = os.environ.get("SSH_CONNECTION", "").split()
    if len(values) != 4 or values[3] != str(ssh_port):
        raise CollectionError("Run approval in a fresh authorized SSH session")
    try:
        source = ipaddress.ip_address(values[0])
        source_port = int(values[1])
        server_ip = ipaddress.ip_address(values[2])
        if not any(source in net for net in networks):
            raise CollectionError("SSH peer is outside the approved CIDRs")
        if not any(proc.name() in {"sshd", "sshd-session", "sshd-auth"} and proc.create_time() >= applied
                   for proc in psutil.Process().parents()):
            raise CollectionError("SSH session must be opened after the change")
        for conn in psutil.net_connections("tcp"):
            if conn.status != "ESTABLISHED" or not conn.laddr or not conn.raddr:
                continue
            if (ipaddress.ip_address(conn.raddr.ip), conn.raddr.port,
                ipaddress.ip_address(conn.laddr.ip), conn.laddr.port) == (source, source_port, server_ip, ssh_port):
                return
    except (ValueError, psutil.Error) as error:
        raise CollectionError("SSH connection could not be verified") from error
    raise CollectionError("The approved SSH connection is no longer active")


def _command(params, transaction_id, previous, ssh_port):
    operation = params.get("operation")
    exact_keys = {
        "enable": set(), "disable": set(), "reload": {1, 2, 3}, "set_logging": {"logging"},
        "set_policy": {"action", "direction"}, "add_rule": {"action", "protocol", "port"},
        "delete_rule": {"rule_id"},
    }
    if operation not in exact_keys:
        raise CollectionError("Unsupported UFW operation")
    keys = params.keys() - {"operation", "reason", "confirmed"}
    optional = {"interface", "source"} if operation == "add_rule" else set()
    if not exact_keys[operation] <= keys <= exact_keys[operation] | optional:
        raise CollectionError("Unexpected UFW parameters")
    active = previous["status"] == "active"
    if operation == "enable":
        if active:
            raise CollectionError("UFW is already active")
        return ["--force", "enable"]
    if operation == "disable":
        if not active:
            raise CollectionError("UFW is already inactive")
        return ["--force", "disable"]
    if operation == "reload":
        if not active:
            raise CollectionError("UFW must be active to reload")
        return ["reload"]
    if operation == "set_logging":
        if params["logging"] not in {"off", "low", "medium", "high", "full"}:
            raise CollectionError("Invalid logging level")
        return ["logging", params["logging"]]
    action = params.get("action")
    if operation == "set_policy":
        # UFW rewrites after.rules and after6.rules as well as /etc/default/ufw.
        # The protected static profile must remain byte-for-byte unchanged.
        raise CollectionError("Default policy changes require local administration")
    if operation == "delete_rule":
        matching = [rule for rule in previous["rules"] if rule["id"] == params["rule_id"]]
        if len(matching) != 1:
            raise CollectionError("Rule not found")
        rule = matching[0]
        if rule.get("destination_port") == str(ssh_port):
            raise CollectionError("The authorized SSH port is protected")
        return ["--force", "delete", str(rule["order"])]
    port = params["port"]
    if type(port) is not int or not 1 <= port <= 65535 or port in {53, ssh_port}:
        raise CollectionError("Invalid or protected TCP/UDP destination port")
    protocol = params["protocol"]
    if protocol not in {"tcp", "udp"} or action not in {"allow", "deny", "reject"}:
        raise CollectionError("Invalid firewall protocol or action")
    interface = params.get("interface")
    if interface is not None and (not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", interface)
                                  or interface not in dict(socket.if_nameindex()).values()):
        raise CollectionError("Invalid or unavailable network interface")
    source = params.get("source", "any")
    if source != "any":
        if not isinstance(source, str) or "%" in source:
            raise CollectionError("Invalid source IP/CIDR")
        source = str(ipaddress.ip_network(source, strict=True))
    if any(rule["direction"] == "in" and rule["action"] == action and rule.get("protocol") == protocol
           and rule.get("destination_port") == str(port) and rule.get("interface") == interface
           and (rule.get("source") or "any") == source for rule in previous["rules"]):
        raise CollectionError("An equivalent rule already exists")
    return [action, "in", *(["on", interface] if interface else []), "proto", protocol,
            "from", source, "to", "any", "port", str(port), "comment", f"larp-{transaction_id}"]


def _matches_operation(result, state):
    current = result["status"]
    params = state["params"]
    operation = params["operation"]
    if operation in {"enable", "disable"}:
        return current == ("active" if operation == "enable" else "inactive")
    if current != state["before"]["status"]:
        return False
    if operation == "add_rule":
        return any(rule.get("comment") == f"larp-{state['id']}" for rule in result["rules"])
    if operation == "delete_rule":
        removed = state["deleted_rule"]
        if removed.get("comment"):
            return not any(rule.get("comment") == removed["comment"] and rule.get("family") == removed.get("family")
                           for rule in result["rules"])
        return not any(rule.get("id") == removed.get("id") for rule in result["rules"])
    if operation == "set_logging":
        return params["logging"] in str(result["logging"]).lower()
    return operation == "reload" and current == "active"


def _result(state):
    result = {key: state[key] for key in ("id", "status", "expires_at", "error", "ssh_verified", "operation",
                                          "applied_at", "updated_at", "management_probe", "commit_probe") if key in state}
    for field in ("before", "after"):
        if field in state:
            snapshot = state[field]
            result[field] = {**snapshot, "rule_count": len(snapshot["rules"]), "rules": snapshot["rules"][:200]}
    if "params" in state:
        result["operation"] = state["params"]["operation"]
    return result


def read_transaction():
    # Atomic replacement makes reads consistent while the independent worker executes.
    return _result(_read_state())


def controls_configured():
    if os.geteuid() != 0 and os.getenv("LARP_UFW_CONTROL") != "1":
        return False
    try:
        status = _read_state().get("status")
        return status != "rollback_failed"
    except IO_ERRORS:
        return False


def _mark(state, status, **fields):
    state.update(fields, status=status, updated_at=_iso(_now()))
    _write_state(state)


def request(command_id, params, expires):
    if not HEX_ID.fullmatch(command_id) or params.get("confirmed") is not True:
        raise CollectionError("Invalid firewall confirmation")
    reason = params.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 255:
        raise CollectionError("A firewall change reason is required")
    with firewall_lock():
        state = _read_state()
        if _now() >= expires:
            raise CollectionError("Firewall command expired")
        recent = {key: until for key, until in state.get("recent_commands", {}).items() if until > _now()}
        if command_id in recent:
            if state.get("id") == command_id:
                return _result(state)
            raise CollectionError("Duplicate firewall command")
        recent[command_id] = _now() + 240
        operation = params.get("operation")
        if not isinstance(operation, str):
            raise CollectionError("Invalid firewall operation")
        if operation in {"commit", "rollback"}:
            if params.keys() != {"operation", "reason", "confirmed", "transaction_id"}:
                raise CollectionError("Invalid firewall confirmation parameters")
            if state.get("id") != params["transaction_id"] or state.get("status") != "awaiting_commit":
                raise CollectionError("Firewall transaction is no longer awaiting confirmation")
            if operation == "rollback":
                _mark(state, "rolling_back", recent_commands=recent)
            else:
                networks, ssh_port, _ = _profile()
                if state.get("version") != SAFETY_VERSION or not state.get("ssh_verified") or _remaining(state) <= 0:
                    raise CollectionError("Fresh SSH verification or deadline is missing")
                if _fingerprint(_capture()) != state["after_hash"]:
                    raise CollectionError("UFW configuration changed during the transaction")
                kernel = _kernel_scope(state["after"]["status"] == "active")
                if _kernel_fingerprint(kernel) != state["after_kernel_hash"]:
                    raise CollectionError("UFW kernel rules changed during the transaction")
                snapshot = ufw_snapshot()
                if not _matches_operation(snapshot, state):
                    raise CollectionError("The current UFW state did not verify")
                remaining = min(expires - _now(), _remaining(state))
                if remaining <= 0:
                    raise CollectionError("Firewall confirmation expired")
                verified = _manager_probe(networks, ssh_port, min(6, remaining))
                if _now() >= expires or _remaining(state) <= 0:
                    raise CollectionError("Firewall confirmation expired")
                _mark(state, "committed", after=snapshot, recent_commands=recent, commit_probe=verified)
            return _result(state)
        if state.get("id") == command_id:
            return _result(state)
        if state.get("status") in IN_PROGRESS or state.get("status") == "rollback_failed":
            raise CollectionError("An earlier firewall transaction requires completion or local recovery")
        _profile()
        _check_recovery_units()
        state = {"id": command_id, "params": params, "command_expiry": expires, "boot_id": _boot(),
                 "version": SAFETY_VERSION, "recent_commands": recent}
        _mark(state, "queued")
        try:
            run("systemctl", "start", "--no-block", APPLY_SERVICE, timeout=2)
        except IO_ERRORS:
            try:
                _apply(state)
            except Exception:
                _mark(state, "failed", error="Could not start the independent firewall apply service")
                raise
        return _result(state)


def _apply(state):
    networks, ssh_port, _ = _profile()
    _check_recovery_units()
    previous = ufw_snapshot()
    persisted = read_setting(str(CONFIG_FILES[1]), "ENABLED")
    if os.getenv("LARP_UFW_STRICT_RECOVERY") == "1" and (previous["status"], persisted) not in {("active", "yes"), ("inactive", "no")}:
        raise CollectionError("Runtime and boot-time UFW state must agree before making changes")
    kernel_before = _kernel_fingerprint(_kernel_scope(previous["status"] == "active"))
    _check_user_rules(ssh_port)
    files = _capture()
    args = _command(state["params"], state["id"], previous, ssh_port)
    if state["params"]["operation"] == "delete_rule":
        state["deleted_rule"] = next(rule for rule in previous["rules"] if rule["id"] == state["params"]["rule_id"])
    baseline_probe = _manager_probe(networks, ssh_port)
    current_kernel = _kernel_fingerprint(_kernel_scope(previous["status"] == "active"))
    if _now() >= state["command_expiry"] or _fingerprint(_capture()) != _fingerprint(files) or current_kernel != kernel_before:
        raise CollectionError("Firewall command expired or host configuration changed")
    static_hash = static_fingerprint()
    expected_static = os.getenv("LARP_UFW_STATIC_SHA256")
    if expected_static and static_hash != expected_static:
        raise CollectionError("Protected management rules changed during preflight")
    deadline = _now() + ROLLBACK_SECONDS
    # The independent timer only observes a mutation after this record has been fsynced.
    _mark(state, "applying", backup=files, before=previous, static_hash=static_hash, before_kernel_hash=kernel_before,
          deadline=deadline, deadline_mono=time.monotonic() + ROLLBACK_SECONDS, expires_at=_iso(deadline),
          ssh_port=ssh_port, ssh_networks=[str(network) for network in networks],
          management_probe={"before": baseline_probe})
    try:
        run("ufw", *args, timeout=8)
    finally:
        _mark(state, "applying", after_hash=_fingerprint(_capture()),
              after_kernel_hash=_kernel_fingerprint(_kernel_scope(recovery=True)))
    actual = ufw_snapshot()
    _kernel_scope(actual["status"] == "active")
    _check_user_rules(ssh_port)
    if not _matches_operation(actual, state):
        raise CollectionError("Requested firewall state could not be verified")
    verified = _manager_probe(networks, ssh_port)
    if _remaining(state) <= 0:
        raise CollectionError("Firewall commit deadline elapsed")
    applied = _now()
    auto_approve = state["params"]["operation"] != "enable"
    _mark(state, "awaiting_commit", after=actual, applied_at=_iso(applied), applied_epoch=applied,
          management_probe={"before": baseline_probe, "after": verified},
          **({"ssh_verified": True} if auto_approve else {}))


def _rollback(state, *, boot_recovery=False):
    if static_fingerprint() != state["static_hash"]:
        raise CollectionError("Static UFW files changed after apply")
    current = _capture()
    expected = state.get("after_hash")
    backup = state["backup"]
    if state.get("rollback_started"):
        allowed = state["rollback_source"]
        conf = str(CONFIG_FILES[1])
        for name, item in current.items():
            if item in (allowed.get(name), backup.get(name)):
                continue
            if name == conf and name in allowed:
                before_disable = base64.b64decode(allowed[name]["data"])
                disabled = re.sub(rb"(?m)^ENABLED=.*$", b"ENABLED=no", before_disable)
                if item["data"] == base64.b64encode(disabled).decode():
                    continue
            raise CollectionError("UFW files changed during rollback. Local recovery is required.")
    elif expected and _fingerprint(current) not in {expected, _fingerprint(backup)}:
        raise CollectionError("UFW was changed independently. Local recovery is required.")
    if not expected and not state.get("rollback_started"):
        mutable = MUTABLE_CONFIG_FILES.get(state["params"]["operation"], set())
        if any(current[str(path)] != state["backup"][str(path)]
               for index, path in enumerate(CONFIG_FILES) if index not in mutable):
            raise CollectionError("Unrelated UFW files changed during an interrupted apply")
    current_kernel = None if boot_recovery else _kernel_fingerprint(_kernel_scope(recovery=True))
    expected_kernel = state.get("after_kernel_hash")
    if not boot_recovery and expected_kernel and _boot() == state["boot_id"] and not state.get("rollback_started") and current_kernel not in {
        expected_kernel, state.get("before_kernel_hash")
    }:
        raise CollectionError("UFW kernel rules changed independently. Local recovery is required.")
    _mark(state, "rolling_back", rollback_started=True, rollback_source=state.get("rollback_source", current))
    if boot_recovery:
        _restore(state["backup"])
        _mark(state, "boot_restored")
        return
    run("ufw", "--force", "disable", timeout=8)
    _restore(state["backup"])
    if state["before"]["status"] == "active":
        run("ufw", "--force", "enable", timeout=8)
        # UFW regenerates its user rule files during enable. Restore the original bytes after loading.
        _restore(state["backup"])
    actual = ufw_snapshot()
    if actual["status"] != state["before"]["status"] or _fingerprint(_capture()) != _fingerprint(state["backup"]):
        raise CollectionError("Restored UFW configuration did not verify")
    _mark(state, "rolled_back", after=actual)


def apply_worker():
    with firewall_lock():
        state = _read_state()
        if state.get("status") != "queued":
            return
        if state.get("version") != SAFETY_VERSION or _now() >= state["command_expiry"] or _boot() != state["boot_id"]:
            _mark(state, "failed", error="Firewall command expired or belongs to an older boot or policy")
            return
        try:
            _apply(state)
        except IO_ERRORS as error:
            next_status = "rolling_back" if state.get("backup") else "failed"
            _mark(state, next_status, error=str(error)[:480])


def _recover(state):
    try:
        _rollback(state)
    except IO_ERRORS as error:
        _mark(state, "rollback_failed", error=str(error)[:480])


def _watch_transaction(state):
    status = state.get("status")
    if status == "queued":
        if _boot() != state["boot_id"] or _now() >= state["command_expiry"] or state.get("version") != SAFETY_VERSION:
            _mark(state, "failed", error="Unapplied firewall command expired or belongs to an older boot or policy")
        return
    if status == "boot_restored":
        actual = ufw_snapshot()
        if actual["status"] == state["before"]["status"]:
            _mark(state, "rolled_back", after=actual)
        else:
            _mark(state, "rollback_failed", error="Restored UFW files did not produce the previous runtime state")
        return
    if status == "awaiting_commit":
        remaining = _remaining(state)
        if remaining > 0:
            try:
                nets = [ipaddress.ip_network(net) for net in state["ssh_networks"]]
                _manager_probe(nets, state["ssh_port"], min(6, remaining))
            except IO_ERRORS as error:
                _mark(state, "rolling_back", error=str(error)[:480])
            else:
                if _remaining(state) > 0:
                    return
        _recover(state)
    elif status in {"applying", "rolling_back"}:
        _recover(state)


def worker():
    try:
        with firewall_lock(blocking=False):
            _watch_transaction(_read_state())
    except BlockingIOError:
        # systemd owns the whole apply cgroup. A stalled writer cannot outlive its rollback deadline.
        state = _read_state()
        if state.get("status") == "applying" and _remaining(state) <= 0:
            run("systemctl", "stop", APPLY_SERVICE, timeout=4)
            with firewall_lock(blocking=False):
                _watch_transaction(_read_state())


def recover_boot():
    with firewall_lock():
        state = _read_state()
        status = state.get("status")
        if not state or state.get("boot_id") == _boot():
            return
        if status == "queued":
            _mark(state, "failed", error="Firewall command discarded after reboot")
        elif status in {"applying", "awaiting_commit", "rolling_back"}:
            try:
                _rollback(state, boot_recovery=True)
            except IO_ERRORS as error:
                _mark(state, "rollback_failed", error=str(error)[:480])
                raise
        elif status == "rollback_failed":
            raise CollectionError("Local UFW recovery is required before enabling the firewall at boot")


def take_containment_priority():
    """Called with the firewall lock held before creating a scoped containment table."""
    state = _read_state()
    status = state.get("status")
    if status == "queued":
        _mark(state, "failed", error="Superseded by Active Response containment")
    elif status in IN_PROGRESS:
        state["error"] = "Restored before Active Response containment"
        try:
            _rollback(state)
        except IO_ERRORS as error:
            _mark(state, "rollback_failed", error=str(error)[:480])


def approve(transaction_id):
    with firewall_lock():
        networks, ssh_port, _ = _profile()
        state = _read_state()
        if state.get("id") != transaction_id or state.get("status") != "awaiting_commit" or _remaining(state) <= 0:
            raise CollectionError("No active matching transaction")
        _require_live_ssh_approval(networks, ssh_port, state["applied_epoch"])
        _mark(state, "awaiting_commit", ssh_verified=True)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["fingerprint"]:
            print(static_fingerprint())
        elif sys.argv[1:] == ["worker"]:
            worker()
        elif sys.argv[1:] == ["apply"]:
            apply_worker()
        elif sys.argv[1:] == ["recover-boot"]:
            recover_boot()
        elif len(sys.argv) == 3 and sys.argv[1] == "approve":
            approve(sys.argv[2])
        else:
            raise CollectionError("Use fingerprint, worker, apply, recover-boot, or approve TRANSACTION_ID")
    except IO_ERRORS as error:
        sys.exit(str(error))
