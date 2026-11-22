"""UFW transactions applied and recovered by a local systemd timer."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
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
from urllib.parse import quote, urlsplit

import psutil

from network_events import atomic_json, state_directory
from network_sources import CollectionError, read_setting, run, run_json, ufw_snapshot

TIMER = "larp-firewall-rollback.timer"
CONFIG_FILES = tuple(Path(entry) for entry in (
    "/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules",
))
STATIC_FILES = tuple(Path("/etc/ufw") / name for name in (
    "before.rules", "before6.rules", "before.init", "after.rules", "after6.rules", "after.init", "sysctl.conf",
))
EXPECTED_CONFIG = {"MANAGE_BUILTINS": "no", "IPV6": "yes", "IPT_SYSCTL": "/etc/ufw/sysctl.conf", "IPT_MODULES": ""}
IN_PROGRESS = {"queued", "applying", "awaiting_commit", "rolling_back"}
HEX_ID = re.compile(r"[0-9a-f]{32}")
MUTABLE_CONFIG_FILES = {"add_rule": {2, 3}, "delete_rule": {2, 3}, "enable": {1}, "disable": {1},
                             "reload": set(), "set_policy": {0}, "set_logging": {1}}
IO_ERRORS = (CollectionError, OSError, ValueError, http.client.HTTPException)


def _state_path():
    return state_directory() / "firewall-transaction.json"


@contextmanager
def firewall_lock():
    directory = state_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory / "firewall.lock", os.O_NOFOLLOW | os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
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


def _profile():
    if os.geteuid() or os.getenv("LARP_UFW_CONTROL") != "1":
        raise CollectionError("Local UFW control is not enabled")
    expected = os.getenv("LARP_UFW_STATIC_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != static_fingerprint():
        raise CollectionError("UFW static configuration does not match the locally reviewed profile")
    try:
        networks = [ipaddress.ip_network(part.strip()) for part in os.environ["LARP_UFW_SSH_CIDRS"].split(",")]
        port = int(os.getenv("LARP_UFW_SSH_PORT", "22"))
        timeout = int(os.getenv("LARP_UFW_ROLLBACK_SECONDS", "90"))
    except (KeyError, ValueError) as error:
        raise CollectionError("Invalid local SSH or rollback configuration") from error
    if not networks or any(net.prefixlen == 0 for net in networks) or not 1 <= port <= 65535 or not 60 <= timeout <= 300:
        raise CollectionError("Invalid local SSH or rollback configuration")
    for key, value in EXPECTED_CONFIG.items():
        if read_setting(str(CONFIG_FILES[0]), key) != value:
            raise CollectionError(f"UFW requires {key}={value} for scoped rollback")
    if read_setting(str(CONFIG_FILES[0]), "DEFAULT_OUTPUT_POLICY") != "ACCEPT":
        raise CollectionError("Management requires default outgoing ACCEPT")
    return networks, port, timeout


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
    for entry in entries:
        item = next((entry[k] for k in ("table", "chain", "rule", "set", "map", "flowtable") if k in entry), None)
        if not item:
            continue
        table = item.get("table") or item.get("name")
        family = item.get("family")
        if table == "nat" and family in {"ip", "ip6"}:
            continue  # UFW stock filter profile leaves guest NAT independently managed.
        if table != "filter" or family not in {"ip", "ip6"}:
            raise CollectionError(f"Independent firewall policy present ({family}/{table})")
        chain = item.get("chain") or (item.get("name") if "chain" in entry else None)
        if chain and chain not in builtin and not chain.startswith("ufw"):
            raise CollectionError("Independent filter chains are present")
        if "rule" in entry and chain in builtin:
            expressions = [expr for expr in item.get("expr", []) if "counter" not in expr]
            jump = expressions[0].get("jump") if len(expressions) == 1 else None
            if not isinstance(jump, dict) or not jump.get("target", "").startswith("ufw"):
                raise CollectionError("Independent filtering rules are present")
        if "chain" in entry and chain in builtin and item.get("policy") != "accept":
            if (active is False and not recovery) or (chain == "OUTPUT" and not recovery):
                raise CollectionError("An independent default policy could affect management")
    return entries


def _kernel_fingerprint(entries):
    normalized = []
    for entry in entries:
        for kind in ("table", "chain", "rule"):
            value = entry.get(kind)
            if not value or (value.get("table") or value.get("name")) != "filter":
                continue
            value = {key: item for key, item in value.items() if key != "handle"}
            if "expr" in value:
                value["expr"] = [expr for expr in value["expr"] if "counter" not in expr]
            normalized.append({kind: value})
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()


def _check_ssh_rules(networks, ssh_port):
    approved = set()
    for version, path in ((4, CONFIG_FILES[2]), (6, CONFIG_FILES[3])):
        text = _trusted_read(path)[0].decode()
        if any(line.startswith("*") and line != "*filter" for line in text.splitlines()):
            raise CollectionError("UFW user files must contain only filter rules")
        for line in text.splitlines():
            if not line.startswith("-A "):
                continue
            args = shlex.split(line)
            chain = args[1]
            if not chain.startswith(("ufw-user-", "ufw6-user-")):
                raise CollectionError("Unexpected chain in the UFW user configuration")
            if re.fullmatch(r"ufw6?-user-(output|forward)", chain):
                raise CollectionError("Custom outbound or forwarding rules require local administration")
            if not re.fullmatch(r"ufw6?-user-input", chain):
                continue
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
            if fields.get("-s") and "-i" not in fields and "-d" not in fields:
                approved.add(ipaddress.ip_network(fields["-s"], strict=False))
    if not set(networks) <= approved:
        raise CollectionError("The locally enrolled SSH CIDRs require explicit UFW allow rules")


def _manager_probe():
    manager = urlsplit(os.environ.get("MANAGER_URL", ""))
    token = os.environ.get("LARP_NETWORK_AGENT_TOKEN", "")
    agent_id = os.environ.get("AGENT_ID", socket.gethostname())
    if manager.scheme != "wss" or not manager.hostname or not token or manager.username:
        raise CollectionError("A TLS Manager URL and Agent credential are required")
    connection = http.client.HTTPSConnection(manager.hostname, manager.port or 443, timeout=4)
    try:
        prefix = manager.path.removesuffix("/ws/agent").rstrip("/")
        connection.request("GET", f"{prefix}/api/v1/network/agents/{quote(agent_id, safe='')}/probe",
                           headers={"X-LARP-Agent-Token": token, "Cache-Control": "no-cache"})
        if connection.getresponse().status != 204:
            raise CollectionError("Authenticated Manager probe failed")
    finally:
        connection.close()


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
        "enable": set(), "disable": set(), "reload": set(), "set_logging": {"logging"},
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
        direction = params["direction"]
        if direction not in {"incoming", "outgoing", "routed"} or action not in {"allow", "deny", "reject"}:
            raise CollectionError("Invalid default policy")
        if direction == "outgoing" and action != "allow":
            raise CollectionError("Outgoing policy must preserve Manager and DNS connectivity")
        return ["default", action, direction]
    if not active:
        raise CollectionError("UFW must be active to change rules remotely")
    if operation == "delete_rule":
        matching = [rule for rule in previous["rules"] if rule["id"] == params["rule_id"]]
        if len(matching) != 1 or matching[0]["management"] != "LARP":
            raise CollectionError("Only the exact LARP-managed rule can be deleted")
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
        return not any(rule.get("comment") == removed["comment"] and rule["family"] == removed["family"]
                       for rule in result["rules"])
    if operation == "set_policy":
        direction = params["direction"]
        configured = result.get("configured_defaults", result["defaults"]).get(direction)
        effective = result["defaults"].get(direction)
        return configured == params["action"] and effective in {
            params["action"], "disabled" if direction == "routed" else params["action"]
        }
    if operation == "set_logging":
        return params["logging"] in str(result["logging"]).lower()
    return operation == "reload" and current == "active"


def _result(state):
    result = {key: state[key] for key in ("id", "status", "expires_at", "error", "ssh_verified", "operation",
                                          "applied_at", "updated_at") if key in state}
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
    return os.getenv("LARP_UFW_CONTROL") == "1" and os.geteuid() == 0


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
                _profile()
                if not state.get("ssh_verified") or _now() >= state["deadline"]:
                    raise CollectionError("Fresh SSH verification or deadline is missing")
                if _fingerprint(_capture()) != state["after_hash"]:
                    raise CollectionError("UFW configuration changed during the transaction")
                kernel = _kernel_scope(state["after"]["status"] == "active")
                if _kernel_fingerprint(kernel) != state["after_kernel_hash"]:
                    raise CollectionError("UFW kernel rules changed during the transaction")
                _manager_probe()
                if _now() >= min(expires, state["deadline"]):
                    raise CollectionError("Firewall confirmation expired")
                snapshot = ufw_snapshot()
                if not _matches_operation(snapshot, state):
                    raise CollectionError("The current UFW state did not verify")
                _mark(state, "committed", after=snapshot, recent_commands=recent)
            return _result(state)
        if state.get("id") == command_id:
            return _result(state)
        if state.get("status") in IN_PROGRESS or state.get("status") == "rollback_failed":
            raise CollectionError("An earlier firewall transaction requires completion or local recovery")
        _, _, timeout = _profile()
        if run("systemctl", "is-active", TIMER) != "active" or run("systemctl", "is-enabled", TIMER) != "enabled":
            raise CollectionError("The independent UFW rollback timer must be active and enabled")
        deadline = _now() + timeout
        _mark({"id": command_id, "params": params, "command_expiry": expires, "boot_id": _boot(),
               "deadline": deadline, "expires_at": _iso(deadline), "recent_commands": recent}, "queued")
        return _result(_read_state())


def _apply(state):
    networks, ssh_port, _ = _profile()
    previous = ufw_snapshot()
    if previous["status"] not in {"active", "inactive"}:
        raise CollectionError("UFW state is unknown")
    kernel_before = _kernel_fingerprint(_kernel_scope(previous["status"] == "active"))
    _check_ssh_rules(networks, ssh_port)
    files = _capture()
    args = _command(state["params"], state["id"], previous, ssh_port)
    if state["params"]["operation"] == "delete_rule":
        state["deleted_rule"] = next(rule for rule in previous["rules"] if rule["id"] == state["params"]["rule_id"])
    _manager_probe()
    run("ufw", "--dry-run", *args, timeout=8)
    current_kernel = _kernel_fingerprint(_kernel_scope(previous["status"] == "active"))
    if _now() >= state["command_expiry"] or _fingerprint(_capture()) != _fingerprint(files) or current_kernel != kernel_before:
        raise CollectionError("Firewall command expired or host configuration changed")
    _mark(state, "applying", backup=files, before=previous, static_hash=static_fingerprint(),
          before_kernel_hash=kernel_before)
    try:
        run("ufw", *args, timeout=12)
    finally:
        _mark(state, "applying", after_hash=_fingerprint(_capture()),
              after_kernel_hash=_kernel_fingerprint(_kernel_scope(recovery=True)))
    actual = ufw_snapshot()
    _kernel_scope(actual["status"] == "active")
    _check_ssh_rules(networks, ssh_port)
    if not _matches_operation(actual, state):
        raise CollectionError("Requested firewall state could not be verified")
    _manager_probe()
    applied = _now()
    _mark(state, "awaiting_commit", after=actual, applied_at=_iso(applied), applied_epoch=applied)


def _rollback(state):
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
    if not expected:
        mutable = MUTABLE_CONFIG_FILES[state["params"]["operation"]]
        if any(current[str(path)] != state["backup"][str(path)]
               for index, path in enumerate(CONFIG_FILES) if index not in mutable):
            raise CollectionError("Unrelated UFW files changed during an interrupted apply")
    current_kernel = _kernel_fingerprint(_kernel_scope(recovery=True))
    expected_kernel = state.get("after_kernel_hash")
    if expected_kernel and _boot() == state["boot_id"] and not state.get("rollback_started") and current_kernel not in {
        expected_kernel, state.get("before_kernel_hash")
    }:
        raise CollectionError("UFW kernel rules changed independently. Local recovery is required.")
    _mark(state, "rolling_back", rollback_started=True, rollback_source=state.get("rollback_source", current))
    run("ufw", "--force", "disable", timeout=12)
    _restore(state["backup"])
    if state["before"]["status"] == "active":
        run("ufw", "--force", "enable", timeout=12)
    actual = ufw_snapshot()
    if actual["status"] != state["before"]["status"] or _fingerprint(_capture()) != _fingerprint(state["backup"]):
        raise CollectionError("Restored UFW configuration did not verify")
    _mark(state, "rolled_back", after=actual)


def worker():
    with firewall_lock():
        state = _read_state()
        status = state.get("status")
        if status == "queued":
            if _now() >= state["command_expiry"] or _boot() != state["boot_id"]:
                _mark(state, "failed", error="Firewall command expired before execution")
                return
            try:
                _apply(state)
                return
            except IO_ERRORS as error:
                if not state.get("backup"):
                    _mark(state, "failed", error=str(error)[:480])
                    return
                state["error"] = str(error)[:480]
        elif status == "awaiting_commit":
            if _now() < state["deadline"] and _boot() == state["boot_id"]:
                return
        elif status not in {"applying", "rolling_back"}:
            return
        try:
            _rollback(state)
        except IO_ERRORS as error:
            _mark(state, "rollback_failed", error=str(error)[:480])


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
        if state.get("id") != transaction_id or state.get("status") != "awaiting_commit" or _now() >= state["deadline"]:
            raise CollectionError("No active matching transaction")
        _require_live_ssh_approval(networks, ssh_port, state["applied_epoch"])
        _mark(state, "awaiting_commit", ssh_verified=True)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["fingerprint"]:
            print(static_fingerprint())
        elif sys.argv[1:] == ["worker"]:
            worker()
        elif len(sys.argv) == 3 and sys.argv[1] == "approve":
            approve(sys.argv[2])
        else:
            raise CollectionError("Use fingerprint, worker, or approve TRANSACTION_ID")
    except IO_ERRORS as error:
        sys.exit(str(error))
