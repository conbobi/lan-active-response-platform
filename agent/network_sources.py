"""Bounded Linux command collection and firewall/NAT decoders."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import subprocess
import tempfile
import time

SEARCH_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ROW_LIMIT = 500


class CollectionError(RuntimeError):
    pass


def tool(name):
    return shutil.which(name, path=SEARCH_PATH)


def run(name, *args, timeout=4, limit=2_000_000, input_data=None):
    executable = tool(name)
    if executable is None:
        raise CollectionError(f"{name}: utility unavailable")
    with tempfile.TemporaryFile() as input_file:
        if input_data:
            input_file.write(input_data)
            input_file.seek(0)
        with subprocess.Popen(
            [executable, *args], shell=False, stdin=input_file if input_data else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": SEARCH_PATH, "LC_ALL": "C"},
        ) as process:
            try:
                buffers = {"output": bytearray(), "error": bytearray()}
                deadline = time.monotonic() + timeout
                size = 0
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, "output")
                    selector.register(process.stderr, selectors.EVENT_READ, "error")
                    while selector.get_map():
                        left = deadline - time.monotonic()
                        if left <= 0 or not (ready := selector.select(left)):
                            raise CollectionError(f"{name}: timed out")
                        for key, _ in ready:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            size += len(chunk)
                            if size > limit:
                                raise CollectionError(f"{name}: output limit exceeded")
                            buffers[key.data].extend(chunk)
                result = buffers["output"].decode("utf-8", "replace").strip()
                if process.wait(timeout=max(0.01, deadline - time.monotonic())):
                    error = buffers["error"].decode("utf-8", "replace").strip()
                    raise CollectionError(f"{name}: {(error or result)[:400] or 'command failed'}")
                return result
            except subprocess.TimeoutExpired as error:
                raise CollectionError(f"{name}: timed out") from error
            finally:
                if process.poll() is None:
                    process.kill()


def run_json(name, *args):
    try:
        return json.loads(run(name, *args))
    except ValueError as error:
        raise CollectionError(f"{name}: invalid JSON") from error


def stable_id(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:24]


def read_setting(path, key):
    try:
        for line in Path(path).read_text().splitlines():
            if line.startswith(f"{key}="):
                return line.partition("=")[2].strip().strip('"\'')
    except OSError:
        return None
    return None


def _ufw_endpoint(value):
    value = value.strip()
    interface = None
    if " on " in value:
        value, interface = value.rsplit(" on ", 1)
    if value == "Anywhere":
        return None, None, None, interface
    match = re.fullmatch(r"(\d+(?:[:,]\d+)*)(?:/(tcp|udp))?", value)
    if match:
        return None, match[1], match[2], interface
    return value, None, None, interface


def parse_ufw(verbose, numbered):
    status = re.search(r"^Status:\s*(active|inactive)\s*$", verbose, re.M)
    logging = re.search(r"^Logging:\s*(.+)$", verbose, re.M)
    defaults = dict((direction, action) for action, direction in re.findall(
        r"(\w+) \((incoming|outgoing|routed)\)", verbose.partition("Default:")[2].splitlines()[0]
        if "Default:" in verbose else "",
    ))
    rules = []
    for line in numbered.splitlines():
        match = re.match(r"^\[\s*(\d+)\]\s+(.*?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s{2,}(.*)$", line)
        if not match:
            continue
        order, destination, action, direction, source = match.groups()
        source, _, comment = source.partition(" # ")
        ipv6 = "(v6)" in destination or "(v6)" in source or ":" in source
        destination, dest_port, dest_proto, dest_if = _ufw_endpoint(destination.replace("(v6)", ""))
        source, source_port, source_proto, source_if = _ufw_endpoint(source.replace("(v6)", ""))
        rule = {
            "order": int(order), "provider": "ufw", "direction": (direction or "IN").lower(),
            "action": action.lower(), "protocol": dest_proto or source_proto,
            "source": source, "destination": destination, "source_port": source_port,
            "destination_port": dest_port, "interface": dest_if or source_if,
            "comment": comment.strip()[:256] or None, "family": "IPv6" if ipv6 else "IPv4",
            "management": "LARP" if re.fullmatch(r"larp-[0-9a-f]{32}", comment.strip()) else "Host",
        }
        rule["id"] = stable_id(rule)
        rules.append(rule)
    return {
        "provider": "ufw", "status": status[1] if status else "unknown",
        "logging": logging[1].strip() if logging else None, "defaults": defaults, "rules": rules,
    }


def parse_ufw_added(output):
    rules = []
    for line in output.splitlines():
        if not line.startswith("ufw "):
            continue
        try:
            tokens = shlex.split(line[4:])
        except ValueError:
            continue
        routed = tokens and tokens[0] == "route"
        if routed:
            tokens.pop(0)
        if not tokens or tokens[0] not in {"allow", "deny", "reject", "limit"}:
            continue
        action = tokens.pop(0)
        direction = "fwd" if routed else tokens.pop(0) if tokens and tokens[0] in {"in", "out"} else "in"

        def after(keyword):
            if keyword not in tokens or tokens.index(keyword) + 1 >= len(tokens):
                return None
            return tokens[tokens.index(keyword) + 1]

        source, destination = after("from"), after("to")
        source_port, dest_port = None, None
        for index, token in enumerate(tokens[:-1]):
            if token == "port":
                if "from" in tokens and ("to" not in tokens or index < tokens.index("to")):
                    source_port = tokens[index + 1]
                else:
                    dest_port = tokens[index + 1]
        protocol = after("proto")
        if not dest_port and tokens and not source and not destination:
            _, dest_port, short_protocol, _ = _ufw_endpoint(tokens[0])
            protocol = protocol or short_protocol
        interface, comment = after("on"), after("comment")
        rule = {"order": len(rules) + 1, "provider": "ufw", "direction": direction, "action": action,
                "source": None if source == "any" else source, "destination": None if destination == "any" else destination,
                "source_port": source_port, "destination_port": dest_port, "protocol": protocol,
                "interface": interface, "comment": comment, "family": "IPv6" if ":" in (source or "") or ":" in (destination or "") else None,
                "management": "LARP" if comment and re.fullmatch(r"larp-[0-9a-f]{32}", comment) else "Host",
                "configured_only": True, "match": line[:600]}
        rule["id"] = stable_id(rule)
        rules.append(rule)
    return rules


def ufw_snapshot():
    verbose = run("ufw", "status", "verbose")
    snapshot = parse_ufw(verbose, run("ufw", "status", "numbered"))
    if snapshot["status"] == "inactive":
        snapshot["rules"] = parse_ufw_added(run("ufw", "show", "added"))
    snapshot["ipv4"] = True
    ipv6 = read_setting("/etc/default/ufw", "IPV6")
    snapshot["ipv6"] = ipv6.lower() == "yes" if ipv6 else None
    snapshot["configured_defaults"] = {}
    for direction, key in (("incoming", "INPUT"), ("outgoing", "OUTPUT"), ("routed", "FORWARD")):
        value = read_setting("/etc/default/ufw", f"DEFAULT_{key}_POLICY")
        if value:
            policy = {"DROP": "deny", "ACCEPT": "allow", "REJECT": "reject"}.get(value)
            snapshot["configured_defaults"][direction] = policy
            snapshot["defaults"].setdefault(direction, policy)
    if snapshot["logging"] is None:
        snapshot["logging"] = read_setting("/etc/ufw/ufw.conf", "LOGLEVEL")
    modified = []
    for path in ("/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules"):
        try:
            modified.append(Path(path).stat().st_mtime)
        except OSError:
            continue
    snapshot["configuration_mtime"] = max(modified, default=None)
    return snapshot


def _atom(value):
    if isinstance(value, dict) and "prefix" in value:
        return f"{value['prefix']['addr']}/{value['prefix']['len']}"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)[:300]
    return value


def nft_rules(document):
    entries = document.get("nftables", [])
    chains = {(c["family"], c["table"], c["name"]): c for row in entries if (c := row.get("chain"))}
    filters, nat = [], []
    for entry in entries:
        rule = entry.get("rule")
        if not rule:
            continue
        family, table, chain = (rule[key] for key in ("family", "table", "chain"))
        hook = chains.get((family, table, chain), {}).get("hook")
        parsed = {
            "id": f"{family}/{table}/{chain}/{rule.get('handle')}", "provider": "nftables",
            "family": family, "table": table, "chain": chain, "hook": hook,
            "order": len(filters) + len(nat) + 1, "handle": rule.get("handle"),
            "direction": {"input": "in", "output": "out", "forward": "fwd"}.get(hook),
            "comment": rule.get("comment"),
            "management": "Docker" if "docker" in f"{table}/{chain}".lower() else
                          "EDR" if table == "larp_containment" else "Host",
        }
        details = []
        for expression in rule.get("expr", []):
            if "match" in expression:
                match = expression["match"]
                left = match.get("left", {})
                right = _atom(match.get("right"))
                payload = left.get("payload", {})
                field, protocol = payload.get("field"), payload.get("protocol")
                key = {"saddr": "source", "daddr": "destination", "sport": "source_port", "dport": "destination_port"}.get(field)
                if key and match.get("op") in {"==", "in"}:
                    parsed[key] = right
                    if protocol in {"tcp", "udp", "sctp"}:
                        parsed["protocol"] = protocol
                meta = left.get("meta", {}).get("key")
                if meta in {"iifname", "oifname"} and match.get("op") in {"==", "in"}:
                    parsed["interface"] = right
                if meta == "l4proto" and match.get("op") == "==":
                    parsed["protocol"] = right
            for action in ("accept", "drop", "reject", "jump", "goto", "dnat", "snat", "masquerade", "redirect"):
                if action not in expression:
                    continue
                parsed["action"] = action
                if action in {"dnat", "snat", "masquerade", "redirect"}:
                    translation = expression[action] or {}
                    parsed.update(nat_type=action.upper(), translated_ip=_atom(translation.get("addr")),
                                  translated_port=_atom(translation.get("port")))
            if "counter" in expression and isinstance(expression["counter"], dict):
                parsed.update({key: expression["counter"].get(key) for key in ("packets", "bytes")})
            if "counter" not in expression:
                details.append(expression)
        parsed["match"] = json.dumps(details, ensure_ascii=False)[:600]
        if "nat_type" in parsed:
            nat.append(parsed)
        elif chains.get((family, table, chain), {}).get("type") != "nat":
            filters.append(parsed)
    return filters, nat, list(chains.values())


def iptables_rules(output, provider, family):
    table, rules, nat, policies = None, [], [], {}
    order = {}
    for line in output.splitlines():
        if line.startswith("*"):
            table = line[1:]
        elif line.startswith(":") and table == "filter":
            chain, policy, *_ = line[1:].split()
            if policy != "-":
                policies[chain] = policy.lower()
        elif " -A " in f" {line}":
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            counter = re.fullmatch(r"\[(\d+):(\d+)\]", tokens[0])
            if counter:
                tokens.pop(0)
            if len(tokens) < 2 or tokens[0] != "-A":
                continue
            chain = tokens[1]
            order[(table, chain)] = order.get((table, chain), 0) + 1
            def arg(*flags):
                for flag in flags:
                    if flag in tokens and tokens.index(flag) + 1 < len(tokens):
                        return tokens[tokens.index(flag) + 1]
                return None
            action = arg("-j", "-g")
            rule = {
                "id": stable_id(provider, family, table, line.split("-A ", 1)[1], order[(table, chain)]),
                "provider": provider, "family": family, "table": table, "chain": chain,
                "hook": chain.lower() if chain in {"PREROUTING", "POSTROUTING", "OUTPUT", "INPUT", "FORWARD"} else None,
                "order": order[(table, chain)], "action": action,
                "protocol": arg("-p"), "source": arg("-s"), "destination": arg("-d"),
                "source_port": arg("--sport", "--sports"), "destination_port": arg("--dport", "--dports"),
                "interface": arg("-i", "-o"), "comment": arg("--comment"), "match": line[:600],
                "management": "Docker" if "DOCKER" in chain else "LARP" if (arg("--comment") or "").startswith("larp-") else "Host",
            }
            if counter:
                rule.update(packets=int(counter[1]), bytes=int(counter[2]))
            if table == "nat" and action in {"DNAT", "SNAT", "MASQUERADE", "REDIRECT"}:
                target = arg("--to-destination", "--to-source")
                translated_ip, translated_port = target, arg("--to-ports")
                if target and target.startswith("[") and "]:" in target:
                    translated_ip, translated_port = target[1:].split("]:", 1)
                elif target and target.count(":") == 1:
                    translated_ip, translated_port = target.split(":")
                rule.update(nat_type=action, translated_ip=translated_ip, translated_port=translated_port)
                nat.append(rule)
            elif table != "nat":
                rules.append(rule)
    return rules, nat, policies


def collect_firewall():
    errors, kernel_rules, nat, policies, backends = {}, [], [], {}, []
    try:
        kernel_rules, nat, chains = nft_rules(run_json("nft", "-j", "list", "ruleset"))
        backends.append("nftables")
        for chain in chains:
            direction = {"input": "incoming", "output": "outgoing", "forward": "routed"}.get(chain.get("hook"))
            if direction and chain.get("policy"):
                policies[f"{chain['family']}/{chain['table']}/{chain['name']}"] = chain["policy"]
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as error:
        errors["nftables"] = str(error)
    nft_active = bool(kernel_rules or nat or any(policy != "accept" for policy in policies.values()))
    xt_policies = {}
    xt_active = None
    for save, command, family in (("iptables-save", "iptables", "IPv4"), ("ip6tables-save", "ip6tables", "IPv6")):
        try:
            version = run(command, "-V")
            backend = "iptables (nf_tables)" if "nf_tables" in version else "iptables (legacy)"
            lines = run(save, "-c")
            if backend not in backends:
                backends.append(backend)
            if backend.endswith("(nf_tables)") and "nftables" in backends:
                # The same kernel objects already appeared in nft JSON.
                continue
            saved_filter, saved_nat, defaults = iptables_rules(lines, backend, family)
            kernel_rules.extend(saved_filter)
            nat.extend(saved_nat)
            if defaults:
                xt_policies[family] = defaults
            if saved_filter or saved_nat or any(policy != "accept" for policy in defaults.values()):
                xt_active = backend
        except (CollectionError, OSError, ValueError) as error:
            errors[save] = str(error)
    try:
        result = ufw_snapshot()
    except (CollectionError, OSError) as error:
        errors["ufw"] = str(error)
        provider = "nftables" if nft_active else xt_active or next(iter(backends), "unavailable")
        result = {"provider": provider, "status": "unknown", "rules": []}
    if result["provider"] != "ufw":
        result["rules"] = kernel_rules
        result["status"] = "active" if nft_active or xt_active else "unknown"
    result["kernel_status"] = "active" if nft_active or xt_active else "unknown"
    result.update(kernel_backends=backends, kernel_rules=kernel_rules[:ROW_LIMIT], kernel_policies=policies,
                  iptables_policies=xt_policies, kernel_rule_count=len(kernel_rules), errors=errors,
                  rule_count=len(result["rules"]))
    result["rules"] = result["rules"][:ROW_LIMIT]
    return result, {"rows": nat[:ROW_LIMIT], "total": len(nat), "backends": backends,
                    "errors": {k: v for k, v in errors.items() if k != "ufw"}}
