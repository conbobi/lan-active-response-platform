"""Place incident evidence on detection-pattern ladders and attach response playbooks.

Ladders and playbooks are data (``manager/knowledge/detection_patterns`` and
``manager/knowledge/response_playbooks``); this module evaluates named evidence predicates against
the dict produced by ``http_investigation.investigate()``, a behavior evidence dict or network-shell
detection evidence. Every confirmed fact and ATT&CK mapping cites the incident's own evidence IDs.
Knowledge chunks are reference material and are cited separately by ``chunk_id``.
"""
from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from app.core.agent_health import as_utc
from app.services.ai.knowledge.contracts import KNOWLEDGE_CATEGORIES, AttackMapping, PatternAssessment
from app.services.detection.behavior_evidence import (
    BRUTE_FORCE, REPEATED, SCAN, SQLI_TOOL_UA, valid_indicators,
)
from app.services.detection.network_shell import RULE_ID as SHELL_RULE_ID, SHELLS
from app.services.response.http_investigation import ASSIST_TYPES, BLOCK

logger = logging.getLogger(__name__)

KNOWLEDGE_ROOT = Path(__file__).resolve().parents[4] / "knowledge"
PATTERN_DIR = KNOWLEDGE_ROOT / "detection_patterns"
PLAYBOOK_DIR = KNOWLEDGE_ROOT / "response_playbooks"

ISOLATE = "isolate"
KILL_TREE = "kill_process_tree"
EXECUTABLE_ACTIONS = frozenset((*ASSIST_TYPES, KILL_TREE, ISOLATE))
ACTION_CATEGORIES = ("investigation", "containment", "application_protection", "remediation", "recovery")
EXECUTION_MODES = ("executable", "advisory")
RISK_LEVELS = ("low", "medium", "high")
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
ACTION_TYPE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")
BRUTE_FORCE_CRITERIA = ("password_burst_same_account_source", "distributed_password_burst_same_account")
TRUSTED_HTTP_SOURCES = ("web_access_logs", "auth_events")
SCAN_PORT_THRESHOLD = 8
CORRELATED_REQUESTS = 3
CORRELATION_SECONDS = 120
GRANT_SKEW_SECONDS = 5
START_TIME_TOLERANCE = 1e-3
KB_LIMIT = 4
NOT_CORRELATED = "related, not correlated"
WEB_APP_EXECUTABLE = re.compile(r"(?:python[0-9.]*|flask|gunicorn|uwsgi)\Z")
WEB_APP_CMDLINE = re.compile(r"vulnerable_web/app\.py|(?:^|[\s/])flask\s+run\b|(?:^|[\s/])gunicorn\b")
WEB_APP_CMDLINE_HINTS = ("vulnerable_web/app.py", "flask", "gunicorn")
CLOCK_SKEW_SECONDS = 30
MIN_EPOCH = 1_000_000_000          # process_start_time below this is not a wall-clock epoch
# Code-level invariant independent of the YAML: SQL injection never maps brute force or proxy execution.
HARD_FORBIDDEN = {"sql_injection": frozenset({"T1110", "T1218"})}
# Predicates that only gate a level (trusted provenance) and do not discriminate it.
GATE_PREDICATES = frozenset({"trusted_http_facts"})
ISOLATION_WORDING = re.compile(r"isolat|c\u00f4 l\u1eadp", re.I)
# Explicit negations ("kh\u00f4ng c\u00f4 l\u1eadp", "does not isolate") are allowed in block wording.
NEGATED_ISOLATION = re.compile(r"\b(?:kh\u00f4ng|not|no|never)\s+(?:isolat\w*|c\u00f4 l\u1eadp)", re.I)
# Host evidence kinds that describe a process started by the web application.
SHELL_KIND = "shell_with_network_socket"
CHILD_KIND = "web_server_child_process"
WEB_PROCESS_KINDS = (SHELL_KIND, CHILD_KIND)

PATTERN_KEYS = frozenset({"pattern_id", "title", "category", "applies_to", "forbidden_techniques", "levels"})
APPLIES_KEYS = frozenset({"classifications", "rule_ids", "host_evidence"})
LEVEL_KEYS = frozenset({"level", "name", "classifications", "requires", "conclusion", "confirmed", "suspected",
                        "missing_evidence", "alternative_explanations", "investigation_steps", "attack",
                        "playbook", "knowledge"})
REQUIRES_KEYS = frozenset({"all", "any"})
CONFIRMED_KEYS = frozenset({"predicate", "text"})
ATTACK_KEYS = frozenset({"technique_id", "evidence_from"})
QUERY_KEYS = frozenset({"terms", "categories", "attack_ids"})
PLAYBOOK_FILE_KEYS = frozenset({"playbooks"})
PLAYBOOK_KEYS = frozenset({"title", "actions"})
ACTION_KEYS = frozenset({"action_type", "category", "priority", "execution", "description", "prerequisites",
                         "depends_on", "conflicts_with", "operational_risk", "rollback", "verification_method",
                         "knowledge"})

Refs = tuple[str, ...]


class PatternSchemaError(ValueError):
    """A detection pattern or response playbook file does not satisfy the expected schema."""


# --------------------------------------------------------------------------- evidence normalization


@dataclass(frozen=True)
class _Evidence:
    kind: str                       # "http" | "behavior" | "shell" | "host"
    classification: str | None
    facts: tuple[dict, ...] = ()
    behavior: dict = field(default_factory=dict)
    shell: dict = field(default_factory=dict)
    host: tuple[dict, ...] = ()


def _strings(values) -> Refs:
    return tuple(dict.fromkeys(v for v in values or () if isinstance(v, str) and v))


def _behavior_facts(behavior: dict) -> tuple[dict, ...]:
    """Represent behavior-form HTTP evidence like one investigate() fact without inventing outcomes."""
    ua = behavior.get("user_agent") or ""
    tool = SQLI_TOOL_UA.search(ua) if isinstance(ua, str) else None
    hint = behavior.get("automation_hint") or (tool[1].lower() if tool else None)
    return ({
        "evidence_ids": list(_strings([behavior.get("evidence_id"), *behavior.get("source_event_ids", [])])),
        "provenance": behavior.get("source"), "observed_at": behavior.get("last_attempt_at"),
        "method": behavior.get("request_method"), "path": behavior.get("request_path"),
        "http_status": behavior.get("http_status"), "source_ip": behavior.get("source_ip"),
        "automation_hint": hint, "payload_indicators": sorted(valid_indicators(behavior.get("payload_indicators"))),
    },)


def _normalize(investigation: dict, host_evidence: Iterable[dict]) -> _Evidence:
    data = investigation if isinstance(investigation, dict) else {}
    host = tuple(item for item in host_evidence or () if isinstance(item, dict))
    if data.get("rule_id") == SHELL_RULE_ID:
        return _Evidence("shell", data.get("classification"), shell=data, host=host)
    if isinstance(data.get("observed_facts"), list):
        facts = tuple(f for f in data["observed_facts"] if isinstance(f, dict))
        return _Evidence("http", data.get("classification"), facts=facts, host=host)
    behavior = data.get("behavior") if isinstance(data.get("behavior"), dict) else data
    if isinstance(behavior.get("source_event_ids"), list) and behavior.get("classification"):
        facts = _behavior_facts(behavior) if behavior.get("evidence_type") in ("http", "authentication") else ()
        return _Evidence("behavior", behavior["classification"], facts=facts, behavior=behavior, host=host)
    return _Evidence("host" if host else "none", None, host=host)


# --------------------------------------------------------------------------- predicates


def _http_facts(ev: _Evidence) -> list[dict]:
    return [f for f in ev.facts if f.get("provenance") in TRUSTED_HTTP_SOURCES and _strings(f.get("evidence_ids"))]


def _sqli_tool(fact: dict) -> bool:
    hint = fact.get("automation_hint")
    return isinstance(hint, str) and bool(SQLI_TOOL_UA.fullmatch(hint))


def _refs_of(facts: Iterable[dict]) -> Refs:
    return _strings(ref for f in facts for ref in f.get("evidence_ids") or ())


def trusted_http_facts(ev: _Evidence) -> Refs:
    return _refs_of(_http_facts(ev))


def sqli_tool_user_agent(ev: _Evidence) -> Refs:
    return _refs_of(f for f in _http_facts(ev) if _sqli_tool(f) and f.get("method") == "POST"
                    and f.get("path") in (None, "/login"))


def http_automation_hint(ev: _Evidence) -> Refs:
    return _refs_of(f for f in _http_facts(ev) if isinstance(f.get("automation_hint"), str) and f["automation_hint"])


def _payload_facts(ev: _Evidence) -> list[dict]:
    return [f for f in _http_facts(ev) if valid_indicators(f.get("payload_indicators"))]


def sql_payload_indicators(ev: _Evidence) -> Refs:
    return _refs_of(_payload_facts(ev))


def correlated_tool_requests(ev: _Evidence) -> Refs:
    """At least three SQL-tool requests from one source inside a short window."""
    by_source: dict[str, list[tuple[datetime, dict]]] = {}
    for fact in _http_facts(ev):
        stamp = as_utc(fact.get("observed_at"))
        if _sqli_tool(fact) and stamp and isinstance(fact.get("source_ip"), str):
            by_source.setdefault(fact["source_ip"], []).append((stamp, fact))
    for items in by_source.values():
        items.sort(key=lambda item: item[0])
        for start in range(len(items) - CORRELATED_REQUESTS + 1):
            window = items[start:start + CORRELATED_REQUESTS]
            if window[-1][0] - window[0][0] <= timedelta(seconds=CORRELATION_SECONDS):
                return _refs_of(f for _, f in window)
    return ()


def _grant_pairs(ev: _Evidence) -> list[tuple[dict, dict]]:
    """Session grants whose request row is a payload-bearing request from the same source and time."""
    payload = {f["evidence_ids"][0]: f for f in _payload_facts(ev) if f.get("provenance") == "web_access_logs"}
    pairs = []
    for fact in ev.facts:
        ids = _strings(fact.get("evidence_ids"))
        if (fact.get("outcome") != "session_granted" or fact.get("provenance") != "auth_events + web_access_logs"
                or len(ids) != 2 or ids[0] not in payload):
            continue
        request = payload[ids[0]]
        granted, sent = as_utc(fact.get("observed_at")), as_utc(request.get("observed_at"))
        if (granted and sent and abs((granted - sent).total_seconds()) <= GRANT_SKEW_SECONDS
                and fact.get("source_ip") == request.get("source_ip")):
            pairs.append((request, fact))
    return pairs


def session_grant_correlated(ev: _Evidence) -> Refs:
    return _refs_of(f for pair in _grant_pairs(ev) for f in pair)


def credential_mismatch_validated(ev: _Evidence) -> Refs:
    grants = {(_strings(g["evidence_ids"])[0], _strings(g["evidence_ids"])[1]): (r, g) for r, g in _grant_pairs(ev)}
    refs: list[str] = []
    for fact in ev.facts:
        ids = _strings(fact.get("evidence_ids"))
        if (fact.get("outcome") == "credential_mismatch_grant" and fact.get("provenance") == "lab grant_observation"
                and len(ids) == 3 and (ids[2], ids[1]) in grants
                and fact.get("source_ip") == grants[(ids[2], ids[1])][0].get("source_ip")):
            refs.extend((*ids, *_refs_of(grants[(ids[2], ids[1])])))
    return _strings(refs)


def _behavior_refs(ev: _Evidence) -> Refs:
    behavior = ev.behavior
    return _strings([behavior.get("evidence_id"), *behavior.get("source_event_ids", [])])


def auth_failures_observed(ev: _Evidence) -> Refs:
    b = ev.behavior
    failed = b.get("failed_attempts")
    ok = (b.get("evidence_type") == "authentication" and b.get("classification") in (REPEATED, BRUTE_FORCE)
          and type(failed) is int and failed > 0)
    return _behavior_refs(ev) if ok and b.get("source_event_ids") else ()


def brute_force_criteria_met(ev: _Evidence) -> Refs:
    b = ev.behavior
    ok = b.get("classification") == BRUTE_FORCE and b.get("brute_force_criteria") in BRUTE_FORCE_CRITERIA
    return auth_failures_observed(ev) if ok else ()


def success_after_failures(ev: _Evidence) -> Refs:
    """A success inside a single-source, single-account burst group.

    Only ``password_burst_same_account_source`` groups hold one source and one account; distributed
    groups span many sources. The behavior evidence carries no per-event status times, so ordering
    (success after the failures) is not asserted by this predicate or the level's wording.
    """
    b = ev.behavior
    count = b.get("successful_attempts")
    ok = (type(count) is int and count > 0 and b.get("brute_force_criteria") == BRUTE_FORCE_CRITERIA[0]
          and isinstance(b.get("source_ip"), str) and b["source_ip"] not in ("", "unknown")
          and isinstance(b.get("username"), str) and b["username"])
    return brute_force_criteria_met(ev) if ok else ()


def _ports(behavior: dict) -> set[int]:
    values = behavior.get("destination_ports")
    return {p for p in values if type(p) is int and 0 < p <= 65535} if isinstance(values, list) else set()


def inbound_port_contacts(ev: _Evidence) -> Refs:
    b = ev.behavior
    ok = b.get("classification") == SCAN and b.get("direction") == "inbound" and _ports(b)
    return _behavior_refs(ev) if ok and b.get("source_event_ids") else ()


def service_scan_threshold(ev: _Evidence) -> Refs:
    return inbound_port_contacts(ev) if len(_ports(ev.behavior)) >= SCAN_PORT_THRESHOLD else ()


def _process_identity(process) -> tuple[int, float] | None:
    if not isinstance(process, dict):
        return None
    pid, start = process.get("pid"), process.get("process_start_time")
    if type(pid) is int and pid > 0 and type(start) in (int, float) and start > 0:
        return pid, float(start)
    return None


def _shell_refs(shell: dict) -> Refs:
    network = shell.get("network") if isinstance(shell.get("network"), dict) else {}
    socket = network.get("socket_id") or (f"inode:{network['inode']}" if network.get("inode") else None)
    return _strings([shell.get("incident_id"), shell.get("entity"), socket])


def shell_socket_holder(ev: _Evidence) -> Refs:
    shell, process = ev.shell, ev.shell.get("process")
    network = shell.get("network") if isinstance(shell.get("network"), dict) else {}
    exe = process.get("exe_path") if isinstance(process, dict) else None
    ok = (_process_identity(process) and isinstance(exe, str) and posixpath.basename(exe) in SHELLS
          and network.get("inode") and network.get("attribution") in ("inode_verified", "inode_verified_partial", "holders_truncated")
          and isinstance(process.get("socket_fds"), list) and process["socket_fds"])
    return _shell_refs(shell) if ok else ()


def shell_stdio_on_socket(ev: _Evidence) -> Refs:
    process = ev.shell.get("process") or {}
    stdio, fds = process.get("stdio_fds"), process.get("socket_fds")
    linked = (isinstance(stdio, list) and isinstance(fds, list) and 0 in stdio and 0 in fds
              and any(fd in stdio and fd in fds for fd in (1, 2)))
    return shell_socket_holder(ev) if linked else ()


def _is_shell_item(item: dict) -> bool:
    if item.get("kind") == SHELL_KIND:
        return True
    process = item.get("process") if isinstance(item.get("process"), dict) else {}
    exe = process.get("exe_path") or process.get("name")
    return item.get("kind") == CHILD_KIND and isinstance(exe, str) and posixpath.basename(exe) in SHELLS


def web_spawned_shell_verified(ev: _Evidence) -> Refs:
    return _strings(ref for item in ev.host if item.get("correlation") == "verified"
                    and item.get("spawned_by_web_server") is True and _is_shell_item(item)
                    for ref in item.get("evidence_refs") or ())


def host_activity_unverified(ev: _Evidence) -> Refs:
    return _strings(ref for item in ev.host if item.get("correlation") == "unverified"
                    for ref in item.get("evidence_refs") or ())


PREDICATES: dict[str, Callable[[_Evidence], Refs]] = {fn.__name__: fn for fn in (
    trusted_http_facts, sqli_tool_user_agent, http_automation_hint, sql_payload_indicators,
    correlated_tool_requests, session_grant_correlated, credential_mismatch_validated,
    auth_failures_observed, brute_force_criteria_met, success_after_failures,
    inbound_port_contacts, service_scan_threshold, shell_socket_holder, shell_stdio_on_socket,
    web_spawned_shell_verified, host_activity_unverified,
)}


# --------------------------------------------------------------------------- schema loading


def _require(condition: bool, where: str, message: str) -> None:
    if not condition:
        raise PatternSchemaError(f"{where}: {message}")


def _keys(raw, allowed: frozenset[str], where: str) -> None:
    """Reject unknown or misspelled keys so a typo cannot silently fall back to a default."""
    unknown = sorted(str(k) for k in raw if k not in allowed) if isinstance(raw, dict) else []
    _require(not unknown, where, f"unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _string_list(value, where: str, name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    _require(isinstance(value, list) and all(isinstance(v, str) and v.strip() for v in value),
             where, f"'{name}' must be a list of non-empty strings")
    _require(allow_empty or bool(value), where, f"'{name}' must not be empty")
    return tuple(value)


def _validate_query(query, where: str) -> dict:
    _require(isinstance(query, dict) and isinstance(query.get("terms"), str) and query["terms"].strip(),
             where, "knowledge query needs non-empty 'terms'")
    _keys(query, QUERY_KEYS, f"{where} knowledge")
    categories = _string_list(query.get("categories", []), where, "categories")
    _require(all(c in KNOWLEDGE_CATEGORIES for c in categories), where, f"unknown knowledge category in {categories}")
    attack_ids = _string_list(query.get("attack_ids", []), where, "attack_ids")
    _require(all(TECHNIQUE_ID.match(t) for t in attack_ids), where, f"invalid ATT&CK id in {attack_ids}")
    return {"terms": query["terms"], "categories": categories, "attack_ids": attack_ids}


def _read_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PatternSchemaError(f"{path.name}: invalid YAML: {exc}") from exc
    _require(isinstance(data, dict), path.name, "top level must be a mapping")
    return data


def _validate_level(raw, where: str, forbidden: set[str], previous: int) -> dict:
    _require(isinstance(raw, dict), where, "level must be a mapping")
    number = raw.get("level")
    _require(type(number) is int and number == previous + 1, where, "levels must be numbered 1, 2, 3 ... in order")
    where = f"{where} level {number}"
    _keys(raw, LEVEL_KEYS, where)
    _require(isinstance(raw.get("name"), str) and re.fullmatch(r"[a-z][a-z0-9_]*", raw["name"]), where, "invalid 'name'")
    requires = raw.get("requires")
    _require(isinstance(requires, dict), where, "'requires' needs 'all'/'any'")
    _keys(requires, REQUIRES_KEYS, f"{where} requires")
    all_of = _string_list(requires.get("all", []), where, "requires.all")
    any_of = _string_list(requires.get("any", []), where, "requires.any")
    _require(bool(all_of or any_of), where, "a level needs at least one evidence predicate")
    for name in (*all_of, *any_of):
        _require(name in PREDICATES, where, f"unknown predicate '{name}'")
    conclusion = raw.get("conclusion")
    _require(isinstance(conclusion, str) and conclusion.strip().endswith(".")
             and not re.search(r"[.!?]\s+\S", conclusion.strip()), where, "'conclusion' must be one sentence")
    confirmed = raw.get("confirmed")
    _require(isinstance(confirmed, list), where, "'confirmed' must be a list")
    for item in confirmed:
        _require(isinstance(item, dict) and item.get("predicate") in PREDICATES
                 and isinstance(item.get("text"), str) and item["text"].strip(), where,
                 "confirmed facts need a known 'predicate' and 'text'")
        _keys(item, CONFIRMED_KEYS, f"{where} confirmed")
    attack = raw.get("attack")
    _require(isinstance(attack, list), where, "'attack' must be a list")
    for item in attack:
        _require(isinstance(item, dict) and isinstance(item.get("technique_id"), str)
                 and TECHNIQUE_ID.match(item["technique_id"]), where, "attack entries need a valid 'technique_id'")
        _keys(item, ATTACK_KEYS, f"{where} attack")
        _require(item["technique_id"] not in forbidden, where, f"technique {item['technique_id']} is forbidden")
        sources = _string_list(item.get("evidence_from"), where, "evidence_from", allow_empty=False)
        _require(all(s in PREDICATES for s in sources), where, f"unknown predicate in evidence_from {sources}")
    playbook = raw.get("playbook")
    _require(isinstance(playbook, str) and playbook, where, "'playbook' is required")
    knowledge = raw.get("knowledge")
    _require(isinstance(knowledge, list), where, "'knowledge' must be a list")
    return {
        "level": number, "name": raw["name"], "all": all_of, "any": any_of,
        "classifications": _string_list(raw.get("classifications", []), where, "classifications"),
        "conclusion": conclusion.strip(),
        "confirmed": tuple((item["predicate"], item["text"].strip()) for item in confirmed),
        "suspected": _string_list(raw.get("suspected"), where, "suspected"),
        "missing_evidence": _string_list(raw.get("missing_evidence"), where, "missing_evidence"),
        "alternative_explanations": _string_list(raw.get("alternative_explanations"), where, "alternative_explanations"),
        "investigation_steps": _string_list(raw.get("investigation_steps"), where, "investigation_steps"),
        "attack": tuple((item["technique_id"], tuple(item["evidence_from"])) for item in attack),
        "playbook": playbook,
        "knowledge": tuple(_validate_query(q, where) for q in knowledge),
    }


def _validate_pattern(data: dict, where: str) -> dict:
    _keys(data, PATTERN_KEYS, where)
    pattern_id = data.get("pattern_id")
    _require(isinstance(pattern_id, str) and re.fullmatch(r"[a-z][a-z0-9_]*", pattern_id), where, "invalid 'pattern_id'")
    _require(data.get("category") in KNOWLEDGE_CATEGORIES, where, "'category' must be a knowledge category")
    applies = data.get("applies_to")
    _require(isinstance(applies, dict) and bool(applies), where, "invalid 'applies_to'")
    _keys(applies, APPLIES_KEYS, f"{where} applies_to")
    _require("forbidden_techniques" in data, where, "'forbidden_techniques' is required (use [] for none)")
    forbidden = set(_string_list(data["forbidden_techniques"], where, "forbidden_techniques"))
    forbidden |= HARD_FORBIDDEN.get(data["category"], frozenset())
    levels = data.get("levels")
    _require(isinstance(levels, list) and levels, where, "'levels' must be a non-empty list")
    parsed = []
    for raw in levels:
        parsed.append(_validate_level(raw, f"{where} [{pattern_id}]", forbidden, len(parsed)))
    return {
        "pattern_id": pattern_id, "title": data.get("title", pattern_id), "category": data["category"],
        "classifications": tuple(applies.get("classifications", ())), "rule_ids": tuple(applies.get("rule_ids", ())),
        "host_evidence": applies.get("host_evidence") is True,
        "forbidden": frozenset(forbidden), "levels": tuple(parsed),
    }


def _validate_action(raw, where: str) -> dict:
    _require(isinstance(raw, dict), where, "action must be a mapping")
    kind = raw.get("action_type")
    _require(isinstance(kind, str) and ACTION_TYPE.match(kind), where, f"invalid action_type {kind!r}")
    where = f"{where} {kind}"
    _keys(raw, ACTION_KEYS, where)
    _require(raw.get("category") in ACTION_CATEGORIES, where, f"category must be one of {ACTION_CATEGORIES}")
    _require(raw.get("execution") in EXECUTION_MODES, where, f"execution must be one of {EXECUTION_MODES}")
    _require((raw["execution"] == "executable") == (kind in EXECUTABLE_ACTIONS), where,
             "executable actions must use an existing action_type, advisory actions must not")
    _require(type(raw.get("priority")) is int and raw["priority"] > 0, where, "'priority' must be a positive int")
    _require(raw.get("operational_risk") in RISK_LEVELS, where, f"operational_risk must be one of {RISK_LEVELS}")
    for key in ("description", "rollback", "verification_method"):
        _require(isinstance(raw.get(key), str) and raw[key].strip(), where, f"'{key}' is required")
    if kind == BLOCK:
        for key in ("description", "rollback", "verification_method"):
            _require(not ISOLATION_WORDING.search(NEGATED_ISOLATION.sub("", raw[key])), where,
                     f"blocking a remote source must not be described as isolation ('{key}')")
    return {
        "action_type": kind, "category": raw["category"], "priority": raw["priority"], "execution": raw["execution"],
        "description": raw["description"].strip(),
        "prerequisites": list(_string_list(raw.get("prerequisites", []), where, "prerequisites")),
        "depends_on": list(_string_list(raw.get("depends_on", []), where, "depends_on")),
        "conflicts_with": list(_string_list(raw.get("conflicts_with", []), where, "conflicts_with")),
        "operational_risk": raw["operational_risk"], "rollback": raw["rollback"].strip(),
        "verification_method": raw["verification_method"].strip(),
        "knowledge": _validate_query(raw.get("knowledge"), where),
    }


def _ancestors(kind: str, deps: dict[str, list[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(deps.get(kind, ()))
    while stack:
        item = stack.pop()
        if item not in seen:
            seen.add(item)
            stack.extend(deps.get(item, ()))
    return seen


def _check_graph(actions: list[dict], where: str) -> None:
    deps = {a["action_type"]: a["depends_on"] for a in actions}
    for action in actions:
        for target in action["depends_on"]:
            _require(target in deps, where, f"{action['action_type']} depends on missing action {target}")
        for target in action["conflicts_with"]:
            _require(target in deps or target in EXECUTABLE_ACTIONS, where,
                     f"{action['action_type']} conflicts with unknown action {target}")
    state: dict[str, int] = {}

    def visit(node: str) -> None:
        state[node] = 1
        for nxt in deps[node]:
            _require(state.get(nxt) != 1, where, f"dependency cycle through {node} -> {nxt}")
            if nxt not in state:
                visit(nxt)
        state[node] = 2

    for node in deps:
        if node not in state:
            visit(node)
    if BLOCK in deps and ISOLATE in deps:
        by_type = {a["action_type"]: a for a in actions}
        ordered = ISOLATE in _ancestors(BLOCK, deps) or BLOCK in _ancestors(ISOLATE, deps)
        declared = ISOLATE in by_type[BLOCK]["conflicts_with"] and BLOCK in by_type[ISOLATE]["conflicts_with"]
        _require(ordered or declared, where, "temporary_ip_block and isolate must be ordered or declared conflicting")


def _validate_playbook(playbook_id: str, raw, where: str) -> dict:
    where = f"{where} [{playbook_id}]"
    _require(isinstance(raw, dict) and isinstance(raw.get("actions"), list) and raw["actions"], where,
             "playbook needs a non-empty 'actions' list")
    _keys(raw, PLAYBOOK_KEYS, where)
    actions = [_validate_action(item, where) for item in raw["actions"]]
    kinds = [a["action_type"] for a in actions]
    _require(len(kinds) == len(set(kinds)), where, "duplicate action_type in playbook")
    _check_graph(actions, where)
    return {"playbook_id": playbook_id, "title": raw.get("title", playbook_id), "actions": actions}


def load_playbooks(directory: Path | str = PLAYBOOK_DIR) -> dict[str, dict]:
    """Load and validate every playbook file; raise PatternSchemaError on the first schema violation."""
    playbooks: dict[str, dict] = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        data = _read_yaml(path)
        _require(isinstance(data.get("playbooks"), dict) and data["playbooks"], path.name, "'playbooks' mapping required")
        _keys(data, PLAYBOOK_FILE_KEYS, path.name)
        for playbook_id, raw in data["playbooks"].items():
            _require(isinstance(playbook_id, str) and playbook_id not in playbooks, path.name,
                     f"duplicate or invalid playbook id {playbook_id!r}")
            playbooks[playbook_id] = _validate_playbook(playbook_id, raw, path.name)
    return playbooks


def load_patterns(directory: Path | str = PATTERN_DIR, *, playbook_ids: Iterable[str] | None = None) -> dict[str, dict]:
    """Load and validate every ladder file; with playbook_ids, also check that referenced playbooks exist."""
    known = set(playbook_ids) if playbook_ids is not None else None
    patterns: dict[str, dict] = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        pattern = _validate_pattern(_read_yaml(path), path.name)
        _require(pattern["pattern_id"] not in patterns, path.name, f"duplicate pattern {pattern['pattern_id']}")
        if known is not None:
            for level in pattern["levels"]:
                _require(level["playbook"] in known, path.name, f"unknown playbook {level['playbook']}")
        patterns[pattern["pattern_id"]] = pattern
    return patterns


@lru_cache(maxsize=1)
def catalog() -> tuple[dict[str, dict], dict[str, dict]]:
    """Validated (patterns, playbooks) from the repository knowledge directory, loaded once."""
    playbooks = load_playbooks(PLAYBOOK_DIR)
    return load_patterns(PATTERN_DIR, playbook_ids=playbooks), playbooks


def playbook(playbook_id: str | None) -> dict | None:
    return catalog()[1].get(playbook_id) if playbook_id else None


# --------------------------------------------------------------------------- knowledge resolution


def _default_kb():
    try:
        from app.services.ai.knowledge.kb_store import knowledge_base
        return knowledge_base
    except Exception:  # the knowledge base is optional reference material
        logger.warning("Knowledge base unavailable; assessments carry no knowledge references", exc_info=True)
        return None


def _search(kb, query: dict) -> Refs:
    if kb is None:
        return ()
    try:
        chunks = kb.search(query["terms"], categories=list(query["categories"]) or None,
                           attack_ids=list(query["attack_ids"]) or None, limit=KB_LIMIT)
    except Exception:
        logger.warning("Knowledge search failed for %r", query["terms"], exc_info=True)
        return ()
    return _strings(getattr(chunk, "chunk_id", None) for chunk in chunks or ())


def _technique(kb, technique_id: str) -> tuple[str, Refs]:
    """Technique name and chunk_ids from the synced knowledge base; the bare ID when unavailable."""
    if kb is None:
        return technique_id, ()
    try:
        chunks = [c for c in kb.by_attack_id(technique_id) or () if technique_id in getattr(c, "attack_ids", ())]
    except Exception:
        logger.warning("Knowledge lookup failed for %s", technique_id, exc_info=True)
        return technique_id, ()
    # Prefer the technique's own chunk over detection strategies or runbooks that also cite the ID.
    named = sorted((c for c in chunks if isinstance(getattr(c, "title", None), str) and c.title),
                   key=lambda c: f":{technique_id}:" not in c.chunk_id)
    name = named[0].title if named else technique_id
    return name, _strings(c.chunk_id for c in chunks[:KB_LIMIT])


# --------------------------------------------------------------------------- assessment


def _level_refs(level: dict, refs: dict[str, Refs]) -> Refs | None:
    """Evidence refs that satisfy the level, or None when its predicates are not met."""
    if not all(refs[name] for name in level["all"]):
        return None
    matched_any = [name for name in level["any"] if refs[name]]
    if level["any"] and not matched_any:
        return None
    names = [name for name in (*level["all"], *matched_any) if name not in GATE_PREDICATES]
    return _strings(ref for name in names or level["all"] for ref in refs[name])


def attack_mappings(specs: Iterable[tuple[str, tuple[str, ...]]], refs: dict[str, Refs], kb,
                    forbidden: Iterable[str] = ()) -> tuple[AttackMapping, ...]:
    """Mappings whose every evidence predicate holds; a mapping without evidence refs is dropped."""
    blocked = set(forbidden)
    mappings = []
    for technique_id, sources in specs:
        evidence = _strings(ref for name in sources for ref in refs.get(name, ()))
        if technique_id in blocked or not evidence or not all(refs.get(name) for name in sources):
            logger.debug("Dropped %s mapping without evidence references", technique_id)
            continue
        name, knowledge = _technique(kb, technique_id)
        mappings.append(AttackMapping(technique_id, name, evidence, knowledge))
    return tuple(mappings)


def _forbidden(pattern: dict) -> frozenset[str]:
    """YAML-declared bans plus the code-level invariant for the pattern's category."""
    return frozenset(pattern.get("forbidden", ())) | HARD_FORBIDDEN.get(pattern.get("category"), frozenset())


def _select_pattern(ev: _Evidence, patterns: dict[str, dict]) -> dict | None:
    for pattern in patterns.values():
        if ev.kind == "shell" and ev.shell.get("rule_id") in pattern["rule_ids"]:
            return pattern
        if ev.kind in ("http", "behavior") and ev.classification in pattern["classifications"]:
            return pattern
    if ev.kind == "host":
        return next((p for p in patterns.values() if p["host_evidence"]), None)
    return None


def _unmatched(pattern_id: str, post: tuple[dict, ...]) -> PatternAssessment:
    return PatternAssessment(
        pattern_id=pattern_id, level=0, level_name="not_matched",
        conclusion="Bằng chứng hiện có chưa đáp ứng điều kiện của bất kỳ mức nào trong mẫu phát hiện.",
        confirmed_facts=(), suspected=(), missing_evidence=(), alternative_explanations=(), investigation_steps=(),
        attack_mapping=(), evidence_refs=(), knowledge_refs=(), playbook_id=None, post_exploitation=post,
    )


def _post_exploitation(ev: _Evidence, pattern_id: str, patterns: dict[str, dict], kb) -> tuple[dict, ...]:
    """Host items for HTTP incidents; verified items carry their own ladder placement."""
    if pattern_id == "web_command_injection" or not ev.host:
        return ()
    items = []
    for item in ev.host:
        entry = {**item, "status": "correlated" if item.get("correlation") == "verified" else NOT_CORRELATED}
        if (item.get("correlation") == "verified" and item.get("kind") in WEB_PROCESS_KINDS
                and "web_command_injection" in patterns):
            nested = _assess(_Evidence("host", None, host=(item,)), patterns["web_command_injection"], patterns, kb)
            entry["assessment"] = {"pattern_id": nested.pattern_id, "level": nested.level,
                                   "level_name": nested.level_name,
                                   "attack_mapping": [asdict(m) for m in nested.attack_mapping]}
        items.append(entry)
    return tuple(items)


def _verified_host_facts(post: tuple[dict, ...]) -> tuple[str, ...]:
    facts = []
    for item in post:
        refs = _strings(item.get("evidence_refs"))
        if item.get("status") == "correlated" and refs:
            facts.append(f"Hoạt động máy chủ đã xác minh tương quan ({item.get('kind')}): {item.get('reason')} "
                         f"[evidence: {', '.join(refs)}]")
    return tuple(facts)


def _assess(ev: _Evidence, pattern: dict, patterns: dict[str, dict], kb) -> PatternAssessment:
    refs = {name: fn(ev) for name, fn in PREDICATES.items()}
    post = _post_exploitation(ev, pattern["pattern_id"], patterns, kb)
    chosen, chosen_refs = None, ()
    for level in pattern["levels"]:
        if level["classifications"] and ev.classification not in level["classifications"]:
            continue
        matched = _level_refs(level, refs)
        if matched:
            chosen, chosen_refs = level, matched
    if chosen is None:
        return _unmatched(pattern["pattern_id"], post)
    confirmed = tuple(f"{text} [evidence: {', '.join(refs[name])}]" for name, text in chosen["confirmed"] if refs[name])
    knowledge = _strings(ref for query in chosen["knowledge"] for ref in _search(kb, query))
    return PatternAssessment(
        pattern_id=pattern["pattern_id"], level=chosen["level"], level_name=chosen["name"],
        conclusion=chosen["conclusion"], confirmed_facts=confirmed + _verified_host_facts(post),
        suspected=chosen["suspected"], missing_evidence=chosen["missing_evidence"],
        alternative_explanations=chosen["alternative_explanations"],
        investigation_steps=chosen["investigation_steps"],
        attack_mapping=attack_mappings(chosen["attack"], refs, kb, _forbidden(pattern)),
        evidence_refs=chosen_refs, knowledge_refs=knowledge, playbook_id=chosen["playbook"],
        post_exploitation=post,
    )


def assess(investigation: dict, *, host_evidence: Iterable[dict] = (), kb: Any = None,
           pattern: str | None = None, patterns: dict[str, dict] | None = None) -> PatternAssessment:
    """Deterministically place evidence on its detection-pattern ladder.

    ``investigation`` is the dict from ``investigate()``, a behavior evidence dict (or a dict holding one
    under ``behavior``), or network-shell detection evidence. ``kb`` defaults to the shared knowledge base
    and degrades to no knowledge references when it cannot be imported.
    """
    patterns = patterns if patterns is not None else catalog()[0]
    kb = kb if kb is not None else _default_kb()
    ev = _normalize(investigation, host_evidence)
    selected = patterns.get(pattern) if pattern else _select_pattern(ev, patterns)
    if selected is None:
        return _unmatched(pattern or "unknown", ())
    return _assess(ev, selected, patterns, kb)


def to_dict(assessment: PatternAssessment) -> dict:
    """JSON-ready representation with lists instead of tuples."""
    def plain(value):
        if isinstance(value, dict):
            return {k: plain(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [plain(v) for v in value]
        return value
    return plain(asdict(assessment))


# --------------------------------------------------------------------------- post-exploitation correlation


def is_web_app_process(row) -> bool:
    """The Flask lab application identified from process_info name/exe and command line."""
    exe = posixpath.basename(getattr(row, "exe_path", None) or getattr(row, "exe", None) or "")
    name = getattr(row, "name", None) or ""
    return bool((WEB_APP_EXECUTABLE.match(exe) or WEB_APP_EXECUTABLE.match(name))
                and WEB_APP_CMDLINE.search(getattr(row, "cmdline", None) or ""))


@dataclass(frozen=True)
class _Window:
    """The HTTP attack interval [start, end] plus the correlation window after its last request."""

    start: datetime
    end: datetime
    after: timedelta

    @property
    def lower(self) -> datetime:
        """Earliest time a process can start and still be post-exploitation (small clock-skew allowance)."""
        return self.start - timedelta(seconds=CLOCK_SKEW_SECONDS)

    @property
    def upper(self) -> datetime:
        return self.end + self.after

    @property
    def listed_from(self) -> datetime:
        """Earliest time an item is still listed, as related and never as correlated."""
        return self.start - self.after

    def lists(self, *stamps: datetime | None) -> bool:
        return any(s is not None and self.listed_from <= s <= self.upper for s in stamps)


def _first_stamp(*values) -> datetime | None:
    return next((stamp for value in values if (stamp := as_utc(value))), None)


def _attack_window(incident, window: timedelta) -> _Window | None:
    evidence = incident.detection_evidence if isinstance(incident.detection_evidence, dict) else {}
    behavior = evidence.get("behavior") if isinstance(evidence.get("behavior"), dict) else {}
    start = _first_stamp(behavior.get("first_attempt_at"), evidence.get("first_seen"),
                         getattr(incident, "created_at", None), behavior.get("last_attempt_at"))
    if start is None:
        return None
    end = _first_stamp(behavior.get("last_attempt_at"), evidence.get("last_observed_at")) or start
    return _Window(start, max(start, end), window)


def _epoch(value) -> datetime | None:
    """A wall-clock process start time (psutil create_time); None for boot-relative or invalid values."""
    if type(value) not in (int, float) or value < MIN_EPOCH:
        return None
    try:
        return datetime.fromtimestamp(float(value), timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _shell_time(incident) -> datetime | None:
    """Latest observation of a (deduplicated, updated-in-place) shell incident."""
    evidence = incident.detection_evidence or {}
    network = evidence.get("network") if isinstance(evidence.get("network"), dict) else {}
    return _first_stamp(network.get("observed_at"), evidence.get("last_observed_at"), evidence.get("first_seen"),
                        incident.created_at)


def _shell_started(incident) -> datetime | None:
    """When the shell process started; falls back to the incident's first observation."""
    evidence = incident.detection_evidence or {}
    process = evidence.get("process") if isinstance(evidence.get("process"), dict) else {}
    return _epoch(process.get("process_start_time")) or _first_stamp(evidence.get("first_seen"), incident.created_at)


def _timing_reason(started: datetime | None, win: _Window) -> str | None:
    """Why a process cannot be post-exploitation of this incident, or None when its start time fits."""
    if started is None:
        return "Không xác định được thời điểm khởi động của tiến trình."
    if started < win.lower:
        return "Tiến trình khởi động trước khi chuỗi request HTTP bắt đầu nên không phải hậu khai thác của sự cố này."
    if started > win.upper:
        return "Tiến trình khởi động ngoài cửa sổ tương quan sau request HTTP cuối cùng."
    return None


def _iso(stamp: datetime | None) -> str | None:
    return stamp.isoformat() if stamp else None


def _same_start(a: float, b) -> bool:
    return type(b) in (int, float) and abs(float(a) - float(b)) <= START_TIME_TOLERANCE


def _verify_ancestry(process: dict, ancestry: list, rows: list) -> tuple[dict | None, str]:
    """Walk the recorded ancestry; verified only if a link matches a web-app process_info row by pid + start."""
    child = process
    reused = False
    for depth, parent in enumerate(ancestry if isinstance(ancestry, list) else [], start=1):
        identity = _process_identity(parent)
        if (not identity or child.get("parent_pid") != identity[0]
                or identity[1] > float(child.get("process_start_time") or 0)):
            return None, "Chuỗi tiến trình cha không liên tục hoặc thời điểm khởi động không hợp lệ."
        same_pid = [row for row in rows if row.pid == identity[0] and is_web_app_process(row)]
        match = next((row for row in same_pid if _same_start(identity[1], row.process_start_time)), None)
        if match:
            return ({"pid": match.pid, "process_start_time": match.process_start_time,
                     "process_info_id": match.id, "depth": depth},
                    f"Tiến trình cha ở độ sâu {depth} khớp PID và thời điểm khởi động của ứng dụng web trong process_info.")
        reused = reused or bool(same_pid)
        child = parent
    if reused:
        return None, "PID trùng tiến trình ứng dụng web nhưng thời điểm khởi động khác (PID tái sử dụng)."
    return None, "Không có tiến trình cha nào khớp bản ghi process_info của ứng dụng web theo PID và thời điểm khởi động."


def _shell_item(source, win: _Window, rows: list) -> dict | None:
    evidence = source.detection_evidence or {}
    process = evidence.get("process")
    if not _process_identity(process):
        return None
    started, observed = _shell_started(source), _shell_time(source)
    network = evidence.get("network") if isinstance(evidence.get("network"), dict) else {}
    stdio, fds = process.get("stdio_fds") or [], process.get("socket_fds") or []
    item = {
        "kind": SHELL_KIND, "source_incident_id": source.id, "agent_id": source.agent_id,
        "started_at": _iso(started), "observed_at": _iso(observed),
        "process": {k: process.get(k) for k in ("pid", "process_start_time", "name", "exe_path", "parent_pid")},
        "remote": {"ip": network.get("dst_ip"), "port": network.get("dst_port"), "direction": network.get("direction")},
        "socket_fd_linked": 0 in stdio and 0 in fds and any(fd in stdio and fd in fds for fd in (1, 2)),
        "spawned_by_web_server": False, "web_server_process": None,
    }
    refs = [source.id, evidence.get("entity"), network.get("socket_id")]
    reason = _timing_reason(started, win)
    if reason is None:
        parent, reason = _verify_ancestry(process, evidence.get("ancestry"), rows)
        if parent:
            item.update(spawned_by_web_server=True, web_server_process=parent)
            refs.append(parent["process_info_id"])
    item["correlation"] = "verified" if item["spawned_by_web_server"] else "unverified"
    item["reason"] = reason
    item["evidence_refs"] = list(_strings(refs))
    return item


def _flow_item(flow, shell: dict) -> dict:
    socket = flow.socket_evidence if isinstance(flow.socket_evidence, dict) else {}
    pid, start = shell["process"]["pid"], shell["process"]["process_start_time"]
    holders = socket.get("holders") if isinstance(socket.get("holders"), list) else []
    held = any(isinstance(h, dict) and h.get("pid") == pid and _same_start(start, h.get("process_start_time"))
               for h in holders)
    outbound = socket.get("direction") == "outbound"
    verified = shell["correlation"] == "verified" and held and outbound
    reason = ("Socket của luồng do chính tiến trình đã xác minh nắm giữ (PID và thời điểm khởi động)." if verified
              else "Tiến trình nguồn chưa được xác minh." if shell["correlation"] != "verified"
              else "Luồng chỉ khớp PID, chưa khớp thời điểm khởi động hoặc hướng kết nối.")
    return {
        "kind": "outbound_connection", "source_incident_id": shell["source_incident_id"], "agent_id": flow.agent_id,
        "observed_at": as_utc(flow.start_time).isoformat() if flow.start_time else None,
        "process": shell["process"], "remote": {"ip": flow.dst_ip, "port": flow.dst_port, "protocol": flow.protocol},
        "correlation": "verified" if verified else "unverified", "reason": reason,
        "evidence_refs": list(_strings([flow.id, shell["source_incident_id"]])),
    }


def _child_item(child, parent, win: _Window) -> dict:
    """A process_info child of a web-app pid; process_info has no parent start time, so never verified."""
    started = _epoch(child.process_start_time)
    reason = _timing_reason(started, win) or (
        "process_info chỉ ghi PID của tiến trình cha, không ghi thời điểm khởi động của nó, "
        "nên chưa loại trừ được PID tái sử dụng.")
    return {
        "kind": CHILD_KIND, "source_incident_id": None, "agent_id": child.agent_id,
        "started_at": _iso(started), "observed_at": _iso(as_utc(child.created_at)),
        "process": {"pid": child.pid, "process_start_time": child.process_start_time, "name": child.name,
                    "exe_path": child.exe_path or child.exe or None, "parent_pid": child.parent_pid},
        "spawned_by_web_server": False, "web_server_process": None,
        "candidate_web_server_process": {"pid": parent.pid, "process_start_time": parent.process_start_time,
                                         "process_info_id": parent.id},
        "correlation": "unverified", "reason": reason,
        "evidence_refs": list(_strings([child.id, parent.id])),
    }


async def _web_children(db, agent_id: str, win: _Window, covered: list[tuple[int, float]]) -> list[dict]:
    """Processes recorded in process_info whose parent pid is the web application, inside the window."""
    from sqlalchemy import or_, select

    from app.models.process_info import ProcessInfo

    web = [row for row in (await db.scalars(select(ProcessInfo).where(
        ProcessInfo.agent_id == agent_id,
        or_(*(ProcessInfo.cmdline.contains(hint) for hint in WEB_APP_CMDLINE_HINTS)),
    ).limit(500))).all() if is_web_app_process(row) and type(row.process_start_time) in (int, float)]
    if not web:
        return []
    children = (await db.scalars(select(ProcessInfo).where(
        ProcessInfo.agent_id == agent_id, ProcessInfo.parent_pid.in_(sorted({row.pid for row in web})),
        ProcessInfo.process_start_time.between(win.listed_from.timestamp(), win.upper.timestamp()),
    ).order_by(ProcessInfo.process_start_time, ProcessInfo.id).limit(200))).all()
    items: list[dict] = []
    for child in children:
        start = child.process_start_time
        if is_web_app_process(child) or any(pid == child.pid and _same_start(s, start) for pid, s in covered):
            continue
        parents = [row for row in web if row.pid == child.parent_pid and row.process_start_time <= start]
        if not parents:
            continue
        covered.append((child.pid, start))
        items.append(_child_item(child, max(parents, key=lambda row: row.process_start_time), win))
    return items


async def related_host_evidence(db, incident, *, window_seconds: int = 600) -> list[dict]:
    """Host evidence on the incident's Agent around the HTTP attack, each marked verified or unverified.

    The interval runs from the first HTTP attempt (minus a small clock-skew allowance) to the last attempt
    plus ``window_seconds``. Verified means a shell started inside that interval and its recorded ancestry
    reaches the Flask application by process_info pid and process_start_time. Items that started before the
    attack, web-app children without a recorded parent start time, and anything else unverified are related,
    not correlated, and never change the HTTP conclusion.
    """
    from sqlalchemy import select

    from app.models.flow import Flow
    from app.models.incident import Incident
    from app.models.process_info import ProcessInfo

    agent_id = incident.agent_id
    win = _attack_window(incident, timedelta(seconds=window_seconds)) if agent_id else None
    if win is None:
        return []
    # Shell incidents are deduplicated and updated in place: filter on updated_at, not created_at.
    candidates = (await db.scalars(select(Incident).where(
        Incident.agent_id == agent_id, Incident.id != incident.id,
        Incident.updated_at >= win.listed_from, Incident.created_at <= win.upper + win.after,
    ).order_by(Incident.created_at, Incident.id).limit(200))).all()
    shells = [c for c in candidates if isinstance(c.detection_evidence, dict)
              and c.detection_evidence.get("rule_id") == SHELL_RULE_ID
              and win.lists(_shell_started(c), _shell_time(c))]
    pids = {a.get("pid") for c in shells for a in (c.detection_evidence.get("ancestry") or []) if isinstance(a, dict)}
    pids = [p for p in pids if type(p) is int]
    rows = list((await db.scalars(select(ProcessInfo).where(
        ProcessInfo.agent_id == agent_id, ProcessInfo.pid.in_(pids)))).all()) if pids else []
    items = [item for c in shells if (item := _shell_item(c, win, rows))]
    for shell in list(items):
        flows = (await db.scalars(select(Flow).where(
            Flow.agent_id == agent_id, Flow.pid == shell["process"]["pid"],
            Flow.start_time.between(win.listed_from, win.upper)).order_by(Flow.start_time, Flow.id).limit(25))).all()
        items.extend(_flow_item(flow, shell) for flow in flows)
    covered = [(s["process"]["pid"], s["process"]["process_start_time"]) for s in items if s["kind"] == SHELL_KIND]
    items.extend(await _web_children(db, agent_id, win, covered))
    return items
