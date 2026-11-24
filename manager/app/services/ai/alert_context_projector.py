"""Read incident evidence and project it without inferring process identities."""
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from math import isfinite
from typing import Any

from sqlalchemy import and_, or_, select, true

from app.core.agent_health import as_utc
from app.models.agent import Agent
from app.models.event import Event
from app.models.flow import Flow
from app.models.process_info import ProcessInfo
from app.services.agent.activity import process_identity, socket_key
from app.services.detection.network_shell import RULE_ID, detect_network_shell
from app.services.rule_engine import RuleEngine, match_endpoint_telemetry

from app.services.detection.behavior_evidence import BEHAVIORS, SCAN, SQLI, technique_for

NA = "N/A"
WINDOW = timedelta(minutes=2)
FIM_RULE = "builtin_linux_sensitive_file_change"
AUTH_RULE = "brute_force"
VERIFIED_ATTRIBUTION = {"inode_verified", "inode_verified_partial", "holders_truncated"}


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _records(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _value(value: Any):
    if isinstance(value, str):
        return value if value.strip() else NA
    if type(value) in (bool, int) or (type(value) is float and isfinite(value)):
        return value
    return NA


def _time(value: Any) -> str:
    parsed = as_utc(value)
    return parsed.isoformat() if parsed is not None else NA


def _within(value: Any, reference: Any) -> bool:
    observed, reference = as_utc(value), as_utc(reference)
    return observed is not None and reference is not None and abs(observed - reference) <= WINDOW


def _fds(value: Any) -> list[int] | str:
    if isinstance(value, list):
        return sorted({fd for fd in value if type(fd) is int and 0 <= fd < 2**31})
    return NA


def _inode(value: Any) -> bool:
    return (
        isinstance(value, str) and 0 < len(value) <= 20 and value.isascii()
        and value.isdecimal() and bool(value.strip("0"))
    )


def _network_key(raw: dict) -> list | None:
    protocol = raw.get("protocol")
    if not isinstance(protocol, str) or not re.fullmatch(r"[A-Za-z0-9]{1,16}", protocol):
        return None
    if any(type(raw.get(port)) is not int or not 0 <= raw[port] <= 65535
           for port in ("src_port", "dst_port")):
        return None
    return socket_key({**raw, "protocol": protocol.upper()})


def _verified_attribution(raw: dict) -> bool:
    attribution = raw.get("attribution")
    return isinstance(attribution, str) and attribution in VERIFIED_ATTRIBUTION and _inode(raw.get("inode"))


def _snapshot(incident) -> tuple[dict, dict, list[dict]]:
    evidence = _mapping(incident.detection_evidence)
    network = _mapping(evidence.get("network"))
    procs = [
        _mapping(evidence.get("process")), *_records(network.get("holders")),
        *_records(evidence.get("ancestry")), *_records(evidence.get("descendants")),
    ]
    return evidence, network, [proc for proc in procs if proc]


def _rule_id(incident, evidence):
    if isinstance(evidence.get("rule_id"), str):
        return evidence["rule_id"]
    notes = incident.notes or ""
    if notes.startswith(("rule_id:", "risk_source:")):
        return notes.split(":", 1)[1].split(" | ", 1)[0]
    return NA


def evidence_version(incident) -> str:
    snapshot = incident.detection_evidence
    if isinstance(snapshot, dict):
        # Receipt counters do not change the observation presented to the model.
        receipt_fields = {"observations", "episodes", "first_received_at", "last_received_at", "risk_calculated_at"}
        snapshot = {key: value for key, value in snapshot.items() if key not in receipt_fields}
    data = [
        incident.agent_id, incident.fingerprint, snapshot,
        incident.title, incident.description, incident.notes, incident.risk_score,
        _time(incident.created_at),
    ]
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True, default=str).encode()).hexdigest()


@dataclass
class AlertContext:
    metadata: dict
    processes: list[dict] = field(default_factory=list)
    flows: list[dict] = field(default_factory=list)
    facts: list[dict] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    mandatory: set[str] = field(default_factory=set)
    verified_shell: str | None = None
    conflict: bool = False
    chain_count: int = 0
    mapped_techniques: tuple[str, ...] = ()

    @property
    def by_id(self) -> dict:
        return {item["id"]: item for item in (*self.processes, *self.flows, *self.facts)}

    def prompt_data(self, process_limit: int, flow_limit: int) -> dict:
        def select_items(items, limit):
            picked = sorted(items, key=lambda item: item["id"] not in self.mandatory)[:limit]
            return [dict(item) for item in picked]

        processes = select_items(self.processes, process_limit)
        flows = select_items(self.flows, flow_limit)
        ids = {item["id"] for item in (*processes, *flows, *self.facts)}
        return {
            "alert": self.metadata, "processes": processes, "flows": flows,
            "facts": [dict(item) for item in self.facts],
            "missing": self.missing,
            "omitted": {
                "processes": len(self.processes) - len(processes),
                "flows": len(self.flows) - len(flows),
                "required_evidence": len(self.mandatory - ids),
            },
        }


def build_alert_context(incident, *, hostname=None, processes=(), flows=(), fim=None) -> AlertContext:
    evidence, network, observations = _snapshot(incident)
    rule_id = _rule_id(incident, evidence)
    observed_at = network.get("observed_at") or evidence.get("last_observed_at")
    reference = observed_at or incident.created_at
    result = AlertContext({
        "rule_id": rule_id, "rule_version": _value(evidence.get("rule_version")),
        "agent_id": _value(incident.agent_id), "hostname": _value(hostname),
        "observed_at": _time(observed_at), "incident_created_at": _time(incident.created_at),
        "risk_score": _value(incident.risk_score), "title": _value(incident.title),
    })

    by_identity = {}
    for proc in observations:
        identity = process_identity(proc)
        if not identity:
            continue
        existing = by_identity.setdefault(identity, {"source": "incident_snapshot"})
        for key, value in proc.items():
            if existing.get(key) is None:
                existing[key] = value

    # A historical process row can fill missing fields only for an anchored identity.
    for row in processes:
        identity = process_identity({"pid": row.pid, "process_start_time": row.process_start_time})
        if row.agent_id != incident.agent_id or not identity or not _within(row.created_at, reference):
            continue
        if identity in by_identity:
            proc = by_identity[identity]
            for key in ("parent_pid", "name", "cmdline", "exe_path"):
                if not proc.get(key):
                    proc[key] = getattr(row, key)
                    if proc[key] is not None:
                        proc["supplement"] = "process_info"

    primary_identity = process_identity(_mapping(evidence.get("process")))
    tuple_key = _network_key(network)
    candidates = [(network, "incident_snapshot")] if network else []
    for row in flows:
        raw = _mapping(row.socket_evidence)
        if row.agent_id != incident.agent_id or not _within(raw.get("observed_at"), reference):
            continue
        if not _verified_attribution(raw):
            continue
        flow = {
            **raw, "protocol": row.protocol, "src_ip": row.src_ip, "src_port": row.src_port,
            "dst_ip": row.dst_ip, "dst_port": row.dst_port,
        }
        flow_key = _network_key(flow)
        if not flow_key or (tuple_key and flow_key != tuple_key):
            continue
        if not tuple_key and any(
            _value(network.get(key)) not in (NA, flow[key])
            for key in ("src_ip", "src_port", "dst_ip", "dst_port")
        ):
            continue
        if network.get("inode") and network["inode"] != flow["inode"]:
            continue
        if network.get("socket_id") and network["socket_id"] != flow.get("socket_id"):
            continue
        holders = _records(raw.get("holders"))
        if not any(process_identity(holder) in by_identity for holder in holders):
            continue
        for holder in holders:
            identity = process_identity(holder)
            if identity:
                by_identity.setdefault(identity, {**holder, "source": "flow_socket_evidence"})
        candidates.append((flow, "flow_socket_evidence"))

    process_ids = {key: f"P{index}" for index, key in enumerate(by_identity, 1)}
    related = _records(evidence.get("ancestry"))
    descendants = _records(evidence.get("descendants"))
    parent_by_child = {}
    child = _mapping(evidence.get("process"))
    for parent in related:
        c_identity, p_identity = process_identity(child), process_identity(parent)
        if not c_identity or not p_identity or child.get("parent_pid") != p_identity[0] or p_identity[1] > c_identity[1]:
            break
        parent_by_child[c_identity] = p_identity
        child = parent
    # Descendant edges come from the same snapshot and must resolve unambiguously.
    known = {key for key in (*parent_by_child, *parent_by_child.values(), primary_identity) if key}
    for child in descendants:
        identity = process_identity(child)
        if identity:
            parents = {key for key in known if key[0] == child.get("parent_pid") and key[1] <= identity[1]}
            if len(parents) == 1 and identity not in parents:
                parent_by_child[identity] = parents.pop()
                known.add(identity)

    for identity, proc in by_identity.items():
        item = {
            "id": process_ids[identity], "source": proc["source"], "pid": identity[0],
            "process_start_time": identity[1], "ppid": _value(proc.get("parent_pid")),
            "name": _value(proc.get("name") or proc.get("process_name")),
            "path": _value(proc.get("exe_path") or proc.get("exe")),
            "cmdline": _value(proc.get("cmdline")),
            "parent": process_ids.get(parent_by_child.get(identity), NA),
        }
        if proc.get("supplement"):
            item["supplement"] = proc["supplement"]
        for flag in ("interactive", "pty_requested"):
            if proc.get(flag) is True:
                item[flag] = True
        if isinstance(proc.get("terminal"), str) and proc["terminal"]:
            item["terminal"] = proc["terminal"]
        result.processes.append(item)
    result.mandatory.update(process_ids[key] for key in known if key in process_ids)
    unbound = _mapping(evidence.get("process"))
    if unbound and not primary_identity:
        result.processes.append({
            "id": f"P{len(result.processes) + 1}", "source": "incident_snapshot",
            "pid": _value(unbound.get("pid")), "process_start_time": NA,
            "ppid": _value(unbound.get("parent_pid")), "name": _value(unbound.get("name")),
            "path": _value(unbound.get("exe_path")), "cmdline": _value(unbound.get("cmdline")),
            "parent": NA,
        })
        result.missing.append("process_identity")

    seen = set()
    for raw, source in candidates:
        key = _network_key(raw)
        holder_links = []
        verified_inode = key is not None and _verified_attribution(raw)
        if verified_inode:
            for holder in _records(raw.get("holders")):
                identity = process_identity(holder)
                if identity in process_ids:
                    holder_links.append({
                        "process": process_ids[identity], "pid": identity[0],
                        "socket_fds": _fds(holder.get("socket_fds")), "stdio_fds": _fds(holder.get("stdio_fds")),
                    })
        signature = (tuple(key or ()), raw.get("inode") if verified_inode else None,
                     json.dumps(holder_links, sort_keys=True))
        if signature in seen:
            continue
        seen.add(signature)
        flow_id = f"N{len(result.flows) + 1}"
        tuple_fields = ("protocol", "src_ip", "src_port", "dst_ip", "dst_port")
        item = {
            "id": flow_id, "source": source,
            "tuple": dict(zip(
                tuple_fields, key or [_value(raw.get(field)) for field in tuple_fields], strict=True,
            )),
            "state": _value(raw.get("status")), "direction": _value(raw.get("direction")),
            "observed_at": _time(raw.get("observed_at")), "inode": _value(raw.get("inode")),
            "socket_id": _value(raw.get("socket_id")), "attribution": _value(raw.get("attribution")),
            "holders": holder_links,
            "originator_pid": _value(raw.get("originator_pid")),
            "primary_process": process_ids.get(primary_identity, NA)
            if source == "incident_snapshot" and any(
                link["process"] == process_ids.get(primary_identity) for link in holder_links
            ) else NA,
        }
        for counter in ("bytes_sent", "bytes_received"):
            if type(raw.get(counter)) is int and raw[counter] >= 0:
                item[counter] = raw[counter]
        network_identity = process_identity(raw)
        if source == "incident_snapshot" and network_identity and primary_identity and network_identity != primary_identity:
            item["primary_process"] = NA
            result.conflict = True
        result.flows.append(item)
        result.mandatory.add(flow_id)
        result.mandatory.update(link["process"] for link in holder_links)
        if rule_id == RULE_ID and verified_inode:
            proof_source = raw
            if source == "incident_snapshot" and primary_identity:
                proof_source = {
                    **raw, "holders": [
                        {**holder, "ancestry": related, "descendants": descendants}
                        if process_identity(holder) == primary_identity else holder
                        for holder in _records(raw.get("holders"))
                    ],
                }
            proof = detect_network_shell(proof_source)
            if proof and proof["classification"] == "High-Confidence Reverse Shell" and item["observed_at"] != NA:
                result.verified_shell = result.verified_shell or flow_id
                proven_identity = process_identity(_mapping(proof["process"]))
                conflict = not proven_identity or (primary_identity and primary_identity != proven_identity)
                if conflict:
                    item["primary_process"] = NA
                    result.conflict = True
        if len(holder_links) > 1 and item["primary_process"] == NA:
            result.conflict = True

    result.chain_count = len({
        link["process"] for flow in result.flows for link in flow["holders"]
    } - {item["parent"] for item in result.processes})

    if rule_id == FIM_RULE:
        fields = _mapping(fim) or _mapping(evidence.get("file")) or evidence
        detail = re.search(
            r"^Detail: path=(/[^\n]+?), action=(MODIFIED|CREATED|DELETED)"
            r"(?:, old_sha256=([0-9a-f]{64}|absent), new_sha256=([0-9a-f]{64}|absent))?$",
            incident.description or "", re.MULTILINE,
        )
        result.facts.append({
            "id": "F1", "source": "fim_event" if fim else "incident_snapshot" if fields.get("file_path") else "incident_description",
            "kind": "fim", "path": _value(fields.get("file_path") or fields.get("path") or (detail[1] if detail else None)),
            "operation": _value(fields.get("action") or fields.get("operation") or (detail[2] if detail else None)),
            "old_hash": _value(fields.get("old_hash") or (detail[3] if detail else None)),
            "new_hash": _value(fields.get("new_hash") or (detail[4] if detail else None)),
        })

    behavior = _mapping(evidence.get("behavior"))
    has_behavior = (isinstance(behavior.get("classification"), str) and behavior["classification"] in BEHAVIORS
                    and isinstance(behavior.get("source_event_ids"), list)
                    and bool(behavior["source_event_ids"]))
    if has_behavior:
        fields = (
            "evidence_id", "evidence_type", "source", "classification", "service", "source_ip",
            "username", "account_count", "authentication_status", "failed_attempts",
            "successful_attempts", "error_attempts", "first_attempt_at", "last_attempt_at",
            "detection_window_seconds", "time_basis", "request_method", "request_path",
            "http_status", "request_id", "http_event_id", "user_agent", "payload_indicators",
            "exploitation_outcome", "brute_force_criteria", "protocol", "direction",
            "destination_ip", "connection_count", "automation_hint", "legacy_duplicate_status",
            "timestamp_resolution", "indicator_event_count",
        )
        fact = {field: behavior[field] for field in fields if behavior.get(field) is not None}
        event_ids = behavior["source_event_ids"]
        ordered_ids = list(dict.fromkeys([*behavior.get("indicator_source_event_ids", []), *event_ids]))
        fact.update(
            id=f"F{len(result.facts) + 1}", kind="behavior",
            source_event_ids=ordered_ids[:5], source_event_count=len(event_ids),
            omitted_source_event_ids=max(0, len(event_ids) - 5),
        )
        if behavior.get("source_ips"):
            fact["source_ips"] = behavior["source_ips"][:8]
        if behavior.get("classification") == SCAN:
            fact["destination_port_count"] = len(behavior.get("destination_ports", []))
            fact["destination_ports"] = behavior.get("destination_ports", [])[:16]
            fact["connections"] = [
                {**sample, "holders": (sample.get("holders") or [])[:2]}
                for sample in _records(behavior.get("connections"))[:5]
            ]
        has_original_time = not set(fact.get("time_basis", ())) & {
            "agent_receipt", "manager_receipt", "legacy_receipt",
        }
        has_request = bool(fact.get("request_method") and fact.get("request_path"))
        if not has_original_time:
            result.missing.append("source_attempt_timestamps")
        if behavior.get("classification") == SQLI and not has_request:
            result.missing.append("http_request_metadata")
        fact["evidence_completeness"] = "complete" if has_original_time and not (
            behavior.get("classification") == SQLI and not has_request
        ) else "partial"
        technique = technique_for(behavior)
        if technique:
            fact["verified_technique"] = technique
        result.facts.append(fact)
        result.mandatory.add(fact["id"])

    for factor in _records(evidence.get("factors")):
        name = _value(factor.get("rule"))
        fact = {
            "id": f"F{len(result.facts) + 1}", "source": "incident_snapshot",
            "kind": "authentication" if name == AUTH_RULE else "risk_factor",
            "rule": name, "score": _value(factor.get("score")), "reason": _value(factor.get("reason")),
        }
        if name == AUTH_RULE and has_behavior:
            continue
        if name == AUTH_RULE:
            auth = {**_mapping(evidence.get("auth")), **factor}
            reason = fact["reason"]
            match = re.fullmatch(
                r"Brute force on ([\w-]+) (?:from (\S+): \d+ failed logins|account '([^']+)': \d+ failed logins from \d+ sources)"
                r"|([\w-]+) login for '([^']+)' from (\S+) after \d+ failed attempts for the same account and source",
                reason if isinstance(reason, str) else "",
            )
            count = re.search(r"\b(\d{1,10}) failed (?:logins|attempts)\b", reason) if isinstance(reason, str) else None
            fact.update({
                "reported_failed_attempts": int(count[1]) if count else NA,
                "evidence_completeness": "partial",
                "account": _value(auth.get("account") or auth.get("username") or (match[3] or match[5] if match else None)),
                "source_ip": _value(auth.get("source_ip") or (match[2] or match[6] if match else None)),
                "service": _value(auth.get("service") or (match[1] or match[4] if match else None)),
                "window_seconds": _value(auth.get("window_seconds")),
                "window_start": _time(auth.get("window_start")), "window_end": _time(auth.get("window_end")),
            })
        result.facts.append(fact)

    if rule_id == AUTH_RULE and not has_behavior:
        result.missing.append("auth_event_references")
    if rule_id == AUTH_RULE and not has_behavior and not any(fact["kind"] == "authentication" for fact in result.facts):
        auth = _mapping(evidence.get("auth")) or evidence
        result.facts.append({
            "id": f"F{len(result.facts) + 1}", "source": "incident_snapshot", "kind": "authentication",
            "rule": AUTH_RULE, "account": _value(auth.get("account") or auth.get("username")),
            "source_ip": _value(auth.get("source_ip")), "service": _value(auth.get("service")),
            "window_seconds": _value(auth.get("window_seconds")),
            "window_start": _time(auth.get("window_start")), "window_end": _time(auth.get("window_end")),
        })

    if not result.facts and not result.flows and not result.processes and incident.description:
        result.facts.append({
            "id": "F1", "source": "incident_description", "kind": "unstructured",
            "text": incident.description,
        })
    if rule_id == RULE_ID or result.flows or result.processes:
        if not result.processes:
            result.missing.append("process_identity")
        if not result.flows:
            result.missing.append("network_observation")
        elif not any(flow["holders"] for flow in result.flows):
            result.missing.append("verified_socket_holder")
        if result.conflict:
            result.missing.append("unique_socket_attribution")
    if not result.by_id:
        result.missing.append("incident_evidence")
    result.mandatory.update(fact["id"] for fact in result.facts if fact["kind"] in {"fim", "authentication"})
    return result


async def load_alert_context(session, incident) -> AlertContext:
    evidence, network, observations = _snapshot(incident)
    identities = {identity for proc in observations if (identity := process_identity(proc))}
    reference = as_utc(network.get("observed_at") or evidence.get("last_observed_at") or incident.created_at)
    agent = await session.get(Agent, incident.agent_id) if incident.agent_id else None
    processes, flows, fim = [], [], None
    if agent is not None and reference is not None:
        start, end = reference - WINDOW, reference + WINDOW
        if identities:
            processes = (await session.scalars(
                select(ProcessInfo).where(
                    ProcessInfo.agent_id == incident.agent_id,
                    ProcessInfo.created_at.between(start, end),
                    or_(*(and_(ProcessInfo.pid == pid, ProcessInfo.process_start_time == started)
                          for pid, started in sorted(identities)[:32])),
                ).order_by(ProcessInfo.created_at.desc()).limit(48)
            )).all()
            key = _network_key(network)
            scope = and_(Flow.protocol == key[0], Flow.src_ip == key[1], Flow.src_port == key[2],
                         Flow.dst_ip == key[3], Flow.dst_port == key[4]) if key else true()
            if not _records(network.get("holders")) or not _verified_attribution(network):
                flows = (await session.scalars(
                    select(Flow).where(
                        Flow.agent_id == incident.agent_id, Flow.start_time.between(start, end),
                        Flow.socket_evidence.is_not(None), scope,
                    ).order_by(Flow.start_time.desc()).limit(64)
                )).all()
        if _rule_id(incident, evidence) == FIM_RULE and incident.fingerprint:
            events = (await session.scalars(
                select(Event).where(
                    Event.agent_id == incident.agent_id, Event.event_type == "FIM_ALERT",
                    Event.created_at.between(start, end),
                ).order_by(Event.created_at.desc()).limit(32)
            )).all()
            for event in events:
                matches = match_endpoint_telemetry({"file_changes": [event.details]})
                if any(RuleEngine._fingerprint(match) == incident.fingerprint for match in matches):
                    fim = event.details
                    break
    return build_alert_context(
        incident, hostname=agent.hostname if agent else None, processes=processes, flows=flows, fim=fim,
    )
