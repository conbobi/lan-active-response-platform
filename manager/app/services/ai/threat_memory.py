"""AI Threat Memory: reuse of validated analysis knowledge across incidents of the same attack pattern.

Sits in front of the model call inside AI triage (it never runs detection, never changes severity or
risk score and never creates or executes a response action):

    EXACT_CACHE        the incident's threat fingerprint equals a usable memory entry: the stored
                       template (classification + MITRE techniques bound to evidence *roles*) is
                       re-bound to this incident's evidence IDs and re-validated; no model call.
    SEMANTIC_ASSISTED  no exact entry, but similar entries exist (same platform and schema): they are
                       passed to the model as reference context only; the model analyses current evidence.
    FRESH_LLM          nothing usable: normal model analysis; a validated result is stored.
    RULE_BASED_FALLBACK  the model was not used or failed; the deterministic verdict is shown.

Fingerprints are built from normalised technical features only (rule and version, evidence roles,
behaviour features, platform, schema versions) and never from incident ID, agent, timestamps, PIDs,
IPs, request IDs or file names, which stay in the incident's own evidence.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import posixpath
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models.ai_cache import ThreatMemory, ThreatMemoryEvent

logger = logging.getLogger("larp.ai.threat_memory")

FINGERPRINT_VERSION = "tf-1"
TELEMETRY_SCHEMA_VERSION = "telemetry-2"
TTL = timedelta(days=float(os.getenv("THREAT_MEMORY_TTL_DAYS", "14")))
LOOKUP_TIMEOUT = float(os.getenv("THREAT_MEMORY_LOOKUP_TIMEOUT", "1.5"))
USABLE = {"auto_validated", "soc_verified"}
SEMANTIC_TOP_K = 3
SEMANTIC_MIN_RELEVANCE = 0.25  # relevance filter for context only; never a "same attack" decision
EXACT, SEMANTIC, FRESH, FALLBACK = "EXACT_CACHE", "SEMANTIC_ASSISTED", "FRESH_LLM", "RULE_BASED_FALLBACK"

INTERPRETERS = {"python", "perl", "php", "ruby", "node", "nodejs", "java", "pwsh", "powershell", "lua"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "busybox", "cmd"}
CMD_FEATURES = {
    "shell_chaining": re.compile(r"[;|&`]|\$\("),
    "interactive_flag": re.compile(r"(?:^|\s)-[a-z]*i(?:\s|$)"),
    "dev_tcp": re.compile(r"/dev/(?:tcp|udp)/"),
    "download_tool": re.compile(r"\b(?:curl|wget|certutil|bitsadmin)\b", re.I),
    "temp_path": re.compile(r"(?:^|[\s'\"])(?:/tmp/|/dev/shm/|/var/tmp/)|\\temp\\", re.I),
    "upload_dir": re.compile(r"/uploads?/", re.I),
    "encoded_payload": re.compile(r"base64|-enc(?:odedcommand)?\b", re.I),
    "inline_code": re.compile(r"(?:^|\s)-c\s", re.I),
    "netcat_exec": re.compile(r"\bnc(?:at)?\b.*\s-[a-z]*e", re.I),
}
# Classification → response playbook *names* (references only; proposals are always re-created by policy).
PLAYBOOKS = {
    "likely_malicious": ["collect_additional_evidence", "kill_process_tree", "block_ip", "isolate"],
    "confirmed_malicious": ["collect_additional_evidence", "kill_process_tree", "block_ip", "isolate"],
    "sqli_probe_observed": ["collect_additional_evidence", "temporary_ip_block", "apply_rate_limit"],
    "sqli_probing": ["collect_additional_evidence", "temporary_ip_block", "apply_rate_limit"],
    "sqli_exploitation_suspected": ["collect_additional_evidence", "revoke_session", "temporary_ip_block"],
    "sqli_exploitation_confirmed": ["collect_additional_evidence", "revoke_session", "temporary_ip_block"],
    "authentication_brute_force": ["collect_additional_evidence", "temporary_ip_block"],
    "repeated_auth_failures": ["collect_additional_evidence"],
}
SUPPORTED_ACTIONS = {"collect_additional_evidence", "kill_process_tree", "block_ip", "isolate", "temporary_ip_block",
                     "apply_rate_limit", "revoke_session", "increase_monitoring", "generate_remediation_guidance"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def utc(value):
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _base(value) -> str:
    text = str(value or "").replace("\\", "/").strip().split(" ")[0]
    name = posixpath.basename(text).lower().removesuffix(".exe")
    return re.sub(r"[\d.]+$", "", name) or name  # python3.13 → python


def cmd_features(*cmdlines) -> List[str]:
    out = set()
    for cmd in cmdlines:
        for name, pattern in CMD_FEATURES.items():
            if cmd and pattern.search(str(cmd)):
                out.add(name)
    return sorted(out)


def port_class(port) -> str:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "unknown"
    return "well_known" if port < 1024 else "registered" if port < 49152 else "dynamic"


# ── fingerprint ─────────────────────────────────────────────────────────────────────────────
def evidence_role(item: Dict[str, Any], context) -> str:
    """Abstract role of one context evidence item: what it is, not which instance it is."""
    item_id = str(item.get("id", ""))
    if item_id.startswith("P"):
        return f"process:{_base(item.get('name') or item.get('exe_path'))}"
    if item.get("kind") is None and ("holders" in item or "tuple" in item or item_id.startswith("N")):
        verified = "verified_shell" if getattr(context, "verified_shell", None) == item_id else "flow"
        return f"network:{item.get('direction') or 'unknown'}:{verified}"
    kind = item.get("kind") or "fact"
    if kind == "behavior":
        return f"behavior:{item.get('classification')}"
    if kind == "risk_factor":
        return f"factor:{item.get('rule') or item.get('name') or 'unknown'}"
    if kind == "chain_stage":
        return f"stage:{item.get('stage')}:{item.get('status')}"
    if kind == "fim":
        return f"fim:{str(item.get('operation') or '').lower()}"
    return kind


def platform_of(incident, context) -> str:
    paths = [p.get("exe_path") or p.get("name") or "" for p in getattr(context, "processes", [])]
    chain = (incident.detection_evidence or {}).get("chain") or {}
    paths += [p.get("exe") or "" for p in chain.get("process_tree") or []]
    process = (incident.detection_evidence or {}).get("process") or {}
    paths.append(process.get("exe_path") or "")
    joined = " ".join(str(p) for p in paths)
    if re.search(r"[a-z]:\\|\.exe\b", joined, re.I):
        return "windows"
    if re.search(r"(?:^|\s)/(?:usr|bin|sbin|opt|tmp|home|lib)", joined):
        return "linux"
    return "unknown"


def behavior_features(evidence: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    chain = evidence.get("chain") or {}
    if chain:
        stages = {c["id"]: c["status"] for c in chain.get("conditions") or [] if c.get("status") in ("OBSERVED", "CORRELATED")}
        processes = chain.get("process_tree") or []
        anchor = (chain.get("anchor") or {}).get("id")
        out["chain"] = {
            "stages": stages,
            "spawned": sorted({_base(p.get("exe") or p.get("name")) for p in processes if p.get("id") != anchor}),
            "cmd": cmd_features(*[p.get("cmdline") for p in processes if p.get("id") != anchor]),
            "network": sorted({f"{'stdio' if n.get('socket_stdio') else 'socket'}:{n.get('direction') or 'unknown'}:"
                               f"{port_class(str(n.get('dst', '')).rsplit(':', 1)[-1])}" for n in chain.get("network") or []}),
            "privileged": any(p.get("euid") == 0 for p in processes if p.get("id") != anchor),
        }
    behavior = evidence.get("behavior") or {}
    if behavior.get("classification"):
        status = behavior.get("http_status")
        out["behavior"] = {
            "classification": behavior.get("classification"), "type": behavior.get("evidence_type"),
            "indicators": sorted(behavior.get("payload_indicators") or []),
            "automation": behavior.get("automation_hint"), "outcome": behavior.get("exploitation_outcome"),
            "http_status_class": f"{str(status)[0]}xx" if status else None,
        }
    process = evidence.get("process") or {}
    if process.get("exe_path") or process.get("cmdline"):
        out["process"] = {"exe": _base(process.get("exe_path") or process.get("name")),
                          "cmd": cmd_features(process.get("cmdline"))}
    if evidence.get("network"):
        out["network"] = {"port_class": port_class((evidence["network"] or {}).get("dst_port"))}
    return out


@dataclass
class Fingerprint:
    value: str
    features: Dict[str, Any]
    platform: str
    rule_ids: List[str]
    roles: Dict[str, str]  # context evidence id → role

    @property
    def short(self) -> str:
        return self.value[:12]

    def tokens(self) -> set:
        return set(_flatten(self.features))


def _flatten(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("fingerprint_version", "telemetry_schema_version", "platform"):
                continue
            yield from _flatten(item, f"{prefix}{key}.")
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _flatten(item, prefix)
    elif value is not None and value is not False:
        yield f"{prefix.rstrip('.')}={value}"


def build_fingerprint(incident, context) -> Fingerprint:
    roles = {item["id"]: evidence_role(item, context) for item in context.by_id.values()}
    evidence = incident.detection_evidence or {}
    metadata = context.metadata or {}
    rule_ids = sorted({str(r) for r in (metadata.get("rule_id"), evidence.get("rule_id")) if r})
    platform = platform_of(incident, context)
    features = {
        "fingerprint_version": FINGERPRINT_VERSION, "telemetry_schema_version": TELEMETRY_SCHEMA_VERSION,
        "platform": platform, "rule_ids": rule_ids,
        "rule_version": str(metadata.get("rule_version") or evidence.get("rule_version") or ""),
        "roles": sorted(set(roles.values())), "mapped_techniques": sorted(getattr(context, "mapped_techniques", ()) or ()),
        "verified_shell": bool(getattr(context, "verified_shell", None)), "conflict": bool(getattr(context, "conflict", False)),
        "missing": sorted(set(getattr(context, "missing", []) or [])),
        "behavior": behavior_features(evidence),
    }
    digest = hashlib.sha256(canonical(features).encode()).hexdigest()
    return Fingerprint(digest, features, platform, rule_ids, roles)


def similarity(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    return round(len(left & right) / len(left | right), 3)


# ── templates ───────────────────────────────────────────────────────────────────────────────
class Ineligible(ValueError):
    """The memory entry cannot be applied to this incident (reason is the message)."""


def make_template(verdict, fp: Fingerprint) -> Dict[str, Any]:
    """Verdict → role-based template. Refuses if a cited item's role is not unique (re-binding would guess)."""
    counts: Dict[str, int] = {}
    for role in fp.roles.values():
        counts[role] = counts.get(role, 0) + 1
    cited = list(verdict.evidence_ids)
    if not cited:
        raise Ineligible("no_evidence")
    for item in cited:
        role = fp.roles.get(item)
        if role is None or counts.get(role) != 1:
            raise Ineligible("ambiguous_evidence_role")
    techniques = []
    for tech in verdict.techniques:
        ids = [e.strip() for e in str(tech.get("evidence", "")).split(",") if e.strip()]
        techniques.append({"id": tech["id"], "roles": [fp.roles[e] for e in ids if e in fp.roles]})
    return {"classification": verdict.classification, "confidence": round(float(verdict.confidence), 2),
            "evidence_roles": [fp.roles[e] for e in cited], "techniques": techniques,
            "evidence_completeness": verdict.evidence_completeness}


def rebind(template: Dict[str, Any], fp: Fingerprint) -> Dict[str, Any]:
    """Template roles → this incident's evidence IDs (each role must exist exactly once)."""
    by_role: Dict[str, List[str]] = {}
    for item_id, role in fp.roles.items():
        by_role.setdefault(role, []).append(item_id)

    def bind(role):
        ids = by_role.get(role) or []
        if len(ids) != 1:
            raise Ineligible("evidence_incomplete" if not ids else "ambiguous_evidence_role")
        return ids[0]
    return {
        "evidence_ids": [bind(r) for r in template["evidence_roles"]],
        "classification": template["classification"], "confidence": template["confidence"],
        "mitre_techniques": [{"id": t["id"], "evidence_ids": [bind(r) for r in t["roles"]]}
                             for t in template.get("techniques", []) if t.get("roles")],
    }


def pattern_name(fp: Fingerprint, classification: str) -> str:
    chain = (fp.features.get("behavior") or {}).get("chain")
    if chain:
        stages = chain.get("stages") or {}
        kind = "Web compromise" if {"web_spawned_shell", "uploaded_file_execution"} & set(stages) else "Web intrusion"
        extra = []
        if "outbound_connection" in stages:
            extra.append("reverse shell/C2")
        if "privileged_execution" in stages:
            extra.append("root")
        return f"{kind} ({', '.join(extra)})" if extra else kind
    behavior = (fp.features.get("behavior") or {}).get("behavior") or {}
    if behavior:
        return f"{str(behavior.get('classification', classification)).replace('_', ' ').capitalize()} ({fp.platform})"
    return f"{classification.replace('_', ' ').capitalize()} ({fp.platform})"


# ── usability ───────────────────────────────────────────────────────────────────────────────
def usable(entry: ThreatMemory, *, model_name: str, prompt_version: str, at: Optional[datetime] = None) -> Optional[str]:
    """None when usable, else the reason it must not be reused."""
    at = at or now()
    if entry.validation_status not in USABLE:
        return f"status_{entry.validation_status}"
    if utc(entry.expires_at) <= at:
        return "expired"
    if entry.fingerprint_version != FINGERPRINT_VERSION:
        return "fingerprint_version"
    if entry.telemetry_schema_version != TELEMETRY_SCHEMA_VERSION:
        return "telemetry_schema_version"
    if entry.prompt_version != prompt_version or entry.model_name != model_name:
        return "model_or_prompt_version"
    playbook = (entry.response_playbook_reference or {}).get("actions") or []
    if any(action not in SUPPORTED_ACTIONS for action in playbook):
        return "playbook_unsupported"
    return None


# ── single flight ───────────────────────────────────────────────────────────────────────────
_locks: Dict[str, asyncio.Lock] = {}


@asynccontextmanager
async def single_flight(fingerprint: str):
    """One analysis per fingerprint at a time in this process (others then hit the stored entry)."""
    lock = _locks.setdefault(fingerprint, asyncio.Lock())
    async with lock:
        yield
    if not lock.locked() and len(_locks) > 2048:
        _locks.pop(fingerprint, None)


# ── lookup / store ──────────────────────────────────────────────────────────────────────────
@dataclass
class Decision:
    source: str
    fingerprint: Optional[Fingerprint] = None
    entry: Optional[Dict[str, Any]] = None
    bound: Optional[Dict[str, Any]] = None
    similar: List[Dict[str, Any]] = field(default_factory=list)
    reason: Optional[str] = None
    stale_rejected: bool = False
    lookup_error: bool = False
    lookup_ms: Optional[float] = None
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:24])


def entry_view(entry: ThreatMemory) -> Dict[str, Any]:
    return {
        "id": entry.id, "attack_pattern": entry.attack_pattern, "platform": entry.platform,
        "validation_status": entry.validation_status, "reviewer": entry.reviewer,
        "mitre_techniques": entry.mitre_techniques or [], "detection_rule_ids": entry.detection_rule_ids or [],
        "classification": (entry.analysis_template or {}).get("classification"),
        "evidence_requirements": entry.evidence_requirements or [],
        "playbook": (entry.response_playbook_reference or {}).get("actions") or [],
        "model_name": entry.model_name, "prompt_version": entry.prompt_version,
        "created_at": iso(entry.created_at), "updated_at": iso(entry.updated_at), "expires_at": iso(entry.expires_at),
        "last_used_at": iso(entry.last_used_at), "usage_count": entry.usage_count,
        "quality_score": round(entry.quality_score, 2), "status_reason": entry.status_reason,
        "fingerprint_short": entry.fingerprint[:12],
    }


def iso(value):
    return utc(value).isoformat() if value else None


async def lookup(session_factory, fp: Fingerprint, *, model_name: str, prompt_version: str, tenant="default",
                 allow_exact=True) -> Decision:
    """Exact then semantic lookup in a short dedicated session with its own timeout."""
    started = time.monotonic()
    decision = Decision(FRESH, fingerprint=fp)
    try:
        async with asyncio.timeout(LOOKUP_TIMEOUT):
            async with session_factory() as session:
                scope = select(ThreatMemory).where(
                    ThreatMemory.tenant == tenant, ThreatMemory.platform == fp.platform,
                    ThreatMemory.fingerprint_version == FINGERPRINT_VERSION,
                    ThreatMemory.telemetry_schema_version == TELEMETRY_SCHEMA_VERSION,
                )
                if allow_exact:
                    exact = (await session.scalars(scope.where(ThreatMemory.fingerprint == fp.value)
                                                   .order_by(ThreatMemory.updated_at.desc()))).all()
                    for row in exact:
                        reason = usable(row, model_name=model_name, prompt_version=prompt_version)
                        if reason is None:
                            decision.source, decision.entry = EXACT, entry_view(row)
                            decision.entry["template"] = row.analysis_template
                            break
                        decision.reason, decision.stale_rejected = reason, True
                else:
                    decision.reason = "forced_fresh"
                if decision.source != EXACT:
                    tokens = fp.tokens()
                    scored = []
                    candidates = scope.where(ThreatMemory.fingerprint != fp.value,
                        ThreatMemory.model_name == model_name, ThreatMemory.prompt_version == prompt_version,
                        ThreatMemory.validation_status.in_(USABLE), ThreatMemory.expires_at > now()
                    ).order_by(ThreatMemory.updated_at.desc(), ThreatMemory.id).limit(500)
                    for row in (await session.scalars(candidates)).all():
                        if usable(row, model_name=model_name, prompt_version=prompt_version):
                            continue
                        score = similarity(tokens, set(_flatten(row.behavioral_features)))
                        if score >= SEMANTIC_MIN_RELEVANCE:
                            scored.append((score, row))
                    scored.sort(key=lambda pair: pair[0], reverse=True)
                    decision.similar = [{**entry_view(r), "similarity": s, "template": r.analysis_template}
                                        for s, r in scored[:SEMANTIC_TOP_K]]
                    if decision.similar:
                        decision.source = SEMANTIC
    except Exception as exc:  # noqa: BLE001 - the memory is optional; analysis continues without it
        logger.warning("Threat memory lookup failed fingerprint=%s error=%s", fp.short, type(exc).__name__)
        decision = Decision(FRESH, fingerprint=fp, reason="lookup_timeout" if isinstance(exc, TimeoutError) else "lookup_error",
                            lookup_error=True)
    decision.lookup_ms = round((time.monotonic() - started) * 1000, 2)
    logger.info("Threat memory decision request=%s fingerprint=%s source=%s reason=%s lookup_ms=%s",
                decision.request_id, fp.short, decision.source, decision.reason, decision.lookup_ms)
    return decision


def references_for(similar: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Similar patterns as prompt references: labelled context, never evidence."""
    out = []
    for item in similar[:2]:
        template = item.get("template") or {}
        out.append({
            "id": f"memory:{item['id'][-8:]}", "source": "larp_threat_memory", "version": FINGERPRINT_VERSION,
            "excerpt": (f"Reference only (not evidence): a previously validated pattern '{item['attack_pattern']}' "
                        f"(similarity {item['similarity']}) was classified {template.get('classification')} with "
                        f"techniques {', '.join(t['id'] for t in template.get('techniques', [])) or 'none'}. "
                        "Judge the current evidence on its own."),
        })
    return out


async def store(session_factory, fp: Fingerprint, template: Dict[str, Any], *, model_name: str, prompt_version: str,
                incident_id: str, tenant="default") -> Optional[str]:
    """Insert (or refresh) the validated template; a duplicate concurrent insert is absorbed."""
    classification = template["classification"]
    playbook = [a for a in PLAYBOOKS.get(classification, ["collect_additional_evidence"]) if a in SUPPORTED_ACTIONS]
    stamp = now()
    try:
        async with session_factory() as session, session.begin():
            existing = (await session.scalars(select(ThreatMemory).where(
                ThreatMemory.tenant == tenant, ThreatMemory.fingerprint == fp.value,
                ThreatMemory.fingerprint_version == FINGERPRINT_VERSION, ThreatMemory.prompt_version == prompt_version,
                ThreatMemory.model_name == model_name))).first()
            if existing is not None:
                if existing.validation_status in USABLE:
                    return existing.id
                if existing.validation_status in ("revoked", "incorrect"):
                    return None  # SOC rejected this pattern's analysis: never re-learn it silently
                existing.analysis_template, existing.validation_status = template, "auto_validated"
                existing.updated_at, existing.expires_at, existing.status_reason = stamp, stamp + TTL, "relearned"
                return existing.id
            row = ThreatMemory(
                tenant=tenant, fingerprint=fp.value, fingerprint_version=FINGERPRINT_VERSION,
                attack_pattern=pattern_name(fp, classification)[:160], platform=fp.platform,
                detection_rule_ids=fp.rule_ids, mitre_techniques=sorted({t["id"] for t in template["techniques"]}),
                behavioral_features=fp.features, analysis_template=template,
                response_playbook_reference={"actions": playbook, "note": "Chỉ tham khảo; đề xuất luôn được tạo lại theo policy"},
                evidence_requirements=sorted(set(template["evidence_roles"])), model_name=model_name,
                prompt_version=prompt_version, telemetry_schema_version=TELEMETRY_SCHEMA_VERSION,
                validation_status="auto_validated", source_incident_id=incident_id, created_at=stamp, updated_at=stamp,
                expires_at=stamp + TTL, quality_score=0.6,
            )
            session.add(row)
            await session.flush()
            return row.id
    except IntegrityError:
        return None  # another worker stored the same pattern first
    except Exception as exc:  # noqa: BLE001
        logger.warning("Threat memory store failed fingerprint=%s error=%s", fp.short, type(exc).__name__)
        return None


async def mark_used(session_factory, memory_id: str) -> None:
    try:
        async with session_factory() as session, session.begin():
            row = await session.get(ThreatMemory, memory_id, with_for_update=True)
            if row is not None:
                row.usage_count += 1
                row.last_used_at = now()
                row.quality_score = min(1.0, row.quality_score + 0.02)
    except Exception:  # noqa: BLE001
        logger.warning("Threat memory usage update failed")


async def penalize(session_factory, memory_id: str, reason: str) -> None:
    """Current evidence contradicted the entry: lower its quality; below 0.3 it stops being reused."""
    try:
        async with session_factory() as session, session.begin():
            row = await session.get(ThreatMemory, memory_id, with_for_update=True)
            if row is not None:
                row.quality_score = max(0.0, row.quality_score - 0.25)
                row.status_reason = reason
                if row.quality_score < 0.3 and row.validation_status == "auto_validated":
                    row.validation_status = "low_quality"
                row.updated_at = now()
    except Exception:  # noqa: BLE001
        logger.warning("Threat memory penalty failed")


async def record_event(session_factory, decision: Decision, *, incident_id, final_source, llm_ms=None, total_ms=None,
                       tokens=None, memory_id=None) -> None:
    try:
        async with session_factory() as session, session.begin():
            session.add(ThreatMemoryEvent(
                request_id=decision.request_id, incident_id=incident_id, decision=final_source,
                memory_id=memory_id or (decision.entry or {}).get("id"), reason=decision.reason,
                stale_rejected=decision.stale_rejected, lookup_error=decision.lookup_error,
                lookup_ms=decision.lookup_ms, llm_ms=llm_ms, total_ms=total_ms, tokens=tokens))
    except Exception:  # noqa: BLE001
        logger.warning("Threat memory event write failed")


# ── management ──────────────────────────────────────────────────────────────────────────────
async def set_status(session, memory_id: str, status: str, actor: str, reason: Optional[str]) -> ThreatMemory:
    row = await session.get(ThreatMemory, memory_id, with_for_update=True)
    if row is None:
        raise KeyError(memory_id)
    row.validation_status, row.reviewer, row.status_reason, row.updated_at = status, actor, (reason or "")[:255], now()
    if status == "soc_verified":
        row.quality_score = max(row.quality_score, 0.9)
    return row


async def invalidate_rule(session, rule_id: str, reason: str) -> int:
    """Detection logic changed or was disabled: entries built on it are no longer reusable."""
    rows = (await session.scalars(select(ThreatMemory).where(ThreatMemory.validation_status.in_(USABLE)))).all()
    count = 0
    for row in rows:
        if rule_id in (row.detection_rule_ids or []):
            row.validation_status, row.status_reason, row.updated_at = "invalidated", reason[:255], now()
            count += 1
    return count


async def metrics(session, days: int = 7) -> Dict[str, Any]:
    since = now() - timedelta(days=days)
    rows = (await session.scalars(select(ThreatMemoryEvent).where(ThreatMemoryEvent.created_at >= since))).all()
    total = len(rows)
    by = {}
    for row in rows:
        by[row.decision] = by.get(row.decision, 0) + 1

    def rate(count):
        return round(count / total, 3) if total else None

    def avg(values):
        values = [v for v in values if v is not None]
        return round(sum(values) / len(values), 1) if values else None
    invalidated = await session.scalar(select(func.count()).select_from(ThreatMemory).where(
        ThreatMemory.validation_status.in_(["invalidated", "revoked", "incorrect", "low_quality"])))
    entries = await session.scalar(select(func.count()).select_from(ThreatMemory))
    return {
        "window_days": days, "analyses": total, "entries": entries or 0,
        "exact_hit_rate": rate(by.get(EXACT, 0)), "semantic_rate": rate(by.get(SEMANTIC, 0)),
        "miss_rate": rate(by.get(FRESH, 0)), "fallback_rate": rate(by.get(FALLBACK, 0)),
        "invalidated_entries": invalidated or 0,
        "error_rate": rate(sum(1 for r in rows if r.lookup_error)),
        "stale_rejection_rate": rate(sum(1 for r in rows if r.stale_rejected)),
        "avg_lookup_ms": avg([r.lookup_ms for r in rows]),
        "avg_llm_ms": avg([r.llm_ms for r in rows if r.decision in (FRESH, SEMANTIC)]),
        "avg_total_ms_exact": avg([r.total_ms for r in rows if r.decision == EXACT]),
        "avg_total_ms_llm": avg([r.total_ms for r in rows if r.decision in (FRESH, SEMANTIC)]),
        "tokens": sum(r.tokens or 0 for r in rows) or None,
        "counts": by,
    }
