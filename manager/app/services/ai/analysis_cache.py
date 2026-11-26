"""Three-tier AI analysis cache.

L1  exact analysis cache (table ``ai_analysis_cache``): a hit means the model would receive exactly the
    same input (evidence payload, detection type, model, prompt, schema, knowledge version, tenant), so
    the stored, already validated output can be reused instead of calling the model again.
L2  similar-pattern retrieval (table ``incident_pattern_cases``): de-identified behaviour fingerprints of
    analyst-labelled incidents. A match returns reviewed guidance references only, never evidence,
    identities, exploitation outcome or action authorization.
L3  in-memory knowledge retrieval cache in front of ``kb.search``.

Nothing here is evidence and nothing here is memory for the model: Ollama ``keep_alive`` only keeps the
weights loaded. Callers own the transaction; L1/L2 functions flush but never commit.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_cache import AIAnalysisCache, IncidentPatternCase
from app.models.incident import Incident

logger = logging.getLogger(__name__)

DEFAULT_TENANT = "default"
DEFAULT_TTL = timedelta(seconds=int(os.getenv("AI_CACHE_TTL_SECONDS", str(24 * 3600))))
DEFAULT_MAX_ROWS = int(os.getenv("AI_CACHE_MAX_ROWS", "5000"))
MAX_PAYLOAD_BYTES = 64 * 1024

# ---------------------------------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------------------------------

TIERS = ("l1", "l2", "l3")
_COUNTERS = ("hits", "misses", "stale", "evictions", "refused", "queries", "matches", "invalidations")
LATENCY_SAMPLES = 512


class CacheMetrics:
    """Thread-safe counters and a bounded latency ring buffer per tier."""

    def __init__(self, samples: int = LATENCY_SAMPLES):
        self._lock = threading.Lock()
        self._samples = samples
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._counts = {tier: dict.fromkeys(_COUNTERS, 0) for tier in TIERS}
            self._latency = {tier: deque(maxlen=self._samples) for tier in TIERS}

    def incr(self, tier: str, counter: str, amount: int = 1) -> None:
        with self._lock:
            self._counts[tier][counter] += amount

    def observe(self, tier: str, milliseconds: float) -> None:
        with self._lock:
            self._latency[tier].append(milliseconds)

    @contextmanager
    def timed(self, tier: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(tier, (time.perf_counter() - start) * 1000)

    def snapshot(self) -> dict:
        with self._lock:
            result = {}
            for tier in TIERS:
                samples = sorted(self._latency[tier])
                result[tier] = {
                    **self._counts[tier],
                    "latency_ms": {"p50": _percentile(samples, 50), "p95": _percentile(samples, 95),
                                   "samples": len(samples)},
                }
            return result


def _percentile(ordered: list[float], percent: int) -> float | None:
    """Nearest-rank percentile of an already sorted list."""
    if not ordered:
        return None
    rank = max(1, -(-percent * len(ordered) // 100))
    return round(ordered[rank - 1], 3)


metrics = CacheMetrics()


def cache_stats() -> dict:
    """Per tier: hits, misses, stale, evictions, refused, L2 queries/matches, L3 invalidations, p50/p95."""
    return metrics.snapshot()


def reset_cache_stats() -> None:
    metrics.reset()


# ---------------------------------------------------------------------------------------------------
# Canonical form, scrubbing and refusal
# ---------------------------------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    """Deterministic, whitespace-free JSON used for hashing and size accounting."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


SECRET_KEYS = frozenset({
    "password", "passwd", "pwd", "token", "secret", "cookie", "cookies", "authorization", "set_cookie",
    "session", "api_key", "apikey", "raw_payload", "raw_message", "body", "request_body", "response_body",
    "private_key", "credentials",
})
_SECRET_PART = re.compile(r"(^|_)(password|passwd|secret|token|cookie|api_?key|session)(_|$)")
# Approval, authorization and execution state must never be served from a cache.
STATE_KEYS = frozenset({
    "status", "approved", "approved_by", "approved_at", "approval", "approval_status", "authorization",
    "authorized", "authorized_by", "dispatch", "dispatched", "dispatched_at", "executed", "executed_by",
    "executed_at", "execution_status",
})
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


class UncacheableOutput(ValueError):
    """The output carries state that must never be cached, or exceeds the payload limit."""


def _key_name(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_")


def find_state_keys(value: Any) -> set[str]:
    """Return approval/authorization/execution keys present anywhere in ``value``."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _key_name(key) in STATE_KEYS:
                found.add(str(key))
            found |= find_state_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found |= find_state_keys(item)
    return found


def _is_secret_key(name: str) -> bool:
    return name in SECRET_KEYS or bool(_SECRET_PART.search(name))


def redact_text(text: str) -> str:
    return _JWT.sub("[REDACTED_JWT]", _BEARER.sub("Bearer [REDACTED]", text))


def scrub(value: Any) -> Any:
    """Drop secret-bearing keys and redact Bearer/JWT-looking strings, recursively."""
    if isinstance(value, Mapping):
        return {str(key): scrub(item) for key, item in value.items() if not _is_secret_key(_key_name(key))}
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _plain(output: Any) -> Any:
    if hasattr(output, "model_dump"):
        return output.model_dump(mode="json")
    if is_dataclass(output) and not isinstance(output, type):
        return asdict(output)
    return output


def prepare_output(output: Any, max_bytes: int = MAX_PAYLOAD_BYTES) -> tuple[dict, int]:
    """Validate cacheability and return (scrubbed JSON-safe dict, size in bytes)."""
    plain = _plain(output)
    if not isinstance(plain, Mapping):
        raise UncacheableOutput("Cached output must be a mapping, pydantic model or dataclass")
    state = find_state_keys(plain)
    if state:
        raise UncacheableOutput(f"Output carries approval/authorization/execution state: {sorted(state)}")
    cleaned = json.loads(canonical_json(scrub(plain)))
    size = len(canonical_json(cleaned).encode("utf-8"))
    if size > max_bytes:
        raise UncacheableOutput(f"Output is {size} bytes; limit is {max_bytes}")
    return cleaned, size


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------------------------------
# L1 exact analysis cache
# ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class AnalysisKey:
    """Every component that can change the model output.

    ``evidence`` is the exact payload presented to the model (dict or the rendered prompt text). Do not
    put incident titles, risk scores, approval state or receipt timestamps here unless the model sees them.
    """

    evidence: Any
    detection_type: str
    model_name: str
    model_version: str
    prompt_version: str
    schema_version: str
    knowledge_version: str
    tenant: str = DEFAULT_TENANT

    @property
    def evidence_hash(self) -> str:
        return sha256_hex(canonical_json(self.evidence))

    def versions(self) -> dict[str, str]:
        return {"model_name": self.model_name, "model_version": self.model_version,
                "prompt_version": self.prompt_version, "schema_version": self.schema_version,
                "knowledge_version": self.knowledge_version}

    def digest(self) -> str:
        return sha256_hex(canonical_json({
            "evidence": self.evidence_hash, "detection_type": self.detection_type,
            "tenant": self.tenant, **self.versions(),
        }))


@dataclass(frozen=True)
class CachedAnalysis:
    output: dict
    created_at: datetime
    expires_at: datetime
    hit_count: int
    versions: dict[str, str]


class AnalysisCache:
    """L1 exact cache backed by ``ai_analysis_cache``."""

    def __init__(self, *, ttl: timedelta = DEFAULT_TTL, max_rows: int = DEFAULT_MAX_ROWS,
                 max_payload_bytes: int = MAX_PAYLOAD_BYTES, now: Callable[[], datetime] = _utcnow):
        self.ttl = ttl
        self.max_rows = max_rows
        self.max_payload_bytes = max_payload_bytes
        self._now = now

    async def get(self, session: AsyncSession, key: AnalysisKey, *, subject: str | None = None
                  ) -> CachedAnalysis | None:
        """Return the cached output for an identical model input, or None.

        Expired or version-mismatched rows, and rows superseded for the same ``subject`` (new evidence or
        a new model/prompt/schema/knowledge version), count as stale misses.
        """
        with metrics.timed("l1"):
            now = self._now()
            row = await session.get(AIAnalysisCache, key.digest())
            if row is not None and not self._valid(row, key, now):
                await session.delete(row)
                await session.flush()
                metrics.incr("l1", "stale")
                metrics.incr("l1", "misses")
                return None
            if row is None:
                if subject is not None and await self._superseded(session, key, subject):
                    metrics.incr("l1", "stale")
                metrics.incr("l1", "misses")
                return None
            row.hit_count += 1
            row.last_hit_at = now
            await session.flush()
            metrics.incr("l1", "hits")
            return CachedAnalysis(dict(row.output), _utc(row.created_at), _utc(row.expires_at),
                                  row.hit_count, key.versions())

    async def put(self, session: AsyncSession, key: AnalysisKey, output: Any, *, subject: str | None = None,
                  ttl: timedelta | None = None) -> bool:
        """Store an already validated output. Returns False (and stores nothing) when refused."""
        try:
            cleaned, size = prepare_output(output, self.max_payload_bytes)
        except UncacheableOutput as exc:
            logger.warning("AI analysis not cached: %s", exc)
            metrics.incr("l1", "refused")
            return False
        now = self._now()
        if subject is not None:
            # Rows for older evidence or versions of the same subject can never hit again usefully.
            await session.execute(delete(AIAnalysisCache).where(
                AIAnalysisCache.tenant == key.tenant, AIAnalysisCache.subject == subject,
                AIAnalysisCache.detection_type == key.detection_type,
                AIAnalysisCache.cache_key != key.digest()))
        row = await session.get(AIAnalysisCache, key.digest())
        if row is None:
            row = AIAnalysisCache(cache_key=key.digest(), hit_count=0)
            session.add(row)
        row.tenant = key.tenant
        row.subject = subject
        row.detection_type = key.detection_type
        row.evidence_hash = key.evidence_hash
        for name, value in key.versions().items():
            setattr(row, name, value)
        row.output = cleaned
        row.payload_bytes = size
        row.created_at = now
        row.expires_at = now + (ttl or self.ttl)
        row.last_hit_at = None
        row.hit_count = 0
        await session.flush()
        await self._enforce_limit(session, now)
        return True

    async def invalidate(self, session: AsyncSession, *, tenant: str, subject: str) -> int:
        result = await session.execute(delete(AIAnalysisCache).where(
            AIAnalysisCache.tenant == tenant, AIAnalysisCache.subject == subject))
        await session.flush()
        return result.rowcount or 0

    async def purge_expired(self, session: AsyncSession) -> int:
        result = await session.execute(delete(AIAnalysisCache).where(AIAnalysisCache.expires_at <= self._now()))
        await session.flush()
        removed = result.rowcount or 0
        metrics.incr("l1", "evictions", removed)
        return removed

    def _valid(self, row: AIAnalysisCache, key: AnalysisKey, now: datetime) -> bool:
        if _utc(row.expires_at) <= now:
            return False
        stored = {name: getattr(row, name) for name in key.versions()}
        return (stored == key.versions() and row.tenant == key.tenant
                and row.detection_type == key.detection_type and row.evidence_hash == key.evidence_hash)

    async def _superseded(self, session: AsyncSession, key: AnalysisKey, subject: str) -> bool:
        found = await session.scalar(select(AIAnalysisCache.cache_key).where(
            AIAnalysisCache.tenant == key.tenant, AIAnalysisCache.subject == subject,
            AIAnalysisCache.detection_type == key.detection_type).limit(1))
        return found is not None

    async def _enforce_limit(self, session: AsyncSession, now: datetime) -> None:
        expired = await session.execute(delete(AIAnalysisCache).where(AIAnalysisCache.expires_at <= now))
        evicted = expired.rowcount or 0
        total = await session.scalar(select(func.count()).select_from(AIAnalysisCache)) or 0
        if total > self.max_rows:
            oldest = select(AIAnalysisCache.cache_key).order_by(
                AIAnalysisCache.created_at, AIAnalysisCache.cache_key).limit(total - self.max_rows)
            keys = list((await session.scalars(oldest)).all())
            await session.execute(delete(AIAnalysisCache).where(AIAnalysisCache.cache_key.in_(keys)))
            evicted += len(keys)
        if evicted:
            await session.flush()
            metrics.incr("l1", "evictions", evicted)


analysis_cache = AnalysisCache()


# ---------------------------------------------------------------------------------------------------
# L2 similar-pattern retrieval
# ---------------------------------------------------------------------------------------------------

FINGERPRINT_VERSION = "pattern-1"
# Weights of the weighted Jaccard similarity. Classification dominates and also gates matching; the
# endpoint and payload indicators describe the technique; the remaining features refine it.
FEATURE_WEIGHTS: dict[str, float] = {
    "attack_classification": 3.0,
    "endpoint_pattern": 2.0,
    "payload_indicators": 2.0,
    "tool_indicator": 1.5,
    "auth_outcome": 1.5,
    "process_behavior": 1.5,
    "http_method": 1.0,
    "network_direction": 1.0,
    "evidence_completeness": 0.5,
}
SET_FEATURES = frozenset({"payload_indicators", "auth_outcome", "process_behavior", "network_direction"})
SCAN_LIMIT = 500
GUIDANCE_LIMIT = 16
_REF = re.compile(r"^[A-Za-z0-9_.:\-/]{1,128}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX = re.compile(r"^(?=.*[0-9])[0-9a-f]{8,}$")
_DIGITS = re.compile(r"\d+")
_TOKEN = re.compile(r"[^a-z0-9_.{}\-]")


def normalize_endpoint(value: Any) -> str | None:
    """Lowercase path with the query string dropped and ids replaced by {uuid}, {hex} or {n}."""
    if not isinstance(value, str) or not value.strip():
        return None
    path = urlsplit(value.strip().lower()).path or "/"
    segments = []
    for segment in path.split("/"):
        if not segment:
            continue
        if _UUID.match(segment):
            segments.append("{uuid}")
        elif _HEX.match(segment):
            segments.append("{hex}")
        else:
            segments.append(_DIGITS.sub("{n}", segment))
    return "/" + "/".join(segments)


def _token(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip() or value.strip().upper() == "N/A":
        return None
    return _TOKEN.sub("_", _DIGITS.sub("{n}", value.strip().lower()))[:64]


def _process_token(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    return _token(name.rsplit("/", 1)[-1])


@dataclass(frozen=True)
class PatternFingerprint:
    features: dict[str, Any]
    hash: str

    @property
    def classification(self) -> str | None:
        return self.features.get("attack_classification")


def _as_source(source: Any) -> dict:
    """Accept an HTTP investigation dict, an AlertContext, or any mapping with the same keys."""
    if isinstance(source, Mapping):
        return dict(source)
    data = {"observed_facts": list(getattr(source, "facts", []) or []),
            "processes": list(getattr(source, "processes", []) or []),
            "flows": list(getattr(source, "flows", []) or [])}
    metadata = getattr(source, "metadata", None)
    if isinstance(metadata, Mapping):
        data["detection_type"] = metadata.get("rule_id")
    return data


def _records(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, (list, tuple)) else []


def fingerprint(source: Any, *, classification: str | None = None, endpoint: str | None = None) -> PatternFingerprint:
    """De-identified behaviour features of an investigation or alert context.

    Source IPs, ports, PIDs, request ids, session references, accounts and timestamps are never read.
    """
    data = _as_source(source)
    facts = _records(data.get("observed_facts")) + _records(data.get("facts"))
    processes = _records(data.get("processes"))
    flows = _records(data.get("flows"))
    resources = [item.get("target_resource") for item in _records(data.get("recommended_responses"))]

    cls = classification or data.get("classification")
    if not cls:
        cls = next((f.get("classification") for f in facts if f.get("classification")), None)
    method = next((f.get("method") or f.get("request_method") for f in facts
                   if f.get("method") or f.get("request_method")), None)
    raw_endpoint = endpoint or data.get("endpoint") or next(
        (f.get(k) for f in facts for k in ("endpoint", "request_path", "path", "url")
         if f.get("kind") != "fim" and isinstance(f.get(k), str)), None) or next(
        (r.get("endpoint") for r in resources if isinstance(r, Mapping) and r.get("endpoint")), None)
    tool = next((f.get("automation_hint") or f.get("tool_indicator") for f in facts
                 if f.get("automation_hint") or f.get("tool_indicator")), None)
    indicators = {i for f in facts for i in (f.get("payload_indicators") or []) if isinstance(i, str)}
    outcomes = {f.get("outcome") or f.get("auth_outcome") for f in facts if f.get("outcome") or f.get("auth_outcome")}
    completeness = data.get("evidence_completeness") or next(
        (f.get("evidence_completeness") for f in facts if f.get("evidence_completeness")), None)

    features: dict[str, Any] = {
        "attack_classification": _token(cls),
        "http_method": _token(method),
        "endpoint_pattern": normalize_endpoint(raw_endpoint),
        "tool_indicator": _token(tool),
        "payload_indicators": sorted(filter(None, map(_token, indicators))),
        "auth_outcome": sorted(filter(None, map(_token, outcomes))),
        "process_behavior": sorted({t for p in processes if (t := _process_token(p.get("name")))}),
        "network_direction": sorted({t for f in flows if (t := _token(f.get("direction")))}),
        "evidence_completeness": _token(completeness),
    }
    digest = sha256_hex(canonical_json({"version": FINGERPRINT_VERSION, "features": features}))
    return PatternFingerprint(features, digest)


def _feature_set(features: Mapping[str, Any], name: str) -> set[str]:
    value = features.get(name)
    if name in SET_FEATURES:
        return set(value or ())
    return {value} if value else set()


def similarity(left: Mapping[str, Any], right: Mapping[str, Any]) -> float:
    """Weighted Jaccard: sum_f w_f * |A_f & B_f| / |A_f | B_f|, over features present on either side,
    divided by the sum of those weights. Different attack classifications never match (0.0)."""
    if left.get("attack_classification") != right.get("attack_classification"):
        return 0.0
    score = weight = 0.0
    for name, w in FEATURE_WEIGHTS.items():
        a, b = _feature_set(left, name), _feature_set(right, name)
        union = a | b
        if not union:
            continue
        score += w * len(a & b) / len(union)
        weight += w
    return round(score / weight, 4) if weight else 0.0


def _refs(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return sorted({v for v in value if isinstance(v, str) and _REF.match(v)})[:GUIDANCE_LIMIT]


def sanitize_guidance(guidance: Mapping[str, Any] | None) -> dict:
    """Keep only reference-type guidance: playbook id, knowledge refs and effective response types."""
    guidance = guidance or {}
    playbook = guidance.get("playbook_id")
    return {
        "playbook_id": playbook if isinstance(playbook, str) and _REF.match(playbook) else None,
        "knowledge_refs": _refs(guidance.get("knowledge_refs")),
        "effective_response_types": _refs(guidance.get("effective_response_types")),
    }


@dataclass(frozen=True)
class SimilarCase:
    incident_id: str
    similarity: float
    classification: str
    analyst_label: str
    playbook_id: str | None = None
    knowledge_refs: tuple[str, ...] = ()
    effective_response_types: tuple[str, ...] = field(default_factory=tuple)


async def record_case(session: AsyncSession, incident: Incident, fp: PatternFingerprint,
                      guidance: Mapping[str, Any] | None = None, *, tenant: str = DEFAULT_TENANT
                      ) -> IncidentPatternCase | None:
    """Insert or update the pattern case of ``incident``. Unclassified fingerprints are not stored."""
    if not fp.classification:
        return None
    row = await session.scalar(select(IncidentPatternCase).where(
        IncidentPatternCase.tenant == tenant, IncidentPatternCase.incident_id == incident.id))
    if row is None:
        row = IncidentPatternCase(tenant=tenant, incident_id=incident.id)
        session.add(row)
    row.classification = fp.classification
    row.fingerprint_hash = fp.hash
    row.features = dict(fp.features)
    row.guidance = sanitize_guidance(guidance)
    row.analyst_label = incident.label if incident.labeled_by else None
    row.updated_at = _utcnow()
    await session.flush()
    return row


async def update_label(session: AsyncSession, incident_id: str, *, tenant: str = DEFAULT_TENANT) -> bool:
    """Refresh the stored analyst label from the incident. Returns False if no case exists."""
    row = await session.scalar(select(IncidentPatternCase).where(
        IncidentPatternCase.tenant == tenant, IncidentPatternCase.incident_id == incident_id))
    if row is None:
        return False
    incident = await session.get(Incident, incident_id)
    row.analyst_label = incident.label if incident is not None and incident.labeled_by else None
    row.updated_at = _utcnow()
    await session.flush()
    return True


async def find_similar(session: AsyncSession, fp: PatternFingerprint, *, tenant: str,
                       exclude_incident_id: str | None = None, threshold: float = 0.8, limit: int = 3
                       ) -> list[SimilarCase]:
    """Analyst-labelled cases of the same tenant and classification whose similarity >= threshold."""
    with metrics.timed("l2"):
        metrics.incr("l2", "queries")
        if not fp.classification or limit <= 0:
            metrics.incr("l2", "misses")
            return []
        query = (
            select(IncidentPatternCase, Incident.label)
            .join(Incident, Incident.id == IncidentPatternCase.incident_id)
            .where(IncidentPatternCase.tenant == tenant,
                   IncidentPatternCase.classification == fp.classification,
                   Incident.labeled_by.is_not(None), Incident.label.is_not(None))
            .order_by(IncidentPatternCase.updated_at.desc())
            .limit(SCAN_LIMIT)
        )
        if exclude_incident_id is not None:
            query = query.where(IncidentPatternCase.incident_id != exclude_incident_id)
        scored = []
        for row, label in (await session.execute(query)).all():
            score = 1.0 if row.fingerprint_hash == fp.hash else similarity(fp.features, row.features)
            if score >= threshold:
                guidance = sanitize_guidance(row.guidance)
                scored.append(SimilarCase(
                    incident_id=row.incident_id, similarity=score, classification=row.classification,
                    analyst_label=label, playbook_id=guidance["playbook_id"],
                    knowledge_refs=tuple(guidance["knowledge_refs"]),
                    effective_response_types=tuple(guidance["effective_response_types"]),
                ))
        scored.sort(key=lambda case: (-case.similarity, case.incident_id))
        result = scored[:limit]
        metrics.incr("l2", "matches", len(result))
        metrics.incr("l2", "hits" if result else "misses")
        return result


# ---------------------------------------------------------------------------------------------------
# L3 knowledge retrieval cache
# ---------------------------------------------------------------------------------------------------

def normalize_query(query: str) -> str:
    return " ".join(str(query).split())


class KnowledgeCache:
    """Thread-safe LRU with TTL in front of ``kb.search``; a new ``kb.version`` clears every entry."""

    def __init__(self, *, max_entries: int = 256, ttl_seconds: float = 600.0,
                 clock: Callable[[], float] = time.monotonic):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple, tuple[float, tuple]] = OrderedDict()
        self._version: Any = None

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    @staticmethod
    def make_key(version: Any, query: str, *, categories=None, attack_ids=None, limit=None, **extra: Any) -> tuple:
        return (
            str(version), normalize_query(query).casefold(),
            tuple(sorted({str(c) for c in categories})) if categories else (),
            tuple(sorted({str(a).upper() for a in attack_ids})) if attack_ids else (),
            limit,
            # Any other search option still changes the result set, so it is part of the key.
            tuple(sorted((name, repr(value)) for name, value in extra.items())),
        )

    def search(self, kb: Any, query: str, **kw: Any) -> list:
        version = getattr(kb, "version", None)
        if version is None:
            logger.debug("Knowledge base has no version; bypassing L3 cache")
            return list(kb.search(normalize_query(query), **kw))
        with metrics.timed("l3"):
            key = self.make_key(version, query, **kw)
            now = self._clock()
            with self._lock:
                if self._version != version:
                    if self._entries:
                        metrics.incr("l3", "invalidations")
                        metrics.incr("l3", "evictions", len(self._entries))
                    self._entries.clear()
                    self._version = version
                entry = self._entries.get(key)
                if entry is not None:
                    if entry[0] > now:
                        self._entries.move_to_end(key)
                        metrics.incr("l3", "hits")
                        return list(entry[1])
                    del self._entries[key]
                    metrics.incr("l3", "stale")
                metrics.incr("l3", "misses")
            result = tuple(kb.search(normalize_query(query), **kw))
            with self._lock:
                if self._version == version:
                    self._entries[key] = (now + self.ttl_seconds, result)
                    self._entries.move_to_end(key)
                    while len(self._entries) > self.max_entries:
                        self._entries.popitem(last=False)
                        metrics.incr("l3", "evictions")
            return list(result)


knowledge_cache = KnowledgeCache()


def cached_search(kb: Any, query: str, **kw: Any) -> list:
    """``kb.search(query, **kw)`` through the shared L3 cache (key: kb.version, query, categories,
    attack_ids, limit)."""
    return knowledge_cache.search(kb, query, **kw)
