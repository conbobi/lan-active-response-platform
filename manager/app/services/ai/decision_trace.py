"""Real backend instrumentation, persistence, sanitization, and SSE brokering for AI Decision Traces."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
import logging
import re
from time import monotonic
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple
import uuid
from weakref import WeakKeyDictionary

from sqlalchemy import desc, func, select

from app.models.decision_trace import AIAnalysisRun, AIDecisionTraceEvent
from app.models.incident import Incident
from app.models.risk_score import RiskScoreRecord

logger = logging.getLogger(__name__)

RUN_STATUSES: Tuple[str, ...] = ("CREATED", "RUNNING", "COMPLETED", "FAILED", "TIMEOUT", "CANCELLED")
ACTIVE_RUN_STATUSES: Tuple[str, ...] = ("CREATED", "RUNNING")

STAGES: Tuple[str, ...] = (
    "INCIDENT_LOADED",
    "EVIDENCE_RETRIEVAL",
    "RISK_RULE_EXPLANATION",
    "PROCESS_NETWORK_CORRELATION",
    "CACHE_LOOKUP",
    "MODEL_INFERENCE",
    "DETERMINISTIC_FALLBACK",
    "CLAIM_VERIFICATION",
    "ANALYSIS_PERSISTENCE",
    "RESPONSE_RECOMMENDATION",
)

STAGE_STATUSES: Tuple[str, ...] = ("PENDING", "RUNNING", "COMPLETED", "SKIPPED", "FAILED", "TIMEOUT", "CANCELLED")

EVENT_TYPES: Tuple[str, ...] = (
    "analysis_started",
    "stage_started",
    "stage_completed",
    "stage_skipped",
    "stage_failed",
    "model_answer_delta",
    "analysis_completed",
    "analysis_failed",
)

SOURCE_TYPES: Tuple[str, ...] = (
    "ENDPOINT_AGENT",
    "MANAGER_STORE",
    "ANALYST_INPUT",
    "AI_INFERENCE",
    "DETERMINISTIC",
    "HYBRID",
)

_ACTIVE_STALE_MINUTES = 15

_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
_THINK_TAG_RE = re.compile(r"</?think>", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
_SECRET_KV_RE = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|access_token|refresh_token|password|passwd|secret|api_key|token)\s*[:=]\s*([^\s,;\"']+)"
)
_SENSITIVE_KEYS = frozenset({
    "authorization", "cookie", "set_cookie", "set-cookie", "access_token", "refresh_token",
    "password", "passwd", "secret", "api_key", "jwt", "thinking", "raw_thinking", "prompt_raw",
})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return _as_utc(dt).isoformat()


def _session_factory(override: Optional[Callable[[], Any]] = None) -> Callable[[], Any]:
    if override is not None:
        return override
    from app.core.database import AsyncSessionLocal
    return AsyncSessionLocal


def sanitize_trace_text(value: Any, *, max_len: int = 2000) -> str:
    """Strip raw thinking blocks, JWTs, bearer headers, cookies, passwords, and API secrets."""
    if value is None:
        return ""
    text = str(value)
    text = _THINK_BLOCK_RE.sub("", text)
    if "<think>" in text.lower():
        # Strip incomplete trailing <think> block cleanly
        idx = text.lower().find("<think>")
        text = text[:idx]
    text = _THINK_TAG_RE.sub("", text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = text.strip()
    if len(text) > max_len:
        text = text[: max_len - 3].rstrip() + "..."
    return text


def sanitize_safe_result(value: Any, *, depth: int = 0) -> Any:
    """Recursively sanitize dictionaries/lists so trace payloads never leak credentials or raw <think>."""
    if depth > 6 or value is None:
        return None if value is None else str(value)[:256]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return sanitize_trace_text(value, max_len=1500)
    if isinstance(value, (list, tuple)):
        return [sanitize_safe_result(item, depth=depth + 1) for item in list(value)[:60]]
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if key.lower() in _SENSITIVE_KEYS:
                cleaned[key] = "[REDACTED]"
                continue
            cleaned[key] = sanitize_safe_result(v, depth=depth + 1)
        return cleaned
    return sanitize_trace_text(str(value), max_len=500)


def serialize_run(run: AIAnalysisRun) -> Dict[str, Any]:
    return {
        "analysis_run_id": run.id,
        "incident_id": run.incident_id,
        "agent_id": run.agent_id,
        "requested_by": run.requested_by,
        "mode": run.mode,
        "status": run.status,
        "evidence_version": run.evidence_version,
        "analysis_id": run.analysis_id,
        "model_name": run.model_name,
        "error_code": run.error_code,
        "error_message": sanitize_trace_text(run.error_message) if run.error_message else None,
        "started_at": _iso(run.started_at),
        "completed_at": _iso(run.completed_at),
        "created_at": _iso(run.created_at),
    }


def serialize_event(event: AIDecisionTraceEvent) -> Dict[str, Any]:
    return {
        "event_id": event.id,
        "analysis_run_id": event.analysis_run_id,
        "incident_id": event.incident_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "stage": event.stage,
        "status": event.status,
        "source_type": event.source_type,
        "started_at": _iso(event.started_at),
        "completed_at": _iso(event.completed_at),
        "duration_ms": event.duration_ms,
        "summary": sanitize_trace_text(event.summary),
        "evidence_refs": list(event.evidence_refs or []),
        "rule_refs": list(event.rule_refs or []),
        "safe_result": sanitize_safe_result(event.safe_result) if event.safe_result is not None else None,
        "error_code": event.error_code,
        "created_at": _iso(event.created_at),
    }


class TraceBroker:
    """In-memory SSE pub/sub broker paired with PostgreSQL active-run single-flight lookup."""

    def __init__(self) -> None:
        self._active_runs: Dict[str, str] = {}
        self._subscribers: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._loop_locks: "WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = WeakKeyDictionary()

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._loop_locks.get(loop)
        if lock is None:
            lock = asyncio.Lock()
            self._loop_locks[loop] = lock
        return lock

    def register_active(self, incident_id: str, run_id: str) -> None:
        self._active_runs[incident_id] = run_id

    def clear_active(self, incident_id: str, run_id: str) -> None:
        if self._active_runs.get(incident_id) == run_id:
            self._active_runs.pop(incident_id, None)

    def subscribe(self, run_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers[run_id].add(queue)
        return queue

    def unsubscribe(self, run_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(run_id)
        if not subs:
            return
        subs.discard(queue)
        if not subs:
            self._subscribers.pop(run_id, None)

    def publish(self, run_id: str, payload: Dict[str, Any]) -> None:
        for queue in list(self._subscribers.get(run_id, ())):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("Trace subscriber queue full for run %s; dropping oldest message", run_id)
                try:
                    queue.get_nowait()
                    queue.put_nowait(payload)
                except asyncio.QueueEmpty:
                    pass

    async def get_active_run(self, db, incident_id: str) -> Optional[AIAnalysisRun]:
        cutoff = _utcnow() - timedelta(minutes=_ACTIVE_STALE_MINUTES)
        stmt = (
            select(AIAnalysisRun)
            .where(
                AIAnalysisRun.incident_id == incident_id,
                AIAnalysisRun.status.in_(ACTIVE_RUN_STATUSES),
                AIAnalysisRun.created_at >= cutoff,
            )
            .order_by(desc(AIAnalysisRun.created_at))
            .limit(1)
        )
        run = (await db.execute(stmt)).scalar_one_or_none()
        if run is not None:
            self._active_runs[incident_id] = run.id
        else:
            self._active_runs.pop(incident_id, None)
        return run

    async def get_or_create_run(
        self,
        db,
        *,
        incident_id: str,
        agent_id: Optional[str] = None,
        requested_by: str = "system",
        mode: str = "reuse",
        model_name: Optional[str] = None,
        evidence_version: Optional[str] = None,
    ) -> Tuple[AIAnalysisRun, bool]:
        async with self._lock():
            existing = await self.get_active_run(db, incident_id)
            if existing is not None:
                return existing, True
            run = AIAnalysisRun(
                id=f"run_{uuid.uuid4().hex[:16]}",
                incident_id=incident_id,
                agent_id=agent_id,
                requested_by=requested_by or "system",
                mode=mode or "reuse",
                status="CREATED",
                evidence_version=evidence_version,
                model_name=model_name,
            )
            db.add(run)
            await db.flush()
            self._active_runs[incident_id] = run.id
            return run, False


trace_broker = TraceBroker()
trace_run_context: ContextVar[Optional[Tuple[str, str]]] = ContextVar("trace_run_context", default=None)


class TraceRecorder:
    """Emits validated, sanitized, sequential trace events backed by database persistence."""

    def __init__(
        self,
        *,
        run_id: str,
        incident_id: str,
        session_factory: Optional[Callable[[], Any]] = None,
        broker: Optional[TraceBroker] = None,
        initial_sequence: int = 0,
    ) -> None:
        self.run_id = run_id
        self.incident_id = incident_id
        self._session_factory = session_factory
        self._broker = broker or trace_broker
        self._seq = initial_sequence
        self._seq_initialized = initial_sequence > 0
        self._stage_starts: Dict[str, Tuple[float, datetime]] = {}
        self._write_lock: Optional[asyncio.Lock] = None
        self._bound_loop: Optional[asyncio.AbstractEventLoop] = None

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._write_lock is None or self._bound_loop is not loop:
            self._write_lock = asyncio.Lock()
            self._bound_loop = loop
        return self._write_lock

    def _factory(self) -> Callable[[], Any]:
        return _session_factory(self._session_factory)

    async def _next_sequence(self, session) -> int:
        if not self._seq_initialized:
            existing_max = await session.scalar(
                select(func.max(AIDecisionTraceEvent.sequence)).where(
                    AIDecisionTraceEvent.analysis_run_id == self.run_id
                )
            )
            self._seq = int(existing_max or 0)
            self._seq_initialized = True
        self._seq += 1
        return self._seq

    async def _record_event(
        self,
        *,
        event_type: str,
        stage: str,
        status: str,
        source_type: str = "DETERMINISTIC",
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        duration_ms: Optional[int] = None,
        summary: str = "",
        evidence_refs: Optional[Iterable[str]] = None,
        rule_refs: Optional[Iterable[str]] = None,
        safe_result: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        run_updates: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        assert event_type in EVENT_TYPES, f"Unsupported event_type {event_type}"
        assert stage in STAGES, f"Unsupported stage {stage}"
        assert status in STAGE_STATUSES, f"Unsupported status {status}"
        assert source_type in SOURCE_TYPES, f"Unsupported source_type {source_type}"

        clean_summary = sanitize_trace_text(summary)
        clean_evidence = list(dict.fromkeys(str(item) for item in (evidence_refs or []) if item))[:50]
        clean_rules = list(dict.fromkeys(str(item) for item in (rule_refs or []) if item))[:30]
        clean_safe = sanitize_safe_result(safe_result) if safe_result is not None else None
        now = _utcnow()

        async with self._lock():
            factory = self._factory()
            async with factory() as session:
                async with session.begin():
                    if run_updates:
                        run = await session.get(AIAnalysisRun, self.run_id)
                        if run is not None:
                            for key, val in run_updates.items():
                                if key == "error_message" and val is not None:
                                    val = sanitize_trace_text(val, max_len=500)
                                setattr(run, key, val)
                    seq = await self._next_sequence(session)
                    event = AIDecisionTraceEvent(
                        id=f"tr_{uuid.uuid4().hex[:16]}",
                        analysis_run_id=self.run_id,
                        incident_id=self.incident_id,
                        sequence=seq,
                        event_type=event_type,
                        stage=stage,
                        status=status,
                        source_type=source_type,
                        started_at=started_at or now,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        summary=clean_summary,
                        evidence_refs=clean_evidence,
                        rule_refs=clean_rules,
                        safe_result=clean_safe,
                        error_code=error_code,
                        created_at=now,
                    )
                    session.add(event)
                payload = serialize_event(event)

        self._broker.publish(self.run_id, payload)
        return payload

    async def start_run(
        self,
        *,
        agent_id: Optional[str] = None,
        model_name: Optional[str] = None,
        evidence_version: Optional[str] = None,
        mode: str = "reuse",
        summary: str = "Khởi tạo phiên phân tích AI Risk Analyst",
    ) -> Dict[str, Any]:
        now = _utcnow()
        updates: Dict[str, Any] = {"status": "RUNNING", "started_at": now, "mode": mode}
        if agent_id is not None:
            updates["agent_id"] = agent_id
        if model_name is not None:
            updates["model_name"] = model_name
        if evidence_version is not None:
            updates["evidence_version"] = evidence_version
        self._broker.register_active(self.incident_id, self.run_id)
        return await self._record_event(
            event_type="analysis_started",
            stage="INCIDENT_LOADED",
            status="RUNNING",
            source_type="DETERMINISTIC",
            started_at=now,
            summary=summary,
            safe_result={"mode": mode, "model_name": model_name, "evidence_version": evidence_version},
            run_updates=updates,
        )

    async def start_stage(
        self,
        stage: str,
        *,
        summary: str,
        source_type: str = "DETERMINISTIC",
        evidence_refs: Optional[Iterable[str]] = None,
        rule_refs: Optional[Iterable[str]] = None,
        safe_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = _utcnow()
        self._stage_starts[stage] = (monotonic(), now)
        return await self._record_event(
            event_type="stage_started",
            stage=stage,
            status="RUNNING",
            source_type=source_type,
            started_at=now,
            summary=summary,
            evidence_refs=evidence_refs,
            rule_refs=rule_refs,
            safe_result=safe_result,
        )

    def _stage_elapsed(self, stage: str) -> Tuple[datetime, datetime, int]:
        done_at = _utcnow()
        start_mono, start_dt = self._stage_starts.pop(stage, (monotonic(), done_at))
        dur_ms = max(0, round((monotonic() - start_mono) * 1000))
        return start_dt, done_at, dur_ms

    async def complete_stage(
        self,
        stage: str,
        *,
        summary: str,
        source_type: str = "DETERMINISTIC",
        evidence_refs: Optional[Iterable[str]] = None,
        rule_refs: Optional[Iterable[str]] = None,
        safe_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        start_dt, done_at, dur_ms = self._stage_elapsed(stage)
        return await self._record_event(
            event_type="stage_completed",
            stage=stage,
            status="COMPLETED",
            source_type=source_type,
            started_at=start_dt,
            completed_at=done_at,
            duration_ms=dur_ms,
            summary=summary,
            evidence_refs=evidence_refs,
            rule_refs=rule_refs,
            safe_result=safe_result,
        )

    async def skip_stage(
        self,
        stage: str,
        *,
        reason: str,
        source_type: str = "DETERMINISTIC",
        evidence_refs: Optional[Iterable[str]] = None,
        rule_refs: Optional[Iterable[str]] = None,
        safe_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        start_dt, done_at, dur_ms = self._stage_elapsed(stage)
        merged = {"skip_reason": reason, **(safe_result or {})}
        return await self._record_event(
            event_type="stage_skipped",
            stage=stage,
            status="SKIPPED",
            source_type=source_type,
            started_at=start_dt,
            completed_at=done_at,
            duration_ms=dur_ms,
            summary=reason,
            evidence_refs=evidence_refs,
            rule_refs=rule_refs,
            safe_result=merged,
        )

    async def fail_stage(
        self,
        stage: str,
        *,
        status: str = "FAILED",
        error_code: str = "STAGE_ERROR",
        summary: str = "",
        source_type: str = "DETERMINISTIC",
        evidence_refs: Optional[Iterable[str]] = None,
        rule_refs: Optional[Iterable[str]] = None,
        safe_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if status not in {"FAILED", "TIMEOUT", "CANCELLED"}:
            status = "FAILED"
        start_dt, done_at, dur_ms = self._stage_elapsed(stage)
        return await self._record_event(
            event_type="stage_failed",
            stage=stage,
            status=status,
            source_type=source_type,
            started_at=start_dt,
            completed_at=done_at,
            duration_ms=dur_ms,
            summary=summary,
            evidence_refs=evidence_refs,
            rule_refs=rule_refs,
            safe_result=safe_result,
            error_code=error_code,
        )

    async def emit_answer_delta(
        self,
        text: str,
        *,
        stage: str = "MODEL_INFERENCE",
        source_type: str = "AI_INFERENCE",
        safe_result: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        clean = sanitize_trace_text(text, max_len=1200)
        if not clean:
            return None
        return await self._record_event(
            event_type="model_answer_delta",
            stage=stage,
            status="RUNNING",
            source_type=source_type,
            summary=clean,
            safe_result=safe_result or {"delta_length": len(clean)},
        )

    async def complete_run(
        self,
        *,
        analysis_id: Optional[str] = None,
        evidence_version: Optional[str] = None,
        model_name: Optional[str] = None,
        final_stage: str = "RESPONSE_RECOMMENDATION",
        summary: str = "Hoàn tất phân tích và kiểm chứng bằng chứng",
        safe_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = _utcnow()
        updates: Dict[str, Any] = {
            "status": "COMPLETED",
            "completed_at": now,
        }
        if analysis_id is not None:
            updates["analysis_id"] = analysis_id
        if evidence_version is not None:
            updates["evidence_version"] = evidence_version
        if model_name is not None:
            updates["model_name"] = model_name
        try:
            return await self._record_event(
                event_type="analysis_completed",
                stage=final_stage,
                status="COMPLETED",
                source_type="DETERMINISTIC",
                completed_at=now,
                summary=summary,
                safe_result={"analysis_id": analysis_id, **(safe_result or {})},
                run_updates=updates,
            )
        finally:
            self._broker.clear_active(self.incident_id, self.run_id)

    async def fail_run(
        self,
        *,
        status: str = "FAILED",
        stage: str = "ANALYSIS_PERSISTENCE",
        error_code: str = "ANALYSIS_ERROR",
        error_message: str = "",
        summary: str = "",
        analysis_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if status not in {"FAILED", "TIMEOUT", "CANCELLED"}:
            status = "FAILED"
        now = _utcnow()
        updates: Dict[str, Any] = {
            "status": status,
            "completed_at": now,
            "error_code": error_code,
            "error_message": sanitize_trace_text(error_message, max_len=500),
        }
        if analysis_id is not None:
            updates["analysis_id"] = analysis_id
        try:
            return await self._record_event(
                event_type="analysis_failed",
                stage=stage,
                status=status,
                source_type="DETERMINISTIC",
                completed_at=now,
                summary=summary or error_message or error_code,
                safe_result={"analysis_id": analysis_id, "error_code": error_code},
                error_code=error_code,
                run_updates=updates,
            )
        finally:
            self._broker.clear_active(self.incident_id, self.run_id)


async def load_run_trace(db, run_id: str) -> Optional[Dict[str, Any]]:
    run = await db.get(AIAnalysisRun, run_id)
    if run is None:
        return None
    rows = (
        await db.scalars(
            select(AIDecisionTraceEvent)
            .where(AIDecisionTraceEvent.analysis_run_id == run_id)
            .order_by(AIDecisionTraceEvent.sequence.asc())
        )
    ).all()
    return {
        "run": serialize_run(run),
        "events": [serialize_event(row) for row in rows],
    }


async def list_incident_runs(db, incident_id: str, *, limit: int = 15) -> List[Dict[str, Any]]:
    rows = (
        await db.scalars(
            select(AIAnalysisRun)
            .where(AIAnalysisRun.incident_id == incident_id)
            .order_by(desc(AIAnalysisRun.created_at))
            .limit(max(1, min(limit, 50)))
        )
    ).all()
    return [serialize_run(row) for row in rows]


async def fetch_events_after(
    session_factory: Callable[[], Any],
    run_id: str,
    after_sequence: int,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    async with session_factory() as session:
        run = await session.get(AIAnalysisRun, run_id)
        if run is None:
            return None, []
        rows = (
            await session.scalars(
                select(AIDecisionTraceEvent)
                .where(
                    AIDecisionTraceEvent.analysis_run_id == run_id,
                    AIDecisionTraceEvent.sequence > after_sequence,
                )
                .order_by(AIDecisionTraceEvent.sequence.asc())
            )
        ).all()
        return serialize_run(run), [serialize_event(row) for row in rows]


def _severity_value(severity: Any) -> str:
    return severity.value if hasattr(severity, "value") else str(severity or "medium")


async def extract_risk_explanation(db, incident: Incident) -> Dict[str, Any]:
    """Read persisted risk-score breakdown from the incident/RiskScoreRecord without inventing numbers."""
    evidence = incident.detection_evidence or {}
    final_score = round(float(incident.risk_score or 0.0), 2)
    severity = _severity_value(incident.severity)

    snapshot = evidence.get("risk_snapshot")
    if isinstance(snapshot, dict) and isinstance(snapshot.get("rule_breakdown"), list) and snapshot["rule_breakdown"]:
        rules = snapshot["rule_breakdown"]
        matched_rules = [r for r in rules if r.get("matched")]
        return {
            "breakdown_available": True,
            "source": snapshot.get("source") or "risk_snapshot",
            "message": "Lấy dữ liệu phân rã trực tiếp từ snapshot tính điểm lúc tạo/cập nhật sự cố.",
            "raw_score": snapshot.get("raw_score", final_score),
            "smoothed_score": snapshot.get("smoothed_score", final_score),
            "previous_smoothed": snapshot.get("previous_smoothed"),
            "ema_applied": bool(snapshot.get("ema_applied")),
            "security_attack_bypass": bool(snapshot.get("security_attack_bypass")),
            "final_score": final_score,
            "severity": severity,
            "thresholds": snapshot.get("thresholds") or {},
            "rule_breakdown": rules,
            "matched_rule_ids": [str(r.get("rule_id")) for r in matched_rules if r.get("rule_id")],
        }

    chain = evidence.get("chain")
    if isinstance(chain, dict) and isinstance(chain.get("conditions"), list) and chain["conditions"]:
        sb = chain.get("score_breakdown") or {}
        rules = []
        for cond in chain["conditions"]:
            matched = cond.get("status") == "OBSERVED"
            weight = float(cond.get("weight") or 0.0)
            contrib = float(cond.get("contribution") or 0.0)
            rules.append({
                "rule_id": cond.get("id"),
                "label": cond.get("label") or cond.get("id"),
                "matched": matched,
                "raw_score": weight if matched else 0.0,
                "debounced_score": weight if matched else 0.0,
                "weight": 1.0,
                "weighted_contribution": contrib,
                "evidence_ids": list(cond.get("evidence_ids") or [])[:15],
                "reason": str(cond.get("detail") or ""),
            })
        return {
            "breakdown_available": True,
            "source": "web_compromise_chain",
            "message": sb.get("rule") or "Phân rã theo trọng số từng giai đoạn chuỗi tấn công web.",
            "raw_score": sb.get("sum_of_weights", final_score),
            "smoothed_score": sb.get("final", final_score),
            "previous_smoothed": None,
            "ema_applied": False,
            "security_attack_bypass": False,
            "final_score": final_score,
            "severity": severity,
            "thresholds": {"cap": sb.get("cap", 100), "severity_high": 70.0, "severity_critical": 85.0},
            "rule_breakdown": rules,
            "matched_rule_ids": [str(r["rule_id"]) for r in rules if r["matched"] and r.get("rule_id")],
        }

    factors = evidence.get("factors")
    if isinstance(factors, list) and factors:
        rules = []
        matched_ids = []
        for item in factors:
            if not isinstance(item, dict):
                continue
            rid = str(item.get("rule") or "unknown_rule")
            score_val = item.get("score")
            matched_ids.append(rid)
            rules.append({
                "rule_id": rid,
                "matched": True,
                "raw_score": float(score_val) if isinstance(score_val, (int, float)) else None,
                "debounced_score": None,
                "weight": None,
                "weighted_contribution": float(score_val) if isinstance(score_val, (int, float)) else None,
                "evidence_ids": [evidence.get("behavior", {}).get("evidence_id")]
                if isinstance(evidence.get("behavior"), dict) and evidence["behavior"].get("evidence_id")
                else [],
                "reason": str(item.get("reason") or ""),
            })
        if rules:
            return {
                "breakdown_available": True,
                "legacy_partial": True,
                "source": "incident_factors",
                "message": "Sự cố cũ chỉ lưu điểm đóng góp theo rule, không có đủ raw/debounce/EMA snapshot.",
                "raw_score": None,
                "smoothed_score": final_score,
                "previous_smoothed": None,
                "ema_applied": None,
                "security_attack_bypass": None,
                "final_score": final_score,
                "severity": severity,
                "thresholds": {"severity_high": 70.0, "severity_critical": 85.0},
                "rule_breakdown": rules,
                "matched_rule_ids": matched_ids,
            }

    # Optional fallback lookup in RiskScoreRecord when agent & close timestamp exist
    recent_risk = (
        await db.scalars(
            select(RiskScoreRecord)
            .where(RiskScoreRecord.agent_id == incident.agent_id)
            .order_by(desc(RiskScoreRecord.timestamp))
            .limit(5)
        )
    ).all()
    matched_rec = next(
        (rec for rec in recent_risk if abs(float(rec.smoothed_score or rec.score) - final_score) < 0.1),
        None,
    )
    if matched_rec and isinstance(matched_rec.factors, dict) and matched_rec.factors.get("_scores"):
        scores = matched_rec.factors.get("_scores") or {}
        rules = [
            {
                "rule_id": rid,
                "matched": True,
                "raw_score": float(val) if isinstance(val, (int, float)) else None,
                "debounced_score": None,
                "weight": None,
                "weighted_contribution": float(val) if isinstance(val, (int, float)) else None,
                "evidence_ids": [],
                "reason": str(matched_rec.factors.get(rid) or ""),
            }
            for rid, val in scores.items()
        ]
        return {
            "breakdown_available": True,
            "legacy_partial": True,
            "source": "risk_score_record",
            "message": "Đối chiếu từ bản ghi RiskScoreRecord gần nhất (chỉ có điểm sau trọng số).",
            "raw_score": round(float(matched_rec.score), 2),
            "smoothed_score": round(float(matched_rec.smoothed_score or matched_rec.score), 2),
            "previous_smoothed": None,
            "ema_applied": None,
            "security_attack_bypass": None,
            "final_score": final_score,
            "severity": severity,
            "thresholds": {"severity_high": 70.0, "severity_critical": 85.0},
            "rule_breakdown": rules,
            "matched_rule_ids": [str(r["rule_id"]) for r in rules],
        }

    return {
        "breakdown_available": False,
        "source": "none",
        "message": "Chưa có dữ liệu phân rã điểm",
        "raw_score": None,
        "smoothed_score": final_score,
        "previous_smoothed": None,
        "ema_applied": None,
        "security_attack_bypass": None,
        "final_score": final_score,
        "severity": severity,
        "thresholds": {},
        "rule_breakdown": [],
        "matched_rule_ids": [],
    }


def summarize_evidence_bundle(incident: Incident, context: Any) -> Dict[str, Any]:
    """Build deterministic evidence provenance counts and correlation trace details from AlertContext."""
    det = incident.detection_evidence or {}
    meta = getattr(context, "metadata", None) or {}
    processes = list(getattr(context, "processes", None) or [])
    net_flows = list(getattr(context, "flows", None) or [])
    facts = list(getattr(context, "facts", None) or [])
    chain = getattr(context, "chain", None) or det.get("chain") or {}
    by_id = getattr(context, "by_id", None) or {}

    http_facts = [f for f in facts if isinstance(f, dict) and f.get("evidence_type") == "http"]
    auth_facts = [f for f in facts if isinstance(f, dict) and f.get("evidence_type") == "authentication"]
    notes = meta.get("analyst_notes") or []
    artifacts = meta.get("containment_history") or []

    http_count = sum(
        int((f.get("activity_summary") or {}).get("request_count") or len(f.get("source_event_ids") or []) or 1)
        for f in http_facts
    )
    auth_count = sum(
        int(f.get("failed_attempts") or len(f.get("source_event_ids") or []) or 1)
        for f in auth_facts
    )
    other_fact_count = max(0, len(facts) - len(http_facts) - len(auth_facts))

    evidence_ids: Set[str] = {str(k) for k in by_id.keys() if k}
    evidence_ids.update(str(x) for x in (getattr(context, "mandatory", None) or set()) if x)
    for f in facts:
        if isinstance(f, dict):
            for sid in f.get("source_event_ids") or []:
                if sid:
                    evidence_ids.add(str(sid))
    for cond in (chain.get("conditions") or []) if isinstance(chain, dict) else []:
        if isinstance(cond, dict):
            for eid in cond.get("evidence_ids") or []:
                if eid:
                    evidence_ids.add(str(eid))
    if det.get("behavior", {}).get("evidence_id"):
        evidence_ids.add(str(det["behavior"]["evidence_id"]))

    has_chain = bool(chain and (chain.get("conditions") or chain.get("execution_observed") or chain.get("network")))
    has_exec_process = any(isinstance(p, dict) and (p.get("pid") is not None or p.get("command") or p.get("cmdline")) for p in processes)
    has_net_flow = any(isinstance(n, dict) and (n.get("dst") or n.get("remote_ip") or n.get("remote_addr")) for n in net_flows)

    provenance = {
        "ENDPOINT_AGENT": http_count + auth_count + len(processes) + len(net_flows) + other_fact_count,
        "MANAGER_STORE": len(artifacts) + (1 if det.get("risk_snapshot") else 0),
        "ANALYST_INPUT": len(notes),
    }

    correlation_status = "OBSERVED" if (has_chain or getattr(context, "verified_shell", None) or (has_exec_process and has_net_flow)) else (
        "CORRELATED" if (has_exec_process or has_net_flow) else "UNKNOWN"
    )
    if not processes and not net_flows and not has_chain:
        correlation_note = (
            "Không tìm thấy tiến trình hoặc kết nối mạng tương ứng trong khoảng thời gian sự cố; "
            "không tự suy đoán PID hay shell."
        )
    elif has_exec_process and not has_net_flow:
        correlation_note = "Ghi nhận tiến trình liên quan nhưng chưa có flow mạng nối ra ngoài khớp inode/PID."
    elif has_net_flow and not has_exec_process:
        correlation_note = "Ghi nhận kết nối mạng trong cửa sổ sự cố nhưng chưa xác định tiến trình cha."
    else:
        correlation_note = "Đã liên kết request/hành vi, tiến trình và kết nối mạng thuộc cùng agent."

    return {
        "counts": {
            "http_events": http_count,
            "auth_events": auth_count,
            "processes": len(processes),
            "network_flows": len(net_flows),
            "host_events": other_fact_count,
            "analyst_notes": len(notes),
            "containment_artifacts": len(artifacts),
        },
        "provenance": provenance,
        "evidence_ids": sorted(evidence_ids)[:40],
        "missing_data": list(getattr(context, "missing", None) or [])[:15],
        "correlation": {
            "status": correlation_status,
            "has_web_compromise_chain": has_chain,
            "process_count": len(processes),
            "network_count": len(net_flows),
            "matched_pids": [p.get("pid") for p in processes if isinstance(p, dict) and p.get("pid") is not None][:10],
            "note": correlation_note,
        },
    }


def _extract_verdict_text(verdict: Any) -> str:
    if verdict is None:
        return ""
    if is_dataclass(verdict):
        data = asdict(verdict)
    elif hasattr(verdict, "model_dump"):
        data = verdict.model_dump()
    elif isinstance(verdict, dict):
        data = verdict
    else:
        return str(verdict)
    parts = [
        str(data.get("classification") or ""),
        str(data.get("summary") or data.get("executive_summary") or ""),
        str(data.get("reasoning") or data.get("attack_interpretation") or ""),
        *(str(x.get("statement") if isinstance(x, dict) else x) for x in (data.get("facts") or data.get("observed_facts") or [])),
        *(str(x) for x in (data.get("inferences") or [])),
    ]
    return " ".join(parts).lower()


def verify_claims(incident: Incident, context: Any, verdict: Any) -> Dict[str, Any]:
    """Run deterministic post-inference claim verification before persisting AI analysis."""
    by_id = getattr(context, "by_id", None) or {}
    known_ids: Set[str] = {str(k) for k in by_id.keys() if k}
    known_ids.update(str(x) for x in (getattr(context, "mandatory", None) or set()) if x)
    known_ids.add(str(incident.id))

    det = incident.detection_evidence or {}
    if isinstance(det.get("behavior"), dict) and det["behavior"].get("evidence_id"):
        known_ids.add(str(det["behavior"]["evidence_id"]))

    if is_dataclass(verdict):
        vdict = asdict(verdict)
    elif hasattr(verdict, "model_dump"):
        vdict = verdict.model_dump()
    elif isinstance(verdict, dict):
        vdict = verdict
    else:
        vdict = {}

    cited_ids: List[str] = [str(e) for e in (vdict.get("evidence_ids") or []) if e]
    for fact in (vdict.get("facts") or vdict.get("observed_facts") or []):
        if isinstance(fact, dict):
            cited_ids.extend(str(e) for e in (fact.get("evidence_ids") or []) if e)
    for tech in (vdict.get("techniques") or []):
        if isinstance(tech, dict):
            cited_ids.extend(str(e) for e in (tech.get("evidence_ids") or []) if e)

    unsupported_ids = sorted({eid for eid in cited_ids if eid not in known_ids})
    all_facts_bound = bool(cited_ids) or not vdict

    processes = list(getattr(context, "processes", None) or [])
    net_flows = list(getattr(context, "flows", None) or [])
    facts = list(getattr(context, "facts", None) or [])
    chain = getattr(context, "chain", None) or det.get("chain") or {}
    meta = getattr(context, "metadata", None) or {}
    chain_conditions = {
        c.get("id"): c.get("status")
        for c in (chain.get("conditions") or [])
        if isinstance(c, dict) and c.get("id")
    }

    # 3. Timestamp consistency check
    timestamps: List[datetime] = []
    for f in facts:
        if isinstance(f, dict):
            for k in ("first_attempt_at", "last_attempt_at", "observed_at"):
                dt = _as_utc(f.get(k)) if isinstance(f.get(k), datetime) else None
                if dt:
                    timestamps.append(dt)
    now_limit = _utcnow() + timedelta(minutes=5)
    timestamp_ok = all(ts <= now_limit for ts in timestamps)
    inc_created = _as_utc(incident.created_at)
    if inc_created and inc_created > now_limit:
        timestamp_ok = False

    # 4. Scope consistency
    scope_ok = meta.get("agent_id", incident.agent_id) == incident.agent_id

    # 5. HTTP failure vs exploit distinction
    text_blob = _extract_verdict_text(vdict)
    has_exec_evidence = bool(processes) or bool(getattr(context, "verified_shell", None)) or chain_conditions.get("child_execution") == "OBSERVED"
    failed_only = not has_exec_evidence and not chain.get("execution_observed")
    claims_execution = any(tok in text_blob for tok in ("rce confirmed", "thực thi lệnh thành công", "reverse shell thành công"))
    http_distinction_ok = not (failed_only and claims_execution)

    # 6. Root privilege claim guard
    has_uid0 = (
        chain_conditions.get("privileged_execution") == "OBSERVED"
        or any(
            isinstance(p, dict) and (p.get("uid") == 0 or p.get("euid") == 0 or str(p.get("user", "")).lower() == "root")
            for p in processes
        )
    )
    claims_root = any(tok in text_blob for tok in ("quyền root", "as root", "root shell", "uid=0", "euid=0"))
    root_ok = has_uid0 or not claims_root

    checks = [
        {
            "check_id": "evidence_ids_exist",
            "label": "Mã bằng chứng trích dẫn tồn tại",
            "passed": len(unsupported_ids) == 0,
            "certainty": "OBSERVED" if not unsupported_ids else "UNKNOWN",
            "detail": (
                f"Tất cả {len(set(cited_ids))} mã bằng chứng đều thuộc ngữ cảnh sự cố."
                if not unsupported_ids
                else f"Phát hiện mã không có trong dữ liệu sự cố: {', '.join(unsupported_ids[:5])}"
            ),
        },
        {
            "check_id": "claims_supported",
            "label": "Nhận định quan sát có bằng chứng đi kèm",
            "passed": all_facts_bound and not unsupported_ids,
            "certainty": "OBSERVED" if all_facts_bound else "INFERRED",
            "detail": (
                "Mỗi kết luận quan sát đều gắn mã bằng chứng cụ thể."
                if all_facts_bound
                else "Có mục quan sát thiếu evidence_id liên kết."
            ),
        },
        {
            "check_id": "timestamp_consistency",
            "label": "Nhất quán mốc thời gian telemetry",
            "passed": timestamp_ok,
            "certainty": "OBSERVED" if timestamp_ok else "UNKNOWN",
            "detail": "Mốc thời gian log và sự cố hợp lệ." if timestamp_ok else "Phát hiện mốc thời gian lệch bất thường.",
        },
        {
            "check_id": "scope_consistency",
            "label": "Đúng phạm vi agent và sự cố",
            "passed": scope_ok,
            "certainty": "OBSERVED" if scope_ok else "UNKNOWN",
            "detail": f"Toàn bộ bằng chứng khớp agent {incident.agent_id}.",
        },
        {
            "check_id": "http_vs_exploit_separation",
            "label": "Phân biệt lỗi HTTP với khai thác thực tế",
            "passed": http_distinction_ok,
            "certainty": "OBSERVED" if has_exec_evidence else "CORRELATED",
            "detail": (
                "Không đồng nhất HTTP failure hoặc scan thành thực thi RCE nếu thiếu tiến trình chứng minh."
                if http_distinction_ok
                else "Kết luận nhắc đến thực thi dù thiếu bằng chứng tiến trình/shell."
            ),
        },
        {
            "check_id": "root_privilege_guard",
            "label": "Không gán quyền root nếu thiếu UID=0",
            "passed": root_ok,
            "certainty": "OBSERVED" if has_uid0 else "UNKNOWN",
            "detail": (
                "Xác minh UID=0 từ telemetry tiến trình."
                if has_uid0
                else "Chưa có bằng chứng UID=0; không khẳng định đặc quyền root."
                if root_ok
                else "Phát hiện nhắc đến đặc quyền root khi chưa có bằng chứng UID=0."
            ),
        },
    ]

    passed = all(c["passed"] for c in checks)
    return {
        "passed": passed,
        "checks": checks,
        "unsupported_evidence_ids": unsupported_ids,
        "cited_evidence_count": len(set(cited_ids)),
        "has_execution_evidence": has_exec_evidence,
        "has_network_evidence": bool(net_flows),
        "has_root_evidence": has_uid0,
    }


async def inspect_response_policy(db, incident: Incident) -> Dict[str, Any]:
    """Read-only Response Policy inspection: never creates, mutates, or dispatches any action."""
    from app.models.containment import ContainmentAction
    from app.models.response_action import ResponseAction
    from app.models.response_policy import ResponsePolicy
    from app.services.response.access_control import suggestions

    policies = (
        await db.scalars(
            select(ResponsePolicy)
            .where(ResponsePolicy.is_active.is_(True))
            .order_by(ResponsePolicy.priority.desc())
        )
    ).all()
    score_val = float(incident.risk_score or 0.0)
    matching = [
        {
            "policy_id": p.id,
            "name": p.name,
            "action_type": getattr(p, "action_type", None),
            "min_score": float(getattr(p, "min_score", 0.0) or 0.0),
            "max_score": float(getattr(p, "max_score", 100.0) or 100.0),
            "scope": getattr(p, "scope", "agent"),
            "requires_approval": True,
        }
        for p in policies
        if float(getattr(p, "min_score", 0.0) or 0.0) <= score_val <= float(getattr(p, "max_score", 100.0) or 100.0)
    ][:8]

    ip_candidates = await suggestions(db, incident)
    existing_actions = await db.scalar(
        select(func.count(ResponseAction.id)).where(ResponseAction.incident_id == incident.id)
    )
    existing_containment = await db.scalar(
        select(func.count(ContainmentAction.id)).where(ContainmentAction.incident_id == incident.id)
    )

    return {
        "read_only": True,
        "auto_executed": False,
        "approval_required": True,
        "matching_policies": matching,
        "ip_candidates": ip_candidates[:10],
        "existing_response_actions": int(existing_actions or 0),
        "existing_containment_actions": int(existing_containment or 0),
        "summary": (
            f"Đối chiếu {len(matching)} policy phù hợp và {len(ip_candidates)} mục tiêu IP ứng viên "
            "(chỉ đọc — mọi hành động ngăn chặn đều cần phê duyệt)."
        ),
    }
