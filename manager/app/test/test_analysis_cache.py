"""Three-tier AI analysis cache: exact L1, labelled-pattern L2, knowledge-search L3."""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models.agent import Agent
from app.models.ai_cache import AIAnalysisCache, IncidentPatternCase
from app.models.base import Base
from app.models.incident import Incident
from app.services.ai import analysis_cache as cache
from app.services.ai.analysis_cache import (
    AnalysisCache, AnalysisKey, KnowledgeCache, cache_stats, find_similar, fingerprint, normalize_endpoint,
    record_case, reset_cache_stats, similarity, update_label,
)
from app.services.ai.triage_schema import ValidatedVerdict

AGENT = "agent-cache"
EVIDENCE = {"alert": {"rule_id": "web_sqli"}, "facts": [{"id": "F1", "kind": "http", "method": "POST"}],
            "processes": [], "flows": []}
OUTPUT = {"classification": "sqli_probe_observed", "confidence": 0.85, "evidence_ids": ["F1"], "techniques": []}


def key(**changes) -> AnalysisKey:
    base = AnalysisKey(evidence=EVIDENCE, detection_type="web_sqli", model_name="sec-q5", model_version="sha:1",
                       prompt_version="p1", schema_version="s1", knowledge_version="k1", tenant="default")
    return replace(base, **changes)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


@pytest.fixture
async def db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'cache.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory.begin() as session:
        session.add(Agent(id=AGENT, hostname=AGENT, ip_address="192.0.2.1", mac_address="00:00:00:00:00:01"))
    reset_cache_stats()
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def l1(clock):
    return AnalysisCache(ttl=timedelta(hours=24), max_rows=100, now=clock)


# ------------------------------------------------------------------------------------------------ L1

@pytest.mark.parametrize("change", [
    {"evidence": {**EVIDENCE, "facts": [{"id": "F1", "kind": "http", "method": "GET"}]}},
    {"detection_type": "web_cmdi"}, {"model_name": "other"}, {"model_version": "sha:2"},
    {"prompt_version": "p2"}, {"schema_version": "s2"}, {"knowledge_version": "k2"}, {"tenant": "acme"},
])
def test_every_component_changes_key(change):
    assert key(**change).digest() != key().digest()


def test_key_is_canonical_over_ordering_and_whitespace():
    reordered = {"processes": [], "flows": [], "facts": [{"method": "POST", "kind": "http", "id": "F1"}],
                 "alert": {"rule_id": "web_sqli"}}
    assert key(evidence=reordered).digest() == key().digest()


async def test_round_trip_counts_hits(db, l1):
    assert await l1.put(db, key(), OUTPUT, subject="inc-1")
    first = await l1.get(db, key(), subject="inc-1")
    second = await l1.get(db, key(), subject="inc-1")
    assert first.output == OUTPUT and second.hit_count == 2
    row = await db.get(AIAnalysisCache, key().digest())
    assert row.last_hit_at is not None and row.prompt_version == "p1" and row.knowledge_version == "k1"
    assert cache_stats()["l1"]["hits"] == 2


async def test_accepts_validated_dataclass(db, l1):
    verdict = ValidatedVerdict("sqli_probe_observed", 0.85, ["F1"], [])
    assert await l1.put(db, key(), verdict)
    assert (await l1.get(db, key())).output == asdict(verdict)


async def test_tenant_isolation(db, l1):
    await l1.put(db, key(tenant="acme"), OUTPUT)
    assert await l1.get(db, key(tenant="globex")) is None
    assert await l1.get(db, key(tenant="acme")) is not None


async def test_expiry_is_stale_miss(db, l1, clock):
    await l1.put(db, key(), OUTPUT, ttl=timedelta(minutes=5))
    clock.now += timedelta(minutes=6)
    assert await l1.get(db, key()) is None
    stats = cache_stats()["l1"]
    assert stats["stale"] == 1 and stats["misses"] == 1
    assert await db.get(AIAnalysisCache, key().digest()) is None


async def test_default_ttl_is_24h(db, l1, clock):
    await l1.put(db, key(), OUTPUT)
    row = await db.get(AIAnalysisCache, key().digest())
    assert cache._utc(row.expires_at) - cache._utc(row.created_at) == timedelta(hours=24)


async def test_version_mismatch_row_is_stale(db, l1):
    await l1.put(db, key(), OUTPUT)
    row = await db.get(AIAnalysisCache, key().digest())
    row.schema_version = "tampered"
    await db.flush()
    assert await l1.get(db, key()) is None
    assert cache_stats()["l1"]["stale"] == 1


async def test_new_version_for_subject_is_stale(db, l1):
    await l1.put(db, key(), OUTPUT, subject="inc-1")
    assert await l1.get(db, key(model_version="sha:2"), subject="inc-1") is None
    assert cache_stats()["l1"]["stale"] == 1


async def test_new_evidence_is_stale_miss(db, l1):
    await l1.put(db, key(), OUTPUT, subject="inc-1")
    newer = key(evidence={**EVIDENCE, "facts": [*EVIDENCE["facts"], {"id": "F2", "kind": "http"}]})
    assert await l1.get(db, newer, subject="inc-1") is None
    assert cache_stats()["l1"]["stale"] == 1
    await l1.put(db, newer, OUTPUT, subject="inc-1")
    # The superseded row of the same subject is removed; only the current evidence remains.
    assert await db.scalar(select(func.count()).select_from(AIAnalysisCache)) == 1
    assert await l1.get(db, newer, subject="inc-1") is not None


async def test_scrubs_secrets_and_tokens(db, l1):
    dirty = {**OUTPUT, "password": "hunter2", "Set-Cookie": "sid=1", "api_key": "k", "raw_message": "x",
             "nested": {"access_token": "abc", "body": "b", "note": "Authorization header was Bearer abc.def-ghi",
                        "jwt": "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl seen"},
             "list": [{"session": "s", "cookie": "c", "keep": 1}]}
    assert await l1.put(db, key(), dirty)
    stored = (await l1.get(db, key())).output
    text = str(stored)
    for secret in ("hunter2", "sid=1", "abc.def", "eyJhbGci", "password", "api_key", "raw_message"):
        assert secret not in text
    assert stored["nested"]["note"].endswith("Bearer [REDACTED]")
    assert "[REDACTED_JWT]" in stored["nested"]["jwt"]
    assert stored["list"] == [{"keep": 1}] and "body" not in stored["nested"]


@pytest.mark.parametrize("state", [
    {"status": "approved"}, {"approved": True}, {"approved_by": "admin"}, {"authorization": "granted"},
    {"nested": [{"dispatch": "queued"}]},
])
async def test_refuses_approval_state(db, l1, state):
    assert not await l1.put(db, key(), {**OUTPUT, **state})
    assert await db.get(AIAnalysisCache, key().digest()) is None
    assert cache_stats()["l1"]["refused"] == 1


async def test_payload_size_limit(db, l1):
    assert not await l1.put(db, key(), {**OUTPUT, "summary": "x" * (64 * 1024)})
    assert await l1.put(db, key(), {**OUTPUT, "summary": "x" * 1000})


async def test_table_limit_evicts_oldest_and_expired(db, clock):
    small = AnalysisCache(max_rows=3, now=clock)
    for index in range(3):
        await small.put(db, key(evidence={"n": index}), OUTPUT, ttl=timedelta(hours=1) if index == 1 else None)
        clock.now += timedelta(minutes=1)
    clock.now += timedelta(hours=2)  # row 1 expired
    await small.put(db, key(evidence={"n": 3}), OUTPUT)
    await small.put(db, key(evidence={"n": 4}), OUTPUT)
    remaining = set((await db.scalars(select(AIAnalysisCache.cache_key))).all())
    assert remaining == {key(evidence={"n": n}).digest() for n in (2, 3, 4)}
    assert cache_stats()["l1"]["evictions"] == 2


# ------------------------------------------------------------------------------------------------ L2

def investigation(source_ip="100.67.222.3", path="/login?id=7&debug=1", cls="sqli_probe_observed",
                  indicators=("boolean_tautology", "comment_sequence")):
    return {
        "classification": cls, "evidence_completeness": "partial", "endpoint": path,
        "observed_facts": [{
            "evidence_ids": ["wlog_abc"], "provenance": "web_access_logs", "observed_at": "2026-11-26T12:00:00+00:00",
            "method": "POST", "http_status": 200, "source_ip": source_ip, "automation_hint": "sqlmap",
            "payload_indicators": list(indicators), "request_id": "req-123", "session_ref": "a" * 64, "pid": 4242,
        }],
    }


GUIDANCE = {"playbook_id": "pb-sqli", "knowledge_refs": ["owasp-sqli:defense-option-1:0"],
            "effective_response_types": ["apply_rate_limit"], "source_ip": "100.67.222.3",
            "approved_by": "admin", "pid": 4242}


async def add_incident(db, incident_id, *, label="true_positive", labeled_by="analyst-1", source_ip="100.67.222.3",
                       cls="sqli_probe_observed", tenant="default", indicators=("boolean_tautology", "comment_sequence")):
    incident = Incident(id=incident_id, title="t", agent_id=AGENT, risk_score=50, label=label, labeled_by=labeled_by)
    db.add(incident)
    await db.flush()
    await record_case(db, incident, fingerprint(investigation(source_ip=source_ip, cls=cls, indicators=indicators)),
                      GUIDANCE, tenant=tenant)
    return incident


def test_endpoint_normalization():
    assert normalize_endpoint("/API/Users/42/orders/550e8400-e29b-41d4-a716-446655440000?x=1#f") == \
        "/api/users/{n}/orders/{uuid}"
    assert normalize_endpoint("https://example.test/files/deadbeef00/v2") == "/files/{hex}/v{n}"


def test_fingerprint_excludes_identities():
    first = fingerprint(investigation(source_ip="100.67.222.3"))
    other = fingerprint(investigation(source_ip="198.51.100.9"))
    assert first.hash == other.hash
    text = str(first.features)
    for identity in ("100.67", "req-123", "4242", "aaaa", "2026-11-26", "wlog_abc"):
        assert identity not in text
    assert first.features["endpoint_pattern"] == "/login"
    assert first.features["tool_indicator"] == "sqlmap"


def test_similarity_weights():
    base = fingerprint(investigation()).features
    assert similarity(base, base) == 1.0
    assert similarity(base, fingerprint(investigation(cls="automated_http_activity")).features) == 0.0
    partial = fingerprint(investigation(indicators=("boolean_tautology",))).features
    assert 0.8 < similarity(base, partial) < 1.0


async def test_same_pattern_other_ip_matches_without_identities(db):
    await add_incident(db, "inc-old", source_ip="198.51.100.9")
    matches = await find_similar(db, fingerprint(investigation()), tenant="default", exclude_incident_id="inc-new")
    assert [m.incident_id for m in matches] == ["inc-old"]
    case = matches[0]
    assert case.similarity == 1.0 and case.analyst_label == "true_positive"
    assert case.playbook_id == "pb-sqli" and case.effective_response_types == ("apply_rate_limit",)
    flat = str(asdict(case))
    for leaked in ("198.51", "100.67", "4242", "req-123", "aaaa", "approved_by", "admin", "session", "outcome"):
        assert leaked not in flat
    stored = await db.scalar(select(IncidentPatternCase))
    assert set(stored.guidance) == {"playbook_id", "knowledge_refs", "effective_response_types"}


async def test_unlabeled_incidents_never_returned(db):
    await add_incident(db, "inc-unlabeled", label=None, labeled_by=None)
    await add_incident(db, "inc-label-only", label="true_positive", labeled_by=None)
    assert await find_similar(db, fingerprint(investigation()), tenant="default") == []


async def test_update_label_refreshes(db):
    incident = await add_incident(db, "inc-1", label=None, labeled_by=None)
    incident.label, incident.labeled_by = "false_positive", "analyst-2"
    assert await update_label(db, "inc-1")
    assert (await db.scalar(select(IncidentPatternCase))).analyst_label == "false_positive"
    [case] = await find_similar(db, fingerprint(investigation()), tenant="default")
    assert case.analyst_label == "false_positive"
    assert not await update_label(db, "missing")


async def test_exclude_self_threshold_and_limit(db):
    await add_incident(db, "inc-exact")
    await add_incident(db, "inc-partial", indicators=("boolean_tautology",))
    query = fingerprint(investigation())
    assert [m.incident_id for m in await find_similar(db, query, tenant="default", threshold=0.99)] == ["inc-exact"]
    both = await find_similar(db, query, tenant="default", threshold=0.8)
    assert [m.incident_id for m in both] == ["inc-exact", "inc-partial"]
    assert len(await find_similar(db, query, tenant="default", limit=1)) == 1
    assert [m.incident_id for m in await find_similar(db, query, tenant="default", exclude_incident_id="inc-exact")] \
        == ["inc-partial"]
    stats = cache_stats()["l2"]
    assert stats["queries"] == 4 and stats["matches"] == 5


async def test_different_classification_no_match(db):
    await add_incident(db, "inc-auto", cls="automated_http_activity")
    assert await find_similar(db, fingerprint(investigation()), tenant="default", threshold=0.0) == []


async def test_pattern_tenant_isolation(db):
    await add_incident(db, "inc-acme", tenant="acme")
    assert await find_similar(db, fingerprint(investigation()), tenant="globex") == []
    assert len(await find_similar(db, fingerprint(investigation()), tenant="acme")) == 1


async def test_record_case_upserts(db):
    incident = await add_incident(db, "inc-1")
    await record_case(db, incident, fingerprint(investigation(indicators=("union_select",))), {})
    rows = (await db.scalars(select(IncidentPatternCase))).all()
    assert len(rows) == 1 and rows[0].features["payload_indicators"] == ["union_select"]


# ------------------------------------------------------------------------------------------------ L3

class FakeKB:
    def __init__(self, version="kb-1"):
        self.version = version
        self.calls = []

    def search(self, query, *, categories=None, attack_ids=None, limit=5):
        self.calls.append((query, categories, attack_ids, limit))
        return [f"{self.version}:{query}:{limit}"]


class Tick:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


def test_l3_hits_normalized_query():
    kb, lru = FakeKB(), KnowledgeCache()
    first = lru.search(kb, "SQL  injection", categories=["sql_injection"], limit=3)
    assert lru.search(kb, " sql injection ", categories=["sql_injection"], limit=3) == first
    assert len(kb.calls) == 1
    lru.search(kb, "sql injection", categories=["sql_injection"], limit=4)
    lru.search(kb, "sql injection", categories=["sql_injection"], attack_ids=["T1190"], limit=3)
    assert len(kb.calls) == 3


def test_l3_kb_version_invalidates():
    kb, lru = FakeKB(), KnowledgeCache()
    lru.search(kb, "beaconing")
    kb.version = "kb-2"
    assert lru.search(kb, "beaconing") == ["kb-2:beaconing:5"]
    assert len(kb.calls) == 2 and len(lru) == 1
    assert cache_stats()["l3"]["invalidations"] == 1


def test_l3_lru_eviction():
    kb, lru = FakeKB(), KnowledgeCache(max_entries=2)
    lru.search(kb, "a")
    lru.search(kb, "b")
    lru.search(kb, "a")  # refresh a
    lru.search(kb, "c")  # evicts b
    lru.search(kb, "a")
    assert [call[0] for call in kb.calls] == ["a", "b", "c"]
    lru.search(kb, "b")
    assert [call[0] for call in kb.calls] == ["a", "b", "c", "b"]


def test_l3_ttl():
    kb, tick = FakeKB(), Tick()
    lru = KnowledgeCache(ttl_seconds=10, clock=tick)
    lru.search(kb, "a")
    tick.value = 9
    lru.search(kb, "a")
    tick.value = 11
    lru.search(kb, "a")
    assert len(kb.calls) == 2
    assert cache_stats()["l3"]["stale"] == 1


def test_cached_search_uses_shared_cache(monkeypatch):
    monkeypatch.setattr(cache, "knowledge_cache", KnowledgeCache())
    kb = FakeKB()
    cache.cached_search(kb, "q", limit=2)
    cache.cached_search(kb, "q", limit=2)
    assert len(kb.calls) == 1


def test_stats_latency_percentiles():
    reset_cache_stats()
    for value in range(1, 101):
        cache.metrics.observe("l1", float(value))
    latency = cache_stats()["l1"]["latency_ms"]
    assert latency == {"p50": 50.0, "p95": 95.0, "samples": 100}
    for _ in range(600):
        cache.metrics.observe("l1", 1.0)
    assert cache_stats()["l1"]["latency_ms"]["samples"] == cache.LATENCY_SAMPLES
