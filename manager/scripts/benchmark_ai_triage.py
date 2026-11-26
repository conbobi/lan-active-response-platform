"""Benchmark AI triage latency and the three cache tiers (P13).

Uses a temporary SQLite database and fixture incidents; never touches the production database or the
Manager API. Real inference goes to the configured Ollama (OLLAMA_URL / AI_MODEL) unless --stub is given.

    cd manager && PYTHONPATH=..:app/test .venv/bin/python scripts/benchmark_ai_triage.py --runs 5
"""
import argparse
import asyncio
import json
import os
import resource
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "app" / "test"), str(ROOT.parent)]
os.environ.setdefault("AI_RESPONSE_MODEL_VERSION", "benchmark-pinned")

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.models.base import Base  # noqa: E402
from app.services.ai import ai_triage_service  # noqa: E402
from app.services.ai.alert_context_projector import build_alert_context  # noqa: E402
from app.services.ai.analysis_cache import cache_stats, cached_search, find_similar, fingerprint  # noqa: E402
from app.services.ai.knowledge.kb_store import knowledge_base  # noqa: E402
from app.services.ai.knowledge.triage_retriever import enrich_rule_mapping, retrieve_references  # noqa: E402
from app.services.ai.triage_router import Route  # noqa: E402
from app.services.ai.triage_tokens import load_tokenizer  # noqa: E402
from test_ai_agent_pipeline import holder, verified_incident  # noqa: E402


def pct(values, p):
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))], 2) if ordered else None


def summary(values):
    return {"n": len(values), "p50_ms": pct(values, 50), "p95_ms": pct(values, 95),
            "mean_ms": round(statistics.mean(values), 2) if values else None}


def counts(values):
    return {"n": len(values), "p50": pct(values, 50), "p95": pct(values, 95)} if values else None


async def timed(coro):
    start = time.perf_counter()
    result = await coro
    return result, (time.perf_counter() - start) * 1000


async def main(args):
    rss_start = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    tokenizer = load_tokenizer()
    tmp = tempfile.mkdtemp(prefix="larp-bench-")
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp}/bench.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    ai_triage_service.AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    usage = {"prompt_tokens": [], "output_tokens": [], "model_ms": []}

    if args.stub:
        async def generate(prompt, *a, **k):
            await asyncio.sleep(args.stub_ms / 1000)
            return {"answer": json.dumps({"classification": "likely_malicious", "confidence": 0.85,
                                          "evidence_ids": ["N1"], "mitre_techniques": []}), "metrics": {}}
        ai_triage_service.ai_client.generate = generate
    else:
        original = ai_triage_service.ai_client.generate

        async def generate(prompt, *a, **k):
            result = await original(prompt, *a, **k)
            metrics = result.get("metrics", {})
            if isinstance(metrics.get("prompt_eval_count"), int):
                usage["prompt_tokens"].append(metrics["prompt_eval_count"])
            if isinstance(metrics.get("eval_count"), int):
                usage["output_tokens"].append(metrics["eval_count"])
            return result
        ai_triage_service.ai_client.generate = generate

    service = ai_triage_service.AITriageService()
    cold, miss, hit = [], [], []
    for run in range(args.runs):
        # A different holder PID per run gives different evidence, i.e. a genuine L1 miss.
        context = build_alert_context(verified_incident(holder(900 + run)))
        await enrich_rule_mapping(None, context)
        _, ms = await timed(service._infer(context, Route.SINGLE_PASS, tokenizer=tokenizer, subject=f"inc{run}"))
        (cold if run == 0 else miss).append(ms)
        _, ms = await timed(service._infer(context, Route.SINGLE_PASS, tokenizer=tokenizer, subject=f"inc{run}"))
        hit.append(ms)

    context = build_alert_context(verified_incident(holder()))
    await enrich_rule_mapping(None, context)
    prepared = ai_triage_service.prepare_prompt(context, tokenizer, references=retrieve_references(context, tokenizer))

    investigation = {"classification": "sqli_probe_observed", "observed_facts": [{
        "evidence_ids": ["w1"], "method": "POST", "http_status": 200, "source_ip": "192.0.2.9",
        "payload_indicators": ["sql_boolean_expression"]}], "recommended_responses": []}
    l2 = []
    async with ai_triage_service.AsyncSessionLocal() as session:
        for _ in range(max(args.runs, 20)):
            _, ms = await timed(find_similar(session, fingerprint(investigation), tenant="default"))
            l2.append(ms)
    kb_miss, kb_hit = [], []
    for i in range(max(args.runs, 20)):
        start = time.perf_counter()
        cached_search(knowledge_base, f"brute force password guessing {i}", limit=4)
        kb_miss.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter()
        cached_search(knowledge_base, f"brute force password guessing {i}", limit=4)
        kb_hit.append((time.perf_counter() - start) * 1000)
    await engine.dispose()
    report = {
        "model": ai_triage_service.ai_client.model, "inference": "stub" if args.stub else "ollama",
        "stub_latency_ms": args.stub_ms if args.stub else None, "runs": args.runs,
        "cold_first_inference": summary(cold), "warm_inference_l1_miss": summary(miss),
        "l1_exact_hit": summary(hit), "l2_find_similar": summary(l2),
        "l3_kb_search_miss": summary(kb_miss), "l3_kb_search_hit": summary(kb_hit),
        "prompt_tokens_tokenizer": prepared.token_count,
        "prompt_tokens_ollama": counts(usage["prompt_tokens"]),
        "output_tokens_ollama": counts(usage["output_tokens"]),
        "cache_stats": cache_stats(),
        "rss_delta_mb": round((resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - rss_start) / 1024, 1),
    }
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--stub", action="store_true", help="synthetic model latency instead of Ollama")
    parser.add_argument("--stub-ms", type=int, default=1500)
    asyncio.run(main(parser.parse_args()))
