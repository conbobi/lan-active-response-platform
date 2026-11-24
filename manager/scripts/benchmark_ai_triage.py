"""Compare the legacy and optimized triage against three labeled synthetic incidents."""
import argparse
import asyncio
import json
import math
import statistics
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models.agent import Agent
from app.models.base import Base
from app.services.ai import ai_triage_service as triage
from app.services.ai.ai_client import DEFAULT_MODEL, TRIAGE_SETTINGS, AIClient
from app.services.ai.alert_context_projector import build_alert_context
from app.services.ai.triage_router import Route, RoutingDecision, TriageQueue, route_triage
from app.services.ai.triage_tokens import load_tokenizer
from app.test.test_alert_context_projector import (
    holder,
    incident_with,
    socket_observation,
    verified_incident,
)


class MeasuredClient(AIClient):
    def __init__(self, url, model):
        super().__init__(url, model)
        self.calls = []
        self.tokenizer = load_tokenizer()

    async def generate(self, prompt, system=None, **kwargs):
        started = time.perf_counter()
        record = {"gguf_input_tokens": self.tokenizer.count_chat(system or "", prompt)}
        self.calls.append(record)
        try:
            result = await super().generate(prompt, system, **kwargs)
            record.update(metrics=result["metrics"], answer=result["answer"])
            return result
        finally:
            record["seconds"] = time.perf_counter() - started


async def sample_memory(path, readings, anonymous_readings):
    if path is None:
        return
    while True:
        readings.append(int(path.read_text().strip()))
        stats = dict(line.split() for line in path.with_name("memory.stat").read_text().splitlines())
        anonymous_readings.append(int(stats["anon"]))
        await asyncio.sleep(0.2)


def legacy_service(ref):
    root = Path(__file__).resolve().parents[2]
    path = "manager/app/services/ai/ai_triage_service.py"
    source = subprocess.check_output(["git", "--no-pager", "show", f"{ref}:{path}"], cwd=root, text=True)
    legacy = ModuleType("larp_legacy_triage")
    exec(compile(source, f"{ref}:{path}", "exec"), legacy.__dict__)
    return legacy


def calculate(case, expected, row, context, calls, legacy):
    raw = json.loads(row.raw_response) if row and row.raw_response and not legacy else {}
    strict_json = False
    if legacy and calls:
        try:
            raw = json.loads(calls[-1].get("answer", ""))
            strict_json = (
                isinstance(raw, dict)
                and raw.get("classification") in triage.CLASS_LABELS
                and isinstance(raw.get("summary"), str)
                and type(raw.get("confidence")) in (int, float)
                and 0 <= raw["confidence"] <= 1
            )
            if not isinstance(raw, dict):
                raw = {}
        except ValueError:
            raw = {}
    else:
        strict_json = raw.get("status") == "ok"

    techniques = {item["id"] for item in (row.mitre_techniques or [])} if row else set()
    classification = raw.get("classification")
    positive = bool(
        classification in {"likely_malicious", "confirmed_malicious"}
        or any(item.startswith(("T1071", "T1059")) for item in techniques)
    ) if row and not row.error_message else None
    attribution = None
    if expected:
        network = context.flows[0]
        holders = {(item["pid"], tuple(item["socket_fds"])) for item in network["holders"]}
        summary = raw.get("evidence_summary", {}).get(network["id"], {})
        attached = {(item["pid"], tuple(item["socket_fds"])) for item in summary.get("holders", [])}
        attribution = bool(
            summary and summary["inode"] == network["inode"] and attached == holders
            and summary["primary_process"] == network["primary_process"]
        )
        if legacy:
            observed = raw.get("observed_facts", "")
            attribution = (
                not context.conflict and isinstance(observed, str) and network["inode"] in observed
                and all(str(pid) in observed for pid, _ in holders)
            )
    metrics = [call["metrics"] for call in calls if call.get("metrics")]

    def total(field):
        values = [item[field] for item in metrics if field in item]
        return sum(values) if len(values) == len(calls) and values else None

    load_ns = total("load_duration")
    return {
        "case": case,
        "expected_positive": expected,
        "observed_positive": positive,
        "attribution_correct": attribution,
        "valid_json": strict_json,
        "status": raw.get("status", "legacy" if row else "timeout"),
        "model_calls": len(calls),
        "gguf_input_tokens": sum(call["gguf_input_tokens"] for call in calls),
        "prompt_tokens": total("prompt_eval_count"),
        "output_tokens": total("eval_count"),
        "model_load_seconds": round(load_ns / 1e9, 3) if load_ns is not None else None,
        "model_wall_seconds": round(sum(call["seconds"] for call in calls), 3),
    }


def summary(rows, readings, anonymous_readings):
    latencies = sorted(row["job_seconds"] for row in rows)
    negatives = [row for row in rows if not row["expected_positive"] and row["observed_positive"] is not None]
    positives = [row for row in rows if row["expected_positive"]]
    def mean(field):
        values = [row[field] for row in rows if row[field] is not None]
        return round(statistics.mean(values), 2) if values else None

    return {
        "job_seconds_p50": statistics.median(latencies),
        "job_seconds_p95": latencies[math.ceil(0.95 * len(latencies)) - 1],
        "mean_gguf_input_tokens": mean("gguf_input_tokens"),
        "mean_prompt_tokens": mean("prompt_tokens"),
        "mean_output_tokens": mean("output_tokens"),
        "peak_cgroup_mib_sampled": round(max(readings) / 2**20, 2) if readings else None,
        "peak_cgroup_anon_mib_sampled": round(max(anonymous_readings) / 2**20, 2) if anonymous_readings else None,
        "strict_json_jobs": sum(row["valid_json"] for row in rows),
        "timeout_jobs": sum(row["status"] == "timeout" for row in rows),
        "evaluated_negatives": len(negatives),
        "false_positive_rate": sum(row["observed_positive"] for row in negatives) / len(negatives) if negatives else None,
        "attribution_accuracy": sum(row["attribution_correct"] for row in positives) / len(positives),
    }


async def benchmark(args, database):
    legacy = legacy_service(args.baseline_ref)
    client = MeasuredClient(args.url, DEFAULT_MODEL)
    triage.ai_client = legacy.ai_client = client
    cases = [
        ("verified-shell", True, verified_incident()),
        ("ordinary-tcp-4444", False, incident_with(
            {"network": socket_observation(holder(name="curl", fds=(7,)))},
            risk=5, identifier="inc-normal-tcp",
        )),
        ("equal-holders", True, verified_incident(holder(), holder(802, 11))),
    ]
    cases[-1][2].id = "inc-equal-holders"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database}")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    triage.AsyncSessionLocal = legacy.AsyncSessionLocal = factory
    triage.triage_queue = TriageQueue(1)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        session.add(Agent(
            id="agent-a", hostname="synthetic-host", ip_address="192.0.2.10", mac_address="00:00:00:00:00:01",
        ))
        await session.flush()
        session.add_all(incident for _, _, incident in cases)
        await session.commit()

    class MeasuredService(triage.AITriageService):
        async def _infer(self, context, route):
            return await super()._infer(context, route, settings=settings)

    try:
        async with httpx.AsyncClient(base_url=args.url, timeout=10.0) as metadata:
            listed = (await metadata.get("/api/tags")).raise_for_status().json()
            model = next(item for item in listed["models"] if item["name"] == client.model)
            print(json.dumps({"dataset": "synthetic", "model": model["name"], "digest": model["digest"]}), flush=True)
            for variant in args.variants:
                (await metadata.post(
                    "/api/generate", json={"model": client.model, "keep_alive": 0},
                )).raise_for_status()
                settings = replace(TRIAGE_SETTINGS, num_ctx=8192 if variant == "B" else 4096)
                triage.route_triage = (
                    (lambda context, **kwargs: route_triage(context, enable_skip=False, **kwargs))
                    if variant == "D" else (lambda *_args, **_kwargs: RoutingDecision(Route.SINGLE_PASS))
                )
                readings, anonymous_readings, rows = [], [], []
                monitor = asyncio.create_task(sample_memory(args.memory_current, readings, anonymous_readings))
                try:
                    for name, expected, incident in cases:
                        client.calls.clear()
                        started = time.perf_counter()
                        service = legacy.AITriageService() if variant == "A" else MeasuredService()
                        try:
                            async with asyncio.timeout(180):
                                row = await service.analyze_incident(incident.id)
                        except TimeoutError:
                            row = None
                        item = calculate(
                            name, expected, row, build_alert_context(incident), client.calls, variant == "A",
                        )
                        item["job_seconds"] = round(time.perf_counter() - started, 3)
                        rows.append(item)
                        print(json.dumps({"variant": variant, **item}), flush=True)
                finally:
                    monitor.cancel()
                    monitor_result = (await asyncio.gather(monitor, return_exceptions=True))[0]
                    if isinstance(monitor_result, Exception):
                        print(json.dumps({"memory_error": type(monitor_result).__name__}), flush=True)
                running = (await metadata.get("/api/ps")).raise_for_status().json()
                profile = next((model for model in running["models"] if model["name"] == client.model), {})
                print(json.dumps({
                    "variant": variant, "summary": summary(rows, readings, anonymous_readings),
                    "ollama_model_bytes": profile.get("size"), "context_length": profile.get("context_length"),
                }), flush=True)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:21434", help="Isolated Ollama endpoint")
    parser.add_argument("--baseline-ref", default="2c257ef", help="Git revision with the pre-change pipeline")
    parser.add_argument("--variants", default="ABCD", choices=("ABCD", "BCD", "A", "B", "C", "D"))
    parser.add_argument("--memory-current", type=Path, help="Read-only cgroup memory.current for the isolated server")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="larp-triage-bench-") as directory:
        asyncio.run(benchmark(options, Path(directory) / "cases.db"))
