"""Authorization-independent response policy. The model may only select a candidate."""
import asyncio
import json
import os
from typing import Literal
from time import monotonic

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.services.ai.triage_schema import parse_output
from app.services.ai.triage_router import triage_queue
from app.services.ai.ai_client import ai_client
from app.services.ai.analysis_cache import AnalysisKey, analysis_cache
from app.services.response.http_investigation import ASSIST_TYPES, GUIDE


class ModelChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: Literal["collect_additional_evidence", "temporary_ip_block", "apply_rate_limit", "revoke_session", "generate_remediation_guidance", "increase_monitoring", "no_action"]
    evidence_ids: list[str] = Field(min_length=1, max_length=256)


def decision(action_type, proposal):
    if not proposal:
        return "REQUIRE_MORE_EVIDENCE"
    if action_type != proposal.action_type or action_type not in ASSIST_TYPES:
        return "DENY"
    return "ALLOW_AUTOMATIC" if action_type == GUIDE else "REQUIRE_APPROVAL"


SYSTEM = "Select the supplied candidate or no_action. Return all supplied evidence IDs exactly."


async def _infer(slot, payload, proposal):
    queued = monotonic()
    async with asyncio.timeout(12):
        async with slot:
            queue_ms = round((monotonic() - queued) * 1000, 3)
            reply = await ai_client.generate(
                json.dumps(payload), system=SYSTEM, format_schema=ModelChoice.model_json_schema(),
                strict=True, options={"num_predict": 384})

    started = monotonic()
    choice = parse_output(reply, ModelChoice, set(proposal.evidence_ids))
    if sorted(choice.evidence_ids) != sorted(proposal.evidence_ids) or choice.action_type not in {proposal.action_type, "no_action"}:
        raise ValueError("Model choice does not match current evidence")
    timing = {"manager_queue_wait_ms": queue_ms, "json_validation_ms": round((monotonic() - started) * 1000, 2)}
    for name in ("load_duration", "prompt_eval_duration", "eval_duration", "total_duration"):
        value = reply.get("metrics", {}).get(name)
        if isinstance(value, int):
            timing[name + "_ms"] = value / 1e6
    return choice, timing


async def recommend(investigation, proposal, db, stages):
    start = monotonic()
    payload = {key: investigation[key] for key in ("risk_score", "classification", "confidence",
                                                    "asset_criticality", "recent_outcomes")}
    payload.update(observations=investigation["observed_facts"], candidate=proposal.action_type,
                   evidence_ids=proposal.evidence_ids, completeness=investigation["evidence_completeness"])
    revision = os.getenv("AI_RESPONSE_MODEL_VERSION")
    key = AnalysisKey(payload, "http_response", ai_client.model, revision or "unpinned",
                      "response-choice-1", "choice-1", proposal.policy_version, proposal.target_agent_id)
    flight = ("response_choice", key.digest())
    try:
        cached = await analysis_cache.get(db, key) if revision else None
        if cached:
            choice = ModelChoice.model_validate(cached.output)
            if sorted(choice.evidence_ids) != sorted(proposal.evidence_ids) or choice.action_type not in {proposal.action_type, "no_action"}:
                raise ValueError("Cached choice does not match current evidence")
            origin = "exact_cache"
        else:
            await db.commit()
            task = triage_queue.submit(flight, lambda slot: _infer(slot, payload, proposal))
            if task is None:
                return True, "policy_fallback", round((monotonic() - start) * 1000)
            choice, timing = await asyncio.shield(task)
            stages.update(timing)
            if revision:
                await analysis_cache.put(db, key, choice.model_dump())
            origin = "ollama"
        selected = choice.action_type != "no_action"
    except (TimeoutError, httpx.HTTPError, ValueError, KeyError, TypeError):
        selected, origin = True, "policy_fallback"
    return selected, origin, round((monotonic() - start) * 1000)
