"""Authorization-independent response policy. The model may only select a candidate."""
import asyncio
import json
from typing import Literal
from time import monotonic

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.services.ai.triage_schema import parse_output
from app.services.ai.ai_client import ai_client
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


async def recommend(investigation, proposal):
    start = monotonic()
    source = "policy_fallback"
    selected = True
    try:
        async with asyncio.timeout(12):
            result = await ai_client.generate(
                json.dumps({"observations": investigation["observed_facts"], "evidence_ids": proposal.evidence_ids,
                            "candidate": proposal.action_type, "risk_score": investigation["risk_score"],
                            "classification": investigation["classification"], "confidence": investigation["confidence"],
                            "completeness": investigation["evidence_completeness"],
                            "asset_criticality": investigation["asset_criticality"],
                            "recent_outcomes": investigation["recent_outcomes"]}),
                system="Select the supplied candidate or no_action. Return all supplied evidence IDs exactly.",
                format_schema=ModelChoice.model_json_schema(), strict=True, options={"num_predict": 384},
            )
            choice = parse_output(result, ModelChoice, set(proposal.evidence_ids))
            if sorted(choice.evidence_ids) != sorted(proposal.evidence_ids):
                raise ValueError("Evidence mismatch")
            if choice.action_type not in {proposal.action_type, "no_action"}:
                raise ValueError("Candidate mismatch")
            selected = choice.action_type != "no_action"
            source = "ollama"
    except (TimeoutError, httpx.HTTPError, ValueError, KeyError, TypeError):
        # The deterministic read-only candidate still requires human approval.
        source = "policy_fallback"
    return selected, source, round((monotonic() - start) * 1000)
