"""Reasoning Orchestrator primitives shared by the AI Rule Generator and the AI Risk Analyst.

* A read-only toolbox: the orchestrator (never the model) calls tools, and only read-only ones exist.
  Response actions (block, isolate, kill, quarantine) cannot be registered, so no analysis can run them.
* The structured explanation every workflow returns, validated with Pydantic. Each claim carries a
  certainty label (OBSERVED, CORRELATED, INFERRED, UNKNOWN) and the evidence IDs it rests on.
* A bounded Generate → Verify → Revise loop. The verifier is deterministic code that checks the
  output against the evidence; the model's own conclusion is never used to prove itself.
"""
from __future__ import annotations

import os
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field


def max_revisions() -> int:
    """Revisions allowed after the first model answer fails verification (0 = no revision)."""
    try:
        return max(0, min(3, int(os.getenv("AI_REASONING_MAX_REVISIONS", "1"))))
    except ValueError:
        return 1


class Certainty(str, Enum):
    OBSERVED = "OBSERVED"        # read directly from telemetry or the Detection Engine
    CORRELATED = "CORRELATED"    # two or more observed records joined (same agent, PID, time window)
    INFERRED = "INFERRED"        # a plausible reading of observed data, not itself observed
    UNKNOWN = "UNKNOWN"          # the data needed to decide is missing


# ── Read-only toolbox ───────────────────────────────────────────────────────────────────────────
RESPONSE_ACTIONS = frozenset({
    "block_ip", "unblock_ip", "isolate_host", "unisolate_host", "kill_process", "quarantine_file",
    "restore_file", "disable_user", "execute_response", "activate_rule",
})


class ToolNotAllowed(PermissionError):
    pass


class ReadOnlyToolbox:
    """Named read-only tools the orchestrator may call during an analysis. Nothing else is callable."""

    def __init__(self) -> None:
        self._tools: Dict[str, Callable[..., Awaitable[Any]]] = {}
        self.calls: List[str] = []

    def register(self, name: str, fn: Callable[..., Awaitable[Any]]) -> None:
        if name in RESPONSE_ACTIONS or not name.startswith(("read_", "load_", "list_", "check_", "lookup_")):
            raise ToolNotAllowed(f"'{name}' is not a read-only tool")
        self._tools[name] = fn

    @property
    def names(self) -> Tuple[str, ...]:
        return tuple(self._tools)

    async def call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        if name not in self._tools:
            raise ToolNotAllowed(f"Tool '{name}' is not available to the AI orchestrator")
        self.calls.append(name)
        return await self._tools[name](*args, **kwargs)


# ── Structured explanation ──────────────────────────────────────────────────────────────────────
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Claim(_Strict):
    fact_id: str
    statement: str = Field(max_length=600)
    certainty: Certainty
    evidence_ids: List[str] = Field(default_factory=list, max_length=20)
    source_type: str = "DETERMINISTIC"


class MatchedRule(_Strict):
    rule_id: str
    label: Optional[str] = None
    contribution: Optional[float] = None
    reason: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list, max_length=15)


class Alternative(_Strict):
    alt_id: str
    explanation: str = Field(max_length=400)
    certainty: Certainty
    basis: str = Field(max_length=400)
    evidence_ids: List[str] = Field(default_factory=list, max_length=10)


class CheckResult(_Strict):
    check_id: str
    label: str
    passed: bool
    detail: str = ""


class Recommendation(_Strict):
    text: str = Field(max_length=300)
    requires_approval: Literal[True] = True   # the analysis never executes anything


class RiskScoreRef(_Strict):
    value: float
    severity: str
    source: Literal["DETECTION_ENGINE"] = "DETECTION_ENGINE"
    breakdown_source: str


class StructuredExplanation(_Strict):
    task_type: Literal["risk_question"] = "risk_question"
    question: str
    conclusion: str = Field(max_length=1200)
    conclusion_source: Literal["AI_INFERENCE", "DETERMINISTIC"]
    risk_score: RiskScoreRef
    observed_facts: List[Claim]
    evidence_ids: List[str]
    matched_rules: List[MatchedRule]
    alternative_explanations: List[Alternative]
    missing_evidence: List[str]
    validation_results: List[CheckResult]
    recommendations: List[Recommendation]
    limitations: List[str]
    model_name: Optional[str] = None
    attempts: int = 0


# ── Bounded self-verification loop ──────────────────────────────────────────────────────────────
Generate = Callable[[List[str], int], Awaitable[Any]]
Verify = Callable[[Any], List[CheckResult]]
Hook = Callable[..., Awaitable[None]]


async def generate_verified(generate: Generate, verify: Verify, *, revisions: Optional[int] = None,
                            on_attempt: Optional[Hook] = None, on_checked: Optional[Hook] = None
                            ) -> Tuple[Any, List[CheckResult], int]:
    """Generate → deterministic checks → revise with the failed checks, at most ``revisions`` times.

    Returns (accepted output or None, checks of the last attempt, attempts made). Exceptions from
    ``generate`` (timeouts, transport errors) propagate: a failed model call is not a rejected answer.
    """
    limit = max_revisions() if revisions is None else revisions
    feedback: List[str] = []
    checks: List[CheckResult] = []
    for attempt in range(1, limit + 2):
        if on_attempt:
            await on_attempt(attempt, feedback)
        output = await generate(feedback, attempt)
        checks = verify(output)
        failed = [c for c in checks if not c.passed]
        if on_checked:
            await on_checked(attempt, checks, output)
        if not failed:
            return output, checks, attempt
        feedback = [f"{c.label}: {c.detail}" for c in failed]
    return None, checks, limit + 1
