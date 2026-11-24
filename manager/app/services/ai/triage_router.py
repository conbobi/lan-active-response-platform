"""Admission control and routing for triage jobs."""
import asyncio
import os
from dataclasses import dataclass
from enum import StrEnum

from app.services.ai.alert_context_projector import NA, AlertContext
from app.services.detection.network_shell import RULE_ID

DETERMINISTIC_RULES = {(RULE_ID, "builtin:1")}
LOW_RISK = 35.0


class Route(StrEnum):
    SKIP_LLM = "skip_llm"
    SINGLE_PASS = "single_pass"
    MULTI_PHASE = "multi_phase"


@dataclass(frozen=True)
class RoutingDecision:
    route: Route
    shadow_candidate: bool = False

    @property
    def deadline_seconds(self) -> int:
        return 180 if self.route == Route.MULTI_PHASE else 120


def route_triage(
    context: AlertContext, *, manual: bool = False, enable_skip: bool | None = None,
) -> RoutingDecision:
    if context.conflict or context.chain_count > 1:
        return RoutingDecision(Route.MULTI_PHASE)

    rule = context.metadata["rule_id"], context.metadata["rule_version"]
    verified = (
        rule in DETERMINISTIC_RULES and context.verified_shell is not None
        and context.by_id[context.verified_shell]["attribution"] == "inode_verified"
    )
    risk = context.metadata["risk_score"]
    low_risk = (
        not manual and type(risk) in (float, int) and 0 <= risk < LOW_RISK
        and rule[0] == NA and not context.facts and not context.missing
        and any(item["holders"] and item["attribution"] == "inode_verified"
                and item["state"] == "ESTABLISHED" and item["observed_at"] != NA
                for item in context.flows)
    )
    if enable_skip is None:
        enable_skip = os.getenv("AI_TRIAGE_ENABLE_SKIP", "false").lower() == "true"
    if (verified or low_risk) and enable_skip:
        return RoutingDecision(Route.SKIP_LLM)
    return RoutingDecision(Route.SINGLE_PASS, shadow_candidate=verified or low_risk)


class TriageQueue:
    """Process-local bound for the single-worker Manager and one Ollama slot."""

    def __init__(self, max_waiting: int = 8):
        if max_waiting < 0:
            raise ValueError("max_waiting must be nonnegative")
        self.capacity = max_waiting + 1
        self.pending: dict[tuple[str, str], asyncio.Task] = {}
        self._loop = None
        self._slot = None

    def submit(self, key, run) -> asyncio.Task | None:
        existing = self.pending.get(key)
        if existing is not None:
            if not existing.done():
                return existing
            self.pending.pop(key)
        if len(self.pending) >= self.capacity:
            return None
        loop = asyncio.get_running_loop()
        if self._loop != loop:
            self._loop = loop
            self._slot = asyncio.Semaphore(1)
        task = loop.create_task(run(self._slot))
        self.pending[key] = task
        task.add_done_callback(lambda completed: self._discard(key, completed))
        return task

    def _discard(self, key, completed):
        if self.pending.get(key) is completed:
            self.pending.pop(key)


triage_queue = TriageQueue(max_waiting=int(os.getenv("AI_TRIAGE_MAX_WAITING", "8")))
