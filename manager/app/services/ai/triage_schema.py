"""Strict model outputs contain references and verdicts, never free-form telemetry."""
import json
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.services.ai.alert_context_projector import AlertContext
from app.services.ai.knowledge.mitre_kb import mitre_kb
from app.services.detection.behavior_evidence import BEHAVIORS, BRUTE_FORCE, REPEATED, SCAN, SQLI, UNKNOWN

Classification = Literal[
    "benign_expected", "suspicious_unconfirmed", "likely_malicious",
    "confirmed_malicious", "insufficient_telemetry",
    "repeated_auth_failures", "authentication_brute_force", "sqli_probing",
    "network_service_scanning", "unknown_automated_activity",
]
EvidenceID = Annotated[str, Field(pattern=r"^[PNF][1-9][0-9]{0,2}$")]
EvidenceIDs = Annotated[list[EvidenceID], Field(max_length=8)]


class VerdictSchemaError(ValueError):
    """The response cannot be used to make a grounded SOC assessment."""


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    evidence_ids: EvidenceIDs

    @model_validator(mode="after")
    def unique_evidence(self):
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("Duplicate evidence references")
        return self


class TechniqueClaim(EvidenceAssessment):
    id: Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]


class TriageVerdict(EvidenceAssessment):
    classification: Classification
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    mitre_techniques: Annotated[list[TechniqueClaim], Field(max_length=3)]


@dataclass(frozen=True)
class ValidatedVerdict:
    classification: Classification
    confidence: float
    evidence_ids: list[str]
    techniques: list[dict]
    evidence_completeness: str | None = None


def _unique_keys(pairs):
    data = dict(pairs)
    if len(data) != len(pairs):
        raise VerdictSchemaError("Duplicate JSON keys")
    return data


def parse_output(result: dict, schema: type[EvidenceAssessment], visible_ids: set[str]):
    metrics = result.get("metrics", {})
    text = result.get("answer")
    if not isinstance(metrics, dict) or metrics.get("done") is False or not isinstance(text, str) or len(text) > 16_384:
        raise VerdictSchemaError("Incomplete or oversized model response")
    if metrics.get("done_reason") == "length":
        raise VerdictSchemaError("Model output exceeded its token limit")
    try:
        data = json.loads(text, object_pairs_hook=_unique_keys)
        output = schema.model_validate(data)
    except (ValueError, RecursionError) as exc:
        raise VerdictSchemaError("Model output failed JSON Schema validation") from exc
    if not set(output.evidence_ids) <= visible_ids:
        raise VerdictSchemaError("Model referenced evidence outside its input")
    return output


def permitted_techniques(context: AlertContext, used_ids: set[str]) -> set[str]:
    if context.verified_shell in used_ids:
        return {"T1059.004"}
    # A static mapping or a network tuple alone cannot establish the C2 protocol
    # or command execution. Other mappings still need relevant structured facts.
    facts = [context.by_id[key] for key in used_ids if key in context.by_id]
    behavior_techniques = {item["verified_technique"] for item in facts
                           if item.get("kind") == "behavior" and item.get("verified_technique")}
    if behavior_techniques:
        return behavior_techniques
    if any(item.get("kind") == "fim" and item.get("path") not in (None, "N/A") for item in facts):
        return {tech for tech in context.mapped_techniques if not tech.startswith(("T1071", "T1059"))}
    return set()


def behavior_verdict(context: AlertContext) -> ValidatedVerdict | None:
    for item in context.facts:
        if item.get("kind") == "behavior":
            key = item["id"]
            tech = item.get("verified_technique")
            techniques = [format_technique(tech, [key])] if tech and mitre_kb.validate_technique(tech) else []
            completeness = item.get("evidence_completeness", "partial")
            classification = item["classification"]
            confidence = {
                REPEATED: 0.9, BRUTE_FORCE: 0.85, SCAN: 0.85,
                SQLI: 0.85 if tech else 0.7, UNKNOWN: 0.45,
            }[classification]
            return ValidatedVerdict(
                classification, confidence, [key], techniques, completeness,
            )
        if item.get("kind") == "authentication" and type(item.get("reported_failed_attempts")) is int:
            return ValidatedVerdict(REPEATED, 0.5, [item["id"]], [], "partial")
    return None


def validate_verdict(output: TriageVerdict, context: AlertContext) -> ValidatedVerdict:
    used = set(output.evidence_ids)
    if output.classification != "insufficient_telemetry" and not used:
        raise VerdictSchemaError("A classification needs evidence references")
    techniques = []
    seen = set()
    for claim in output.mitre_techniques:
        claim_ids = set(claim.evidence_ids)
        if not claim_ids or not claim_ids <= used:
            raise VerdictSchemaError("MITRE claim uses evidence absent from the verdict")
        if claim.id in seen:
            raise VerdictSchemaError("Duplicate MITRE technique")
        if claim.id in permitted_techniques(context, claim_ids) and mitre_kb.validate_technique(claim.id):
            techniques.append(format_technique(claim.id, claim.evidence_ids))
        seen.add(claim.id)

    classification, confidence = output.classification, output.confidence
    if (behavior := behavior_verdict(context)) is not None:
        return behavior
    if classification in BEHAVIORS:
        classification, confidence = "suspicious_unconfirmed", min(confidence, 0.5)
    if context.verified_shell:
        if context.verified_shell not in used:
            return ValidatedVerdict(
                "likely_malicious", 0.85 if context.conflict else 0.9, [context.verified_shell],
                [format_technique("T1059.004", [context.verified_shell])],
            )
        if classification != "likely_malicious" or context.conflict:
            confidence = min(confidence, 0.85)
        classification = "likely_malicious"
        if not any(item["id"] == "T1059.004" for item in techniques):
            techniques.append(format_technique("T1059.004", [context.verified_shell]))
    elif classification in {"confirmed_malicious", "likely_malicious", "benign_expected"}:
        classification = "suspicious_unconfirmed" if has_structured_evidence(context, used) else "insufficient_telemetry"
        confidence = min(confidence, 0.5)
    if classification == "suspicious_unconfirmed" and not has_structured_evidence(context, used):
        classification = "insufficient_telemetry"
    elif classification == "suspicious_unconfirmed":
        confidence = min(confidence, 0.6)
    if classification == "insufficient_telemetry":
        confidence = 0.0
        techniques = []
    return ValidatedVerdict(classification, confidence, output.evidence_ids, techniques)


def has_structured_evidence(context: AlertContext, used_ids: set[str]) -> bool:
    for key in used_ids:
        item = context.by_id.get(key, {})
        if key.startswith("P") and item.get("process_start_time") not in (None, "N/A"):
            return True
        if key.startswith("N") and item.get("holders"):
            return True
        if item.get("kind") == "fim" and item.get("path") not in (None, "N/A"):
            return True
        if item.get("kind") == "authentication" and item.get("service") not in (None, "N/A"):
            return True
        if item.get("kind") == "behavior" and item.get("source_event_ids"):
            return True
    return False


def format_technique(tech_id: str, evidence_ids: list[str]) -> dict:
    meta = mitre_kb.get_technique(tech_id)
    return {
        "id": tech_id, "name": meta.get("name", tech_id), "tactic": meta.get("tactic", "unknown"),
        "evidence": ", ".join(evidence_ids),
    }
