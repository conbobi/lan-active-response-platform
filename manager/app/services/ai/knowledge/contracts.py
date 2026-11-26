"""Shared types for the LARP security knowledge base, evidence-to-knowledge mapping and caches.

Knowledge is reference material, never evidence: an incident's findings must cite its own evidence IDs,
and knowledge chunks are cited separately by ``chunk_id`` (see docs/KNOWLEDGE_ARCHITECTURE.md).
"""
from __future__ import annotations

from dataclasses import dataclass, field

KNOWLEDGE_CATEGORIES = (
    "sql_injection",
    "command_injection",
    "authentication_abuse",
    "network_scanning",
    "reverse_shell",
    "suspicious_process_execution",
    "persistence",
    "beaconing",
    "data_exfiltration",
    "false_positive_investigation",
    "host_containment",
    "firewall_waf_blocking",
    "session_revocation",
    "remediation",
    "incident_response_process",
)


@dataclass(frozen=True)
class KnowledgeChunk:
    """One retrievable, citable excerpt of a source document."""

    chunk_id: str            # stable across rebuilds of the same source version, e.g. "owasp-sqli:defense-option-1:0"
    source_id: str           # key in knowledge_manifest.json "sources"
    title: str               # section heading or technique name
    category: str            # one of KNOWLEDGE_CATEGORIES
    text: str                # excerpt, at most 1200 characters
    url: str                 # canonical URL of the section or document
    version: str             # source version (ATT&CK release, git commit, publication revision)
    synced_at: str           # ISO-8601 date of the sync that produced this chunk
    attack_ids: tuple[str, ...] = ()

    def citation(self) -> dict:
        return {"chunk_id": self.chunk_id, "source_id": self.source_id, "title": self.title,
                "url": self.url, "version": self.version}


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    name: str
    evidence_refs: tuple[str, ...]      # incident evidence IDs that justify the mapping (never empty)
    knowledge_refs: tuple[str, ...]     # chunk_ids describing the technique


@dataclass(frozen=True)
class PatternAssessment:
    """Deterministic placement of incident evidence on a detection pattern ladder."""

    pattern_id: str                     # e.g. "sqli"
    level: int                          # 0 = not matched; ladder levels start at 1
    level_name: str                     # e.g. "tool_indicator", "probing", "exploitation_suspected"
    conclusion: str                     # one Vietnamese sentence the analyst can read
    confirmed_facts: tuple[str, ...]    # statements backed by evidence_refs
    suspected: tuple[str, ...]          # hypotheses, explicitly not confirmed
    missing_evidence: tuple[str, ...]   # what would move the assessment up or down the ladder
    alternative_explanations: tuple[str, ...]
    investigation_steps: tuple[str, ...]
    attack_mapping: tuple[AttackMapping, ...]
    evidence_refs: tuple[str, ...]
    knowledge_refs: tuple[str, ...]
    playbook_id: str | None = None
    post_exploitation: tuple[dict, ...] = field(default_factory=tuple)
