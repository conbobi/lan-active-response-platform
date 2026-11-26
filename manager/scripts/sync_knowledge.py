#!/usr/bin/env python3
"""Download official security references and normalize them into the LARP knowledge base.

Usage (from the manager/ directory):
    PYTHONPATH=.. .venv/bin/python scripts/sync_knowledge.py            # fetch sources, then build
    PYTHONPATH=.. .venv/bin/python scripts/sync_knowledge.py --offline  # rebuild from raw files + lock

Outputs (committed): knowledge/chunks.jsonl, knowledge/knowledge_manifest.json and
knowledge/sources/sources.lock.json. Raw downloads live in knowledge/sources/raw/ (git-ignored).
The build is deterministic: the same raw files, lock and runbooks give a byte-identical chunks.jsonl.
Knowledge is reference material, never incident evidence.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import html
import json
import logging
import re
import subprocess
import sys
import urllib.request
from collections.abc import Iterable, Iterator
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

MANAGER_DIR = Path(__file__).resolve().parents[1]
if str(MANAGER_DIR) not in sys.path:
    sys.path.insert(0, str(MANAGER_DIR))

from app.services.ai.knowledge.contracts import KNOWLEDGE_CATEGORIES, KnowledgeChunk  # noqa: E402

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = MANAGER_DIR / "knowledge"
RAW_DIR = KNOWLEDGE_DIR / "sources" / "raw"
LOCK_PATH = KNOWLEDGE_DIR / "sources" / "sources.lock.json"
RUNBOOK_DIR = KNOWLEDGE_DIR / "runbooks"
CHUNKS_PATH = KNOWLEDGE_DIR / "chunks.jsonl"
MANIFEST_PATH = KNOWLEDGE_DIR / "knowledge_manifest.json"
SCHEMA_VERSION = 1
MAX_CHARS = 1200
USER_AGENT = "larp-knowledge-sync/1"

# ---------------------------------------------------------------- source configuration

ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
ATTACK_TERMS_URL = "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
# Requested techniques and the knowledge category their chunks belong to.
ATTACK_TECHNIQUES = {
    "T1190": "sql_injection",
    "T1046": "network_scanning",
    "T1110": "authentication_abuse",
    "T1110.001": "authentication_abuse",
    "T1110.003": "authentication_abuse",
    "T1110.004": "authentication_abuse",
    "T1059": "suspicious_process_execution",
    "T1059.004": "reverse_shell",
    "T1059.006": "suspicious_process_execution",
    "T1071": "beaconing",
    "T1071.001": "beaconing",
    "T1041": "data_exfiltration",
    "T1048": "data_exfiltration",
    "T1105": "suspicious_process_execution",
    "T1078": "authentication_abuse",
    "T1505.003": "persistence",
    "T1595": "network_scanning",
    "T1595.002": "network_scanning",
    "T1053.003": "persistence",
    "T1543.002": "persistence",
    "T1098.004": "persistence",
    "T1572": "beaconing",
    "T1021.004": "authentication_abuse",
}
FULL_DETECTION_STRATEGIES = ("DET0080",)
DETECTION_PLATFORMS = {"Linux"}  # other strategies: only analytics for the platform LARP monitors

OWASP_REPO = "OWASP/CheatSheetSeries"
OWASP_SHEETS = {
    "owasp-sqli-prevention": "SQL_Injection_Prevention_Cheat_Sheet.md",
    "owasp-query-parameterization": "Query_Parameterization_Cheat_Sheet.md",
    "owasp-os-command-injection": "OS_Command_Injection_Defense_Cheat_Sheet.md",
}
OWASP_CATEGORY = {
    "owasp-sqli-prevention": "sql_injection",
    "owasp-query-parameterization": "sql_injection",
    "owasp-os-command-injection": "command_injection",
}
OWASP_LICENSE = "CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)"
OWASP_SKIP_SECTIONS = {"references"}

NIST_PDF_URL = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf"
NIST_PAGE_URL = "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
NIST_VERSION = "SP 800-61 Rev. 3 (April 2025)"
NIST_LICENSE = "U.S. Government work, not subject to copyright in the United States (17 U.S.C. 105)"
NIST_PDF = "NIST.SP.800-61r3.pdf"
NIST_TEXT = "NIST.SP.800-61r3.layout.txt"
NIST_ELEMENT_CATEGORY = {"RS.MI": "remediation", "RC": "remediation"}

# Documented deviations, published in the manifest next to the affected source.
SOURCE_NOTES = {
    "mitre-attack": "DET0080 and its analytics are read from the STIX bundle only. The attack.mitre.org "
                    "HTML fallback is not implemented; if a bundle lacks DET0080 it is listed in missing_items.",
}

RUNBOOK_SECTIONS = (
    "observed-indicators", "required-evidence", "attack-mapping", "alternative-explanations",
    "investigation-steps", "response-options", "execution-prerequisites", "operational-risks",
    "rollback-guidance",
)

# ---------------------------------------------------------------- text helpers

CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\((?:[^()\s]|\([^)]*\))+\)")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
# Only real inline HTML is stripped; placeholders such as <username> or generics such as Vec<User> are kept.
HTML_TAGS = ("a", "b", "br", "code", "em", "i", "kbd", "li", "ol", "p", "pre", "span", "strong", "sub", "sup", "ul")
HTML_TAG = re.compile(rf"</?(?:{'|'.join(HTML_TAGS)})(?:\s[^<>]*)?/?>", re.I)
FENCE = re.compile(r"^\s*(```|~~~)")


def _clean_prose(text: str) -> str:
    text = HTML_COMMENT.sub("", text)
    text = CITATION.sub("", text)
    text = MD_IMAGE.sub("", text)
    text = MD_LINK.sub(r"\1", text)
    text = html.unescape(HTML_TAG.sub("", text))
    return "\n".join(re.sub(r"[ \t]+", " ", line).rstrip() for line in text.split("\n"))


def _fenced_segments(text: str) -> Iterator[tuple[bool, str]]:
    """Split markdown into (is_code, text) segments; fence lines belong to the code segment."""
    segment: list[str] = []
    fenced = False
    for line in text.split("\n"):
        if FENCE.match(line):
            if fenced:
                segment.append(line)
                yield True, "\n".join(segment)
                segment, fenced = [], False
                continue
            yield False, "\n".join(segment)
            segment, fenced = [line], True
            continue
        segment.append(line)
    yield fenced, "\n".join(segment)


def clean_markup(text: str) -> str:
    """Strip STIX citation markers, markdown links/images, HTML comments and inline HTML from prose.

    Fenced code blocks are kept verbatim (only trailing whitespace is removed) so examples are never altered.
    """
    text = text.replace("\r\n", "\n")
    parts = [("\n".join(line.rstrip() for line in segment.split("\n")) if code else _clean_prose(segment))
             for code, segment in _fenced_segments(text)]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(parts)).strip()


def slugify(text: str) -> str:
    """Python-Markdown toc slug (used by the OWASP cheat sheet site)."""
    value = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def _hard_split(text: str, limit: int) -> Iterator[str]:
    while len(text) > limit:
        cut = text.rfind(" ", 0, limit)
        cut = cut if cut > limit // 2 else limit
        yield text[:cut].rstrip()
        text = text[cut:].lstrip()
    if text:
        yield text


def _units(text: str, limit: int) -> Iterator[str]:
    for paragraph in re.split(r"\n[ \t]*\n", text):
        paragraph = paragraph.strip("\n").rstrip()
        if len(paragraph) <= limit:
            if paragraph.strip():
                yield paragraph
            continue
        for line in paragraph.split("\n"):
            for sentence in re.split(r"(?<=[.!?])\s+", line.strip()):
                yield from _hard_split(sentence, limit)


def split_text(text: str, limit: int = MAX_CHARS) -> list[str]:
    """Pack paragraphs (then sentences) into pieces of at most ``limit`` characters."""
    pieces: list[str] = []
    current = ""
    for unit in _units(text, limit):
        candidate = f"{current}\n\n{unit}" if current else unit
        if len(candidate) <= limit:
            current = candidate
        else:
            pieces.append(current)
            current = unit
    if current:
        pieces.append(current)
    return pieces


def make_chunks(*, source_id: str, key: str, title: str, category: str, text: str, url: str,
                version: str, synced_at: str, attack_ids: Iterable[str] = ()) -> list[KnowledgeChunk]:
    if category not in KNOWLEDGE_CATEGORIES:
        raise ValueError(f"Unknown knowledge category {category!r}")
    ids = tuple(dict.fromkeys(attack_ids))
    return [KnowledgeChunk(chunk_id=f"{source_id}:{key}:{index}", source_id=source_id,
                           title=title if index == 0 else f"{title} (part {index + 1})",
                           category=category, text=piece, url=url, version=version,
                           synced_at=synced_at, attack_ids=ids)
            for index, piece in enumerate(split_text(text))]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------- MITRE ATT&CK


def _external_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _index_attack(bundle: dict) -> dict:
    objects = [o for o in bundle.get("objects", []) if _active(o)]
    by_ref = {o["id"]: o for o in objects}
    techniques: dict[str, dict] = {}
    strategies: dict[str, dict] = {}
    for obj in objects:
        external_id, _ = _external_id(obj)
        if obj["type"] == "attack-pattern" and external_id:
            if external_id not in techniques or obj.get("modified", "") > techniques[external_id].get("modified", ""):
                techniques[external_id] = obj
        elif obj["type"] == "x-mitre-detection-strategy" and external_id:
            strategies[external_id] = obj
    tactics = {o.get("x_mitre_shortname"): o["name"] for o in objects if o["type"] == "x-mitre-tactic"}
    detects: dict[str, list[str]] = {}
    for rel in objects:
        if rel["type"] == "relationship" and rel.get("relationship_type") == "detects":
            source, target = by_ref.get(rel["source_ref"]), by_ref.get(rel["target_ref"])
            if source and target and source["type"] == "x-mitre-detection-strategy" and target["type"] == "attack-pattern":
                detects.setdefault(_external_id(source)[0], []).append(_external_id(target)[0])
    return {"by_ref": by_ref, "techniques": techniques, "strategies": strategies,
            "tactics": tactics, "detects": {k: sorted(set(v)) for k, v in detects.items()}}


def attack_names(bundle: dict) -> dict[str, str]:
    return {tid: obj["name"] for tid, obj in _index_attack(bundle)["techniques"].items()
            if tid in ATTACK_TECHNIQUES}


def _technique_chunks(tid: str, obj: dict, index: dict, version: str, synced_at: str) -> list[KnowledgeChunk]:
    _, url = _external_id(obj)
    tactics = [index["tactics"].get(phase["phase_name"], phase["phase_name"])
               for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"]
    header = (f"{tid} {obj['name']}. Tactic: {', '.join(tactics) or 'n/a'}. "
              f"Platforms: {', '.join(obj.get('x_mitre_platforms', [])) or 'n/a'}. {version}.")
    common = dict(source_id="mitre-attack", category=ATTACK_TECHNIQUES[tid], url=url, version=version,
                  synced_at=synced_at, attack_ids=(tid,))
    chunks = make_chunks(key=f"{tid}:description", title=obj["name"],
                         text=f"{header}\n\n{clean_markup(obj.get('description', ''))}", **common)
    if obj.get("x_mitre_detection"):
        chunks += make_chunks(key=f"{tid}:detection", title=f"{obj['name']}: detection",
                              text=clean_markup(obj["x_mitre_detection"]), **common)
    return chunks


def _analytic_text(analytic: dict, detailed: bool) -> str:
    platforms = ", ".join(analytic.get("x_mitre_platforms", []))
    parts = [f"{_external_id(analytic)[0]} ({platforms}): {clean_markup(analytic.get('description', ''))}"]
    sources = [f"{ref.get('name')} [{ref.get('channel')}]" for ref in analytic.get("x_mitre_log_source_references", [])]
    if sources:
        parts.append("Log sources: " + "; ".join(sources))
    if detailed:
        tunables = [f"{item.get('field')}: {clean_markup(item.get('description', ''))}"
                    for item in analytic.get("x_mitre_mutable_elements", [])]
        if tunables:
            parts.append("Tunable elements: " + "; ".join(tunables))
    return "\n".join(parts)


def _strategy_chunks(det_id: str, index: dict, version: str, synced_at: str) -> list[KnowledgeChunk]:
    strategy = index["strategies"][det_id]
    detected = index["detects"].get(det_id, [])
    requested = [tid for tid in detected if tid in ATTACK_TECHNIQUES]
    _, url = _external_id(strategy)
    detailed = det_id in FULL_DETECTION_STRATEGIES
    analytics = [index["by_ref"][ref] for ref in strategy.get("x_mitre_analytic_refs", []) if ref in index["by_ref"]]
    if not detailed:
        analytics = [a for a in analytics if DETECTION_PLATFORMS & set(a.get("x_mitre_platforms", []))]
    analytics.sort(key=lambda a: _external_id(a)[0] or "")
    common = dict(source_id="mitre-attack", category=ATTACK_TECHNIQUES[requested[0]], version=version,
                  synced_at=synced_at, attack_ids=tuple(detected))
    title = f"{det_id} {clean_markup(strategy['name'])}"
    head = f"Detection strategy {title}. Detects: {', '.join(detected)}. {version}."
    if not detailed:
        body = "\n\n".join([head, *(_analytic_text(a, False) for a in analytics)])
        return make_chunks(key=det_id, title=title, text=body, url=url, **common)
    chunks = make_chunks(key=f"{det_id}:overview", title=title, text=head, url=url, **common)
    for analytic in analytics:
        an_id, an_url = _external_id(analytic)
        chunks += make_chunks(key=f"{det_id}:{an_id}", title=f"{det_id} analytic {an_id}",
                              text=_analytic_text(analytic, True), url=an_url or url, **common)
    return chunks


def build_attack(bundle: dict, version: str, synced_at: str) -> tuple[list[KnowledgeChunk], list[str]]:
    index = _index_attack(bundle)
    chunks: list[KnowledgeChunk] = []
    missing = [tid for tid in ATTACK_TECHNIQUES if tid not in index["techniques"]]
    for tid in ATTACK_TECHNIQUES:
        if tid in index["techniques"]:
            chunks += _technique_chunks(tid, index["techniques"][tid], index, version, synced_at)
    wanted = sorted(det for det, tids in index["detects"].items()
                    if det in index["strategies"] and any(t in ATTACK_TECHNIQUES for t in tids))
    for det_id in FULL_DETECTION_STRATEGIES:
        if det_id not in wanted:
            missing.append(det_id)
    for det_id in wanted:
        chunks += _strategy_chunks(det_id, index, version, synced_at)
    return chunks, missing


# ---------------------------------------------------------------- OWASP cheat sheets

HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")


def _markdown_sections(markdown: str) -> Iterator[tuple[int, str, list[str]]]:
    level, heading, body, fenced = 0, "", [], False
    for line in markdown.split("\n"):
        if FENCE.match(line):
            fenced = not fenced
        match = None if fenced else HEADING.match(line)
        if match:
            yield level, heading, body
            level, heading, body = len(match[1]), match[2], []
        else:
            body.append(line)
    yield level, heading, body


def build_owasp(source_id: str, markdown: str, page_url: str, version: str,
                synced_at: str) -> list[KnowledgeChunk]:
    chunks: list[KnowledgeChunk] = []
    document = ""
    skip_level = 0
    anchors: dict[str, int] = {}
    stack: list[tuple[int, str]] = []
    for level, heading, body in _markdown_sections(markdown):
        if level == 1:
            document = heading
            continue
        if skip_level and level > skip_level:
            continue
        skip_level = level if heading.strip().lower() in OWASP_SKIP_SECTIONS else 0
        stack = [(lvl, name) for lvl, name in stack if lvl < level] + ([(level, heading)] if heading else [])
        text = clean_markup("\n".join(body))
        if not heading or skip_level or not text:
            continue
        anchor = slugify(heading)
        seen = anchors.get(anchor, 0)
        anchors[anchor] = seen + 1
        url_anchor = anchor if not seen else f"{anchor}_{seen}"
        path = " > ".join(clean_markup(name) for _, name in stack)
        chunks += make_chunks(source_id=source_id, key=url_anchor, title=f"OWASP {document}: {path}",
                              category=OWASP_CATEGORY[source_id], text=text, url=f"{page_url}#{url_anchor}",
                              version=version, synced_at=synced_at)
    return chunks


# ---------------------------------------------------------------- NIST SP 800-61r3

PAGE_NOISE = re.compile(r"^(NIST SP 800-61r3\s+Incident Response|April 2025\s+Considerations|\s*\d{1,3}\s*$)")
ELEMENT = re.compile(r"^(GV|ID|PR|DE|RS|RC)(\.[A-Z]{2}(-\d{2})?)?(\s|$)")
TABLE_HEADER = re.compile(r"^\s*CSF Element\s{2,}CSF Element Description\s{2,}Priority\s{2,}Recommendations")
SEGMENT = re.compile(r"\S+(?: \S+)*")


def _nist_lines(text: str) -> list[str]:
    """Drop running headers, footers and page-edge blank lines so paragraphs continue across pages."""
    lines: list[str] = []
    for page in text.split("\f"):
        kept = [line for line in page.split("\n") if not PAGE_NOISE.match(line)]
        while kept and not kept[0].strip():
            kept.pop(0)
        while kept and not kept[-1].strip():
            kept.pop()
        lines += kept
    return lines


def _section(lines: list[str], start: str, end: str) -> list[str]:
    """Body lines between two headings (ignores table-of-contents entries with dot leaders)."""
    begin = next(i for i, line in enumerate(lines) if line.startswith(start) and "...." not in line)
    stop = next(i for i in range(begin + 1, len(lines)) if lines[i].startswith(end) and "...." not in lines[i])
    return lines[begin + 1:stop]


def _prose(lines: list[str]) -> str:
    """Join prose lines, dropping figure captions and the layout of embedded tables."""
    kept, skipping = [], False
    for line in lines:
        stripped = line.strip()
        if re.match(r"^(Table|Fig\.) \d+\. ", stripped):
            skipping = True
            continue
        if skipping and stripped and not line.startswith(" "):
            skipping = False
        if not skipping:
            kept.append(stripped)
    text = "\n".join(kept)
    text = re.sub(r"-\n(?=\w)", "-", text)
    text = re.sub(r"\n(?=•)", "\n\n", text)
    text = re.sub(r"(?<!\n)\n(?!\n)", " ", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def _join_column(parts: list[str]) -> str:
    text = ""
    for part in parts:
        text = f"{text}{part}" if text.endswith("-") or not text else f"{text} {part}"
    return text


def _table_rows(lines: list[str]) -> list[dict]:
    rows: list[dict] = []
    columns: list[int] | None = None
    for line in lines:
        if TABLE_HEADER.match(line):
            columns = [0, line.index("CSF Element Description"), line.index("Priority"), line.index("Recommendations")]
            continue
        if columns is None or not line.strip():
            continue
        cells: list[list[str]] = [[], [], [], []]
        for match in SEGMENT.finditer(line):
            column = max(i for i, start in enumerate(columns) if start <= match.start() + 2)
            cells[column].append(match[0])
        first = " ".join(cells[0])
        if first and ELEMENT.match(first):
            rows.append({"cols": [[], [], [], []]})
        if rows:
            for i in range(4):
                if cells[i]:
                    rows[-1]["cols"][i].append(" ".join(cells[i]))
    return [{"element": _join_column(r["cols"][0]), "description": _join_column(r["cols"][1]),
             "priority": _join_column(r["cols"][2]), "notes": _join_column(r["cols"][3])} for r in rows]


def _nist_category(element_id: str) -> str:
    for prefix, category in NIST_ELEMENT_CATEGORY.items():
        if element_id.startswith(prefix):
            return category
    return "incident_response_process"


def build_nist(text: str, synced_at: str) -> list[KnowledgeChunk]:
    lines = _nist_lines(text)
    common = dict(source_id="nist-sp800-61r3", url=NIST_PAGE_URL, version=NIST_VERSION, synced_at=synced_at)
    chunks = make_chunks(key="2-1-life-cycle-model", title="NIST SP 800-61r3 2.1 Incident Response Life Cycle Model",
                         category="incident_response_process",
                         text=_prose(_section(lines, "2.1. Incident Response Life Cycle Model", "2.2. ")), **common)
    lessons = [r for r in _table_rows(_section(lines, "3.1. Preparation and Lessons Learned", "3.2. Incident Response"))
               if r["element"].startswith("ID.IM")]
    response = _table_rows(_section(lines, "3.2. Incident Response", "References"))
    for row in lessons + response:
        element_id = row["element"].split()[0]
        notes = re.sub(r"\s+(?=[RCN]\d+: )", "\n", row["notes"])
        body = f"{row['element']}: {row['description']} (Priority: {row['priority'] or 'n/a'})\n{notes}"
        chunks += make_chunks(key=element_id.lower().replace(".", "-"), category=_nist_category(element_id),
                              title=f"NIST SP 800-61r3 {element_id}: {row['description']}",
                              text=body.replace("\n", "\n\n"), **common)
    return chunks


# ---------------------------------------------------------------- LARP runbooks


def runbook_version(runbook_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(runbook_dir.glob("*.md")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def _parse_runbook(path: Path) -> tuple[dict, dict[str, str]]:
    raw = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", raw, re.S)
    if not match:
        raise ValueError(f"{path.name}: missing front matter")
    meta = yaml.safe_load(match[1]) or {}
    sections = {slugify(h.replace("&", "")).replace("attck", "attack"): "\n".join(b).strip()
                for level, h, b in _markdown_sections(match[2]) if level == 2}
    missing = [name for name in RUNBOOK_SECTIONS if not sections.get(name)]
    if missing:
        raise ValueError(f"{path.name}: missing sections {missing}")
    return meta, sections


def _mapping_text(attack_ids: list[str], body: str, names: dict[str, str], version: str) -> str:
    mapped = [f"{tid} {names[tid]}" if tid in names else f"{tid} (name not in {version} data)" for tid in attack_ids]
    head = f"Technique names from MITRE {version}: " + ("; ".join(mapped) if mapped else "none mapped")
    return f"{head}\n\n{body}"


def build_runbooks(runbook_dir: Path, names: dict[str, str], attack_version: str, version: str,
                   synced_at: str) -> list[KnowledgeChunk]:
    chunks: list[KnowledgeChunk] = []
    for path in sorted(runbook_dir.glob("*.md")):
        meta, sections = _parse_runbook(path)
        attack_ids = [str(t) for t in meta.get("attack_ids") or []]
        overrides = meta.get("section_categories") or {}
        for name in RUNBOOK_SECTIONS:
            body = clean_markup(sections[name])
            if name == "attack-mapping":
                body = _mapping_text(attack_ids, body, names, attack_version)
            heading = name.replace("-", " ").capitalize().replace("Attack", "ATT&CK")
            chunks += make_chunks(source_id="larp-runbooks", key=f"{meta['id']}:{name}",
                                  title=f"[INTERNAL] {meta['title']}: {heading}",
                                  category=overrides.get(name, meta["category"]),
                                  text=f"Internal LARP runbook (not an external authority).\n\n{body}",
                                  url=f"internal://larp/knowledge/runbooks/{path.name}#{name}",
                                  version=version, synced_at=synced_at, attack_ids=attack_ids)
    return chunks


# ---------------------------------------------------------------- build orchestration


def serialize(chunks: list[KnowledgeChunk]) -> list[str]:
    lines = []
    for chunk in chunks:
        record = dataclasses.asdict(chunk)
        record["attack_ids"] = list(chunk.attack_ids)
        lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    return lines


def kb_version(lines: Iterable[str]) -> str:
    """sha256 over the sorted chunks.jsonl lines, each terminated by a newline."""
    return hashlib.sha256("".join(f"{line}\n" for line in sorted(lines)).encode("utf-8")).hexdigest()


def build(raw_dir: Path, lock: dict, runbook_dir: Path) -> tuple[list[KnowledgeChunk], dict[str, list[str]]]:
    """Normalize raw downloads + runbooks. Pure function of its inputs (no network, no clock)."""
    sources = lock["sources"]
    chunks: list[KnowledgeChunk] = []
    missing: dict[str, list[str]] = {}

    attack = sources["mitre-attack"]
    bundle = json.loads((raw_dir / attack["raw_file"]).read_text(encoding="utf-8"))
    attack_chunks, missing["mitre-attack"] = build_attack(bundle, attack["version"], attack["retrieved_at"])
    chunks += attack_chunks

    for source_id in OWASP_SHEETS:
        meta = sources[source_id]
        markdown = (raw_dir / meta["raw_file"]).read_text(encoding="utf-8")
        chunks += build_owasp(source_id, markdown, meta["url"], meta["version"], meta["retrieved_at"])
        missing[source_id] = []

    nist = sources["nist-sp800-61r3"]
    chunks += build_nist((raw_dir / nist["text_file"]).read_text(encoding="utf-8"), nist["retrieved_at"])
    missing["nist-sp800-61r3"] = []

    runbooks = sources["larp-runbooks"]
    chunks += build_runbooks(runbook_dir, attack_names(bundle), attack["version"], runbooks["version"],
                             runbooks["retrieved_at"])
    missing["larp-runbooks"] = []

    ids = [c.chunk_id for c in chunks]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate chunk_id produced by the normalizer")
    return chunks, missing


def verify_raw(raw_dir: Path, lock: dict) -> None:
    for source_id, meta in lock["sources"].items():
        for name, digest in meta.get("files", {}).items():
            if sha256_file(raw_dir / name) != digest:
                raise ValueError(f"{source_id}: raw file {name} does not match the recorded sha256")


def write_outputs(chunks: list[KnowledgeChunk], missing: dict[str, list[str]], lock: dict) -> dict:
    lines = serialize(chunks)
    CHUNKS_PATH.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    counts: dict[str, int] = {}
    for chunk in chunks:
        counts[chunk.source_id] = counts.get(chunk.source_id, 0) + 1
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kb_version": kb_version(lines),
        "built_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "chunk_count": len(lines),
        "note": "Reference material, never incident evidence. Source larp-runbooks is internal.",
        "sources": [{
            "source_id": source_id, "title": meta["title"], "url": meta["url"], "version": meta["version"],
            "license": meta["license"], "retrieved_at": meta["retrieved_at"], "raw_sha256": meta["raw_sha256"],
            "chunk_count": counts.get(source_id, 0), "missing_items": missing.get(source_id, []),
            **({"internal": True} if source_id == "larp-runbooks" else {}),
            **({"note": SOURCE_NOTES[source_id]} if source_id in SOURCE_NOTES else {}),
        } for source_id, meta in lock["sources"].items()],
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


# ---------------------------------------------------------------- network fetch


def _get(url: str, accept: str | None = None) -> bytes:
    headers = {"User-Agent": USER_AGENT, **({"Accept": accept} if accept else {})}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()


def _store(name: str, payload: bytes) -> str:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / name).write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def fetch_attack(today: str) -> dict:
    index = json.loads(_get(ATTACK_INDEX_URL))
    collection = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    latest = max(collection["versions"], key=lambda v: tuple(int(p) for p in v["version"].split(".")))
    name = f"enterprise-attack-{latest['version']}.json"
    logger.info("Downloading %s", latest["url"])
    digest = _store(name, _get(latest["url"]))
    return {"title": "MITRE ATT&CK Enterprise (STIX 2.1)", "url": latest["url"],
            "version": f"ATT&CK v{latest['version']}", "license": f"MITRE ATT&CK Terms of Use ({ATTACK_TERMS_URL})",
            "retrieved_at": today, "raw_file": name, "raw_sha256": digest, "files": {name: digest}}


def fetch_owasp(source_id: str, sheet: str, today: str) -> dict:
    api = f"https://api.github.com/repos/{OWASP_REPO}/commits?path=cheatsheets/{sheet}&per_page=1"
    commit = json.loads(_get(api, "application/vnd.github+json"))[0]["sha"]
    raw_url = f"https://raw.githubusercontent.com/{OWASP_REPO}/{commit}/cheatsheets/{sheet}"
    name = f"owasp-{sheet.removesuffix('.md')}@{commit[:12]}.md"
    logger.info("Downloading %s", raw_url)
    digest = _store(name, _get(raw_url))
    page = f"https://cheatsheetseries.owasp.org/cheatsheets/{sheet.removesuffix('.md')}.html"
    return {"title": f"OWASP {sheet.removesuffix('.md').replace('_', ' ')}", "url": page,
            "version": f"git:{commit}", "license": OWASP_LICENSE, "retrieved_at": today,
            "raw_url": raw_url, "raw_file": name, "raw_sha256": digest, "files": {name: digest}}


def fetch_nist(today: str) -> dict:
    logger.info("Downloading %s", NIST_PDF_URL)
    digest = _store(NIST_PDF, _get(NIST_PDF_URL))
    subprocess.run(["pdftotext", "-layout", str(RAW_DIR / NIST_PDF), str(RAW_DIR / NIST_TEXT)], check=True)
    return {"title": "NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for "
                     "Cybersecurity Risk Management", "url": NIST_PAGE_URL, "version": NIST_VERSION,
            "license": NIST_LICENSE, "retrieved_at": today, "raw_url": NIST_PDF_URL, "raw_file": NIST_PDF,
            "text_file": NIST_TEXT, "raw_sha256": digest,
            "files": {NIST_PDF: digest, NIST_TEXT: sha256_file(RAW_DIR / NIST_TEXT)}}


def runbook_entry(previous: dict | None, today: str) -> dict:
    version = runbook_version(RUNBOOK_DIR)
    unchanged = previous and previous.get("version") == version
    return {"title": "LARP internal runbooks (INTERNAL, derived from this repository)",
            "url": "internal://larp/knowledge/runbooks/", "version": version,
            "license": "internal (LARP project)", "retrieved_at": previous["retrieved_at"] if unchanged else today,
            "raw_sha256": version, "files": {}}


def fetch_all(previous: dict | None) -> dict:
    today = date.today().isoformat()
    sources = {"mitre-attack": fetch_attack(today)}
    for source_id, sheet in OWASP_SHEETS.items():
        sources[source_id] = fetch_owasp(source_id, sheet, today)
    sources["nist-sp800-61r3"] = fetch_nist(today)
    sources["larp-runbooks"] = runbook_entry((previous or {}).get("sources", {}).get("larp-runbooks"), today)
    return {"schema_version": SCHEMA_VERSION, "sources": sources}


def upstream_changes(previous: dict | None, lock: dict) -> list[str]:
    """Sources whose downloaded content changed while their recorded version string did not."""
    before = (previous or {}).get("sources", {})
    changed = []
    for source_id, meta in lock["sources"].items():
        old = before.get(source_id)
        if old and old.get("version") == meta["version"] and old.get("raw_sha256") != meta["raw_sha256"]:
            logger.warning("%s: content changed upstream under the unchanged version %r (sha256 %s -> %s)",
                           source_id, meta["version"], old.get("raw_sha256"), meta["raw_sha256"])
            changed.append(source_id)
        elif old and old.get("version") != meta["version"]:
            logger.info("%s: version %s -> %s", source_id, old.get("version"), meta["version"])
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--offline", action="store_true", help="rebuild from existing raw files and the lock")
    parser.add_argument("--accept-upstream-change", action="store_true",
                        help="accept downloads whose content changed while the recorded version did not")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    previous = json.loads(LOCK_PATH.read_text(encoding="utf-8")) if LOCK_PATH.exists() else None
    if args.offline:
        if previous is None:
            parser.error("--offline requires an existing sources.lock.json")
        lock = previous
        lock["sources"]["larp-runbooks"] = runbook_entry(lock["sources"].get("larp-runbooks"), date.today().isoformat())
    else:
        lock = fetch_all(previous)
        changed = upstream_changes(previous, lock)
        if changed and not args.accept_upstream_change:
            logger.error("Refusing to build: %s changed without a version change; review the diff, set a "
                         "distinguishing version, or rerun with --accept-upstream-change", ", ".join(changed))
            return 1
    verify_raw(RAW_DIR, lock)
    chunks, missing = build(RAW_DIR, lock, RUNBOOK_DIR)
    LOCK_PATH.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = write_outputs(chunks, missing, lock)
    for source in manifest["sources"]:
        logger.info("%s %s: %d chunks, missing %s", source["source_id"], source["version"],
                    source["chunk_count"], source["missing_items"] or "none")
    logger.info("kb_version %s (%d chunks)", manifest["kb_version"], manifest["chunk_count"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
