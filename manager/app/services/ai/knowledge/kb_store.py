"""Read-only local security knowledge base with an in-memory SQLite FTS5 index.

Chunks come from ``knowledge/chunks.jsonl`` (built by ``scripts/sync_knowledge.py``) and are verified
against ``knowledge_manifest.json`` before use. Knowledge is reference material, never incident evidence:
retrieval returns a few small cited excerpts, never the whole knowledge base.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path

from app.services.ai.knowledge.contracts import KNOWLEDGE_CATEGORIES, KnowledgeChunk

logger = logging.getLogger(__name__)

# app/services/ai/knowledge/kb_store.py -> manager/ (mounted at /app in the container)
MANAGER_DIR = Path(__file__).resolve().parents[4]
DEFAULT_DIR = MANAGER_DIR / "knowledge"
MANIFEST_FILE = "knowledge_manifest.json"
CHUNKS_FILE = "chunks.jsonl"

DEFAULT_LIMIT = 4
MAX_LIMIT = 8
MAX_TEXT_CHARS = 1200
MAX_QUERY_CHARS = 512
MAX_TERMS = 16
MAX_TERM_CHARS = 64
MIN_TERM_CHARS = 2
FTS_OPERATORS = {"and", "or", "not", "near"}
TERM = re.compile(r"\w+", re.UNICODE)
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
FIELDS = tuple(KnowledgeChunk.__dataclass_fields__)


def kb_version(lines: Iterable[str]) -> str:
    """sha256 over the sorted chunks.jsonl lines, each terminated by a newline (same as the sync script)."""
    return hashlib.sha256("".join(f"{line}\n" for line in sorted(lines)).encode("utf-8")).hexdigest()


def query_terms(query: object) -> list[str]:
    """Reduce untrusted text to plain, de-duplicated word terms; FTS syntax never survives."""
    if not isinstance(query, str):
        return []
    if len(query) > MAX_QUERY_CHARS:  # cap length without keeping a truncated trailing word
        query = re.sub(r"\S*\Z", "", query[:MAX_QUERY_CHARS + 1])
    terms: list[str] = []
    for term in TERM.findall(query.lower()):
        term = term.strip("_")[:MAX_TERM_CHARS]
        if len(term) >= MIN_TERM_CHARS and term not in FTS_OPERATORS and term not in terms:
            terms.append(term)
        if len(terms) >= MAX_TERMS:
            break
    return terms


def _clamp_limit(limit: object) -> int:
    if type(limit) is not int:
        return DEFAULT_LIMIT
    return max(1, min(MAX_LIMIT, limit))


def _parse_chunk(line: str) -> KnowledgeChunk:
    record = json.loads(line)
    if not isinstance(record, dict) or tuple(record) != FIELDS:
        raise ValueError("chunk fields do not match KnowledgeChunk")
    attack_ids = record["attack_ids"]
    if not isinstance(attack_ids, list) or not all(isinstance(t, str) and TECHNIQUE_ID.match(t) for t in attack_ids):
        raise ValueError(f"invalid attack_ids in {record.get('chunk_id')!r}")
    if not all(isinstance(record[name], str) and record[name] for name in FIELDS if name != "attack_ids"):
        raise ValueError(f"empty or non-string field in {record.get('chunk_id')!r}")
    if record["category"] not in KNOWLEDGE_CATEGORIES or len(record["text"]) > MAX_TEXT_CHARS:
        raise ValueError(f"invalid category or oversized text in {record['chunk_id']!r}")
    return KnowledgeChunk(**{**record, "attack_ids": tuple(attack_ids)})


class KnowledgeBase:
    """Lazy, thread-safe access to verified knowledge chunks."""

    def __init__(self, directory: str | Path | None = None):
        self._dir = Path(directory) if directory else DEFAULT_DIR
        self._lock = threading.RLock()
        self._loaded = False
        self._version = ""
        self._error: str | None = None
        self._chunks: dict[str, KnowledgeChunk] = {}
        self._by_attack: dict[str, list[str]] = {}
        self._db: sqlite3.Connection | None = None

    # ------------------------------------------------------------ loading

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if not self._loaded:
                self._load()
                self._loaded = True

    def _load(self) -> None:
        try:
            manifest = json.loads((self._dir / MANIFEST_FILE).read_text(encoding="utf-8"))
            lines = [line for line in (self._dir / CHUNKS_FILE).read_text(encoding="utf-8").split("\n") if line]
            expected = manifest.get("kb_version") if isinstance(manifest, dict) else None
            if not isinstance(expected, str) or kb_version(lines) != expected:
                raise ValueError("kb_version does not match chunks.jsonl")
            chunks = [_parse_chunk(line) for line in lines]
            if len({c.chunk_id for c in chunks}) != len(chunks):
                raise ValueError("duplicate chunk_id")
            db = self._build_index(chunks)
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
            self._error = f"{type(error).__name__}: {error}"
            logger.error("Knowledge base at %s rejected, serving an empty KB: %s", self._dir, self._error)
            return
        self._db = db
        self._version = expected
        self._chunks = {c.chunk_id: c for c in chunks}
        for chunk in chunks:
            for tid in chunk.attack_ids:
                self._by_attack.setdefault(tid, []).append(chunk.chunk_id)
        logger.info("Loaded knowledge base %s (%d chunks)", expected[:12], len(chunks))

    @staticmethod
    def _build_index(chunks: list[KnowledgeChunk]) -> sqlite3.Connection:
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE VIRTUAL TABLE kb USING fts5(chunk_id UNINDEXED, title, text, attack_ids, "
                   "tokenize='porter unicode61')")
        db.executemany("INSERT INTO kb VALUES (?,?,?,?)",
                       [(c.chunk_id, c.title, c.text, " ".join(c.attack_ids)) for c in chunks])
        return db

    # ------------------------------------------------------------ public API

    @property
    def version(self) -> str:
        self._ensure_loaded()
        return self._version

    def get(self, chunk_id: str) -> KnowledgeChunk | None:
        self._ensure_loaded()
        return self._chunks.get(chunk_id) if isinstance(chunk_id, str) else None

    def by_attack_id(self, tid: str) -> list[KnowledgeChunk]:
        self._ensure_loaded()
        if not isinstance(tid, str) or not TECHNIQUE_ID.match(tid.strip().upper()):
            return []
        ids = self._by_attack.get(tid.strip().upper(), [])
        # Prefer the authoritative technique description over strategies and internal runbooks.
        ranked = sorted(ids, key=lambda cid: (self._chunks[cid].source_id != "mitre-attack",
                                              ":description:" not in cid))
        return [self._chunks[cid] for cid in ranked[:MAX_LIMIT]]

    def search(self, query: str, *, categories: Iterable[str] | None = None,
               attack_ids: Iterable[str] | None = None, limit: int = DEFAULT_LIMIT) -> list[KnowledgeChunk]:
        self._ensure_loaded()
        terms = query_terms(query)
        limit = _clamp_limit(limit)
        if self._db is None or not terms:
            return []
        wanted_categories = self._filter_set(categories)
        ids = self._filter_set(attack_ids)
        wanted_ids = None if ids is None else {t.strip().upper() for t in ids}
        match = " OR ".join(f'"{term}"' for term in terms)
        try:
            with self._lock:
                rows = self._db.execute("SELECT chunk_id FROM kb WHERE kb MATCH ? "
                                        "ORDER BY bm25(kb, 0.0, 1.0, 1.0, 2.0), chunk_id", (match,)).fetchall()
        except sqlite3.Error as error:
            logger.warning("Knowledge search failed: %s", error)
            return []
        results: list[KnowledgeChunk] = []
        for (chunk_id,) in rows:
            chunk = self._chunks[chunk_id]
            if wanted_categories is not None and chunk.category not in wanted_categories:
                continue
            if wanted_ids is not None and not wanted_ids.intersection(chunk.attack_ids):
                continue
            results.append(chunk)
            if len(results) >= limit:
                break
        return results

    def stats(self) -> dict:
        self._ensure_loaded()
        sources: dict[str, int] = {}
        categories: dict[str, int] = {}
        for chunk in self._chunks.values():
            sources[chunk.source_id] = sources.get(chunk.source_id, 0) + 1
            categories[chunk.category] = categories.get(chunk.category, 0) + 1
        return {"version": self._version, "loaded": self._db is not None, "chunk_count": len(self._chunks),
                "sources": dict(sorted(sources.items())), "categories": dict(sorted(categories.items())),
                "attack_ids": len(self._by_attack), "error": self._error, "directory": str(self._dir)}

    @staticmethod
    def _filter_set(values: Iterable[str] | None) -> set[str] | None:
        if values is None:
            return None
        if isinstance(values, str):
            values = (values,)
        return {v for v in values if isinstance(v, str)}


knowledge_base = KnowledgeBase()
