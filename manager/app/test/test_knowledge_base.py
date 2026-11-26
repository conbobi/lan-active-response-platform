"""Integrity, tamper detection, retrieval and build determinism of the local knowledge base.

The full real-data rebuild test needs the git-ignored raw downloads in knowledge/sources/raw/; without them it is
skipped with a visible reason (run scripts/sync_knowledge.py first). The committed chunks.jsonl is still checked
for known regressions by the tests that read it directly.
"""
import importlib.util
import logging
import json
import shutil
import sys
import threading
from pathlib import Path

import pytest

from app.services.ai.knowledge.contracts import KNOWLEDGE_CATEGORIES, KnowledgeChunk
from app.services.ai.knowledge.kb_store import MAX_LIMIT, KnowledgeBase, kb_version, query_terms

MANAGER_DIR = Path(__file__).resolve().parents[2]
KB_DIR = MANAGER_DIR / "knowledge"
SCRIPT = MANAGER_DIR / "scripts" / "sync_knowledge.py"
INJECTIONS = ['" OR 1=1 --', "NEAR(", "*", "title:x", "x" * 10_000, 'a" AND "b', "NOT", "(", ")", "^",
              "-", "kb MATCH 'x'; DROP TABLE kb; --", "\x00", "T1190*", "{title text}: x", ""]


def _load_script():
    spec = importlib.util.spec_from_file_location("sync_knowledge", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sync = _load_script()


@pytest.fixture(scope="module")
def kb():
    base = KnowledgeBase(KB_DIR)
    assert base.stats()["error"] is None
    return base


@pytest.fixture(scope="module")
def manifest():
    return json.loads((KB_DIR / "knowledge_manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def records():
    return [json.loads(line) for line in (KB_DIR / "chunks.jsonl").read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------------ integrity


def test_manifest_matches_chunks(manifest, records):
    lines = (KB_DIR / "chunks.jsonl").read_text(encoding="utf-8").splitlines()
    assert manifest["schema_version"] == 1
    assert manifest["kb_version"] == kb_version(lines) == sync.kb_version(lines)
    assert manifest["chunk_count"] == len(records)
    by_source = {s["source_id"]: s for s in manifest["sources"]}
    assert set(by_source) == {"mitre-attack", "owasp-sqli-prevention", "owasp-query-parameterization",
                              "owasp-os-command-injection", "nist-sp800-61r3", "larp-runbooks"}
    for source in manifest["sources"]:
        for field in ("title", "url", "version", "license", "retrieved_at", "raw_sha256"):
            assert source[field], (source["source_id"], field)
        assert isinstance(source["missing_items"], list)
        assert source["chunk_count"] == sum(r["source_id"] == source["source_id"] for r in records)
    assert by_source["nist-sp800-61r3"]["version"] == "SP 800-61 Rev. 3 (April 2025)"
    assert by_source["nist-sp800-61r3"]["url"] == "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
    assert by_source["owasp-sqli-prevention"]["version"].startswith("git:")
    assert "CC BY-SA 4.0" in by_source["owasp-sqli-prevention"]["license"]
    assert by_source["larp-runbooks"]["internal"] is True
    assert by_source["larp-runbooks"]["version"] == sync.runbook_version(KB_DIR / "runbooks")


def test_every_chunk_is_cited_and_well_formed(records):
    fields = list(KnowledgeChunk.__dataclass_fields__)
    ids = [r["chunk_id"] for r in records]
    assert len(ids) == len(set(ids))
    for record in records:
        assert list(record) == fields
        assert record["url"] and record["version"] and record["synced_at"] and record["title"]
        assert record["category"] in KNOWLEDGE_CATEGORIES
        assert 0 < len(record["text"]) <= 1200
        assert record["chunk_id"].startswith(record["source_id"] + ":")


def test_mitre_chunks_carry_their_technique(records):
    techniques = [r for r in records if r["source_id"] == "mitre-attack" and ":description:" in r["chunk_id"]]
    assert {r["chunk_id"].split(":")[1] for r in techniques} >= {"T1190", "T1110", "T1046", "T1059.004"}
    for record in techniques:
        tid = record["chunk_id"].split(":")[1]
        assert record["attack_ids"] == [tid]
        assert record["url"] == f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
        assert "(Citation:" not in record["text"] and "](http" not in record["text"]
    det = [r for r in records if r["chunk_id"].startswith("mitre-attack:DET0080:")]
    assert det and all(r["attack_ids"] == ["T1190"] for r in det)


def test_owasp_code_examples_are_verbatim(records):
    by_id = {r["chunk_id"]: r for r in records}
    cold_fusion = by_id["owasp-query-parameterization:using-cold-fusion-built-in-feature:0"]["text"]
    assert '<cfqueryparam value = #intCourseID# CFSQLType = "CF_SQL_INTEGER">' in cold_fusion
    assert "    SELECT * FROM" in cold_fusion
    assert "List<Inventory> list =" in by_id["owasp-query-parameterization:using-java-with-jpahibernate:0"]["text"]
    rust = by_id["owasp-query-parameterization:using-rust-with-sqlx:0"]["text"]
    assert "let users: Vec<User> =" in rust and "<!--" not in rust
    assert "keys-<username>/authorized_keys" in by_id["mitre-attack:T1098.004:description:0"]["text"]
    assert not any("<!--" in r["text"] for r in records)


def test_owasp_titles_carry_heading_path(records):
    titles = {r["chunk_id"]: r["title"] for r in records}
    oracle = titles["owasp-query-parameterization:normal-stored-procedure:0"]
    sql_server = titles["owasp-query-parameterization:normal-stored-procedure_1:0"]
    assert oracle != sql_server
    assert "Oracle using PL/SQL > Normal Stored Procedure" in oracle
    assert "SQL Server using Transact-SQL > Normal Stored Procedure" in sql_server


def test_command_injection_category_is_covered(kb, records):
    assert any(r["category"] == "command_injection" for r in records)
    results = kb.search("OS command injection defense web application", categories=["command_injection", "remediation"])
    assert results and results[0].source_id == "owasp-os-command-injection"


def test_runbook_mappings_take_names_from_stix(records):
    mappings = [r for r in records if r["chunk_id"].endswith(":attack-mapping:0") and r["source_id"] == "larp-runbooks"]
    auth = next(r["text"] for r in mappings if ":authentication-abuse:" in r["chunk_id"])
    assert "Technique names from MITRE ATT&CK v20.1: T1110 Brute Force" in auth
    body = auth.split("\n\n", 2)[2]
    for authored_name in ("password guessing", "password spraying", "credential stuffing", "Unix shell", "web shell"):
        assert all(authored_name not in r["text"].split("\n\n", 2)[2] for r in mappings), authored_name
    assert "T1110.003" in body


def test_upstream_change_under_same_version_is_reported(caplog):
    previous = {"sources": {"a": {"version": "v1", "raw_sha256": "old"}, "b": {"version": "v1", "raw_sha256": "x"}}}
    lock = {"sources": {"a": {"version": "v1", "raw_sha256": "new"}, "b": {"version": "v2", "raw_sha256": "y"},
                        "c": {"version": "v1", "raw_sha256": "z"}}}
    assert sync.upstream_changes(previous, lock) == ["a"]
    assert sync.upstream_changes(None, lock) == []
    assert any("changed upstream" in message for message in caplog.messages)


def test_runbooks_are_internal_and_complete(records):
    runbooks = [r for r in records if r["source_id"] == "larp-runbooks"]
    assert all(r["title"].startswith("[INTERNAL]") and r["url"].startswith("internal://") for r in runbooks)
    names = {r["chunk_id"].split(":")[1] for r in runbooks}
    assert len(names) >= 11
    for name in names:
        sections = {r["chunk_id"].split(":")[2] for r in runbooks if r["chunk_id"].split(":")[1] == name}
        assert sections == set(sync.RUNBOOK_SECTIONS), name


# ------------------------------------------------------------------ tamper detection


def _copy_kb(tmp_path):
    for name in ("knowledge_manifest.json", "chunks.jsonl"):
        shutil.copy(KB_DIR / name, tmp_path / name)
    return tmp_path


def test_tampered_chunks_serve_empty_kb(tmp_path, caplog):
    directory = _copy_kb(tmp_path)
    path = directory / "chunks.jsonl"
    path.write_text(path.read_text(encoding="utf-8").replace("Adversaries", "Defenders", 1), encoding="utf-8")
    base = KnowledgeBase(directory)
    assert base.search("brute force") == [] and base.by_attack_id("T1190") == []
    assert base.version == "" and base.stats()["chunk_count"] == 0 and base.stats()["error"]
    assert any("rejected" in message for message in caplog.messages)


def test_invalid_chunk_with_matching_hash_is_never_partial(tmp_path):
    directory = _copy_kb(tmp_path)
    lines = (directory / "chunks.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["category"] = "not_a_category"
    lines[0] = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    (directory / "chunks.jsonl").write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    manifest = json.loads((directory / "knowledge_manifest.json").read_text(encoding="utf-8"))
    manifest["kb_version"] = kb_version(lines)
    (directory / "knowledge_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    base = KnowledgeBase(directory)
    assert base.stats()["chunk_count"] == 0 and base.search("sql injection") == []


def test_missing_files_serve_empty_kb(tmp_path):
    base = KnowledgeBase(tmp_path)
    assert base.search("sql injection") == [] and base.get("x") is None and base.stats()["error"]


# ------------------------------------------------------------------ retrieval


def test_parameterized_queries_finds_owasp(kb):
    results = kb.search("parameterized queries prepared statements")
    assert results and all(r.source_id.startswith("owasp-") for r in results[:2])
    assert any("parameteriz" in r.chunk_id for r in results)


def test_by_attack_id_t1190(kb):
    results = kb.by_attack_id("t1190")
    assert results and results[0].chunk_id == "mitre-attack:T1190:description:0"
    assert results[0].title == "Exploit Public-Facing Application"
    assert all("T1190" in r.attack_ids for r in results) and len(results) <= MAX_LIMIT
    assert kb.by_attack_id("T9999") == [] and kb.by_attack_id("' OR 1") == []


def test_brute_force_maps_to_t1110(kb):
    results = kb.search("brute force password guessing")
    assert any(tid.startswith("T1110") for r in results for tid in r.attack_ids)


def test_get_returns_chunk(kb):
    chunk = kb.get("mitre-attack:T1190:description:0")
    assert chunk is not None and chunk.citation()["url"].startswith("https://attack.mitre.org/")
    assert kb.get("missing") is None and kb.get(None) is None


@pytest.mark.parametrize("query", INJECTIONS)
def test_fts_injection_strings_do_not_raise(kb, query, caplog):
    caplog.set_level(logging.WARNING, logger="app.services.ai.knowledge.kb_store")
    results = kb.search(query, limit=50)
    assert isinstance(results, list) and len(results) <= MAX_LIMIT
    # search() swallows sqlite errors; a logged failure means the MATCH expression was malformed.
    assert not [r for r in caplog.records if "Knowledge search failed" in r.getMessage()]


def test_broken_match_expression_is_detected(kb, caplog, monkeypatch):
    """Guard for the test above: a malformed FTS expression does log the failure it looks for."""
    from app.services.ai.knowledge import kb_store

    monkeypatch.setattr(kb_store, "query_terms", lambda _query: ['"', "NEAR("])
    assert kb.search("x") == []
    assert any("Knowledge search failed" in r.getMessage() for r in caplog.records)


def test_query_terms_strip_operators():
    assert query_terms('" OR 1=1 --') == []
    assert query_terms("NEAR(title:x) AND *") == ["title"]
    assert len(query_terms("word " * 1000)) == 1
    assert len(query_terms(" ".join(f"w{i}" for i in range(100)))) == 16
    assert query_terms(None) == []


def test_category_and_attack_filters(kb):
    sql = kb.search("injection detection response", categories=["sql_injection"], limit=8)
    assert sql and all(r.category == "sql_injection" for r in sql)
    spray = kb.search("password", attack_ids=["t1110.003"])
    assert spray and all("T1110.003" in r.attack_ids for r in spray)
    assert kb.search("password", categories=["no_such_category"]) == []
    assert len(kb.search("the attack", limit=100)) <= MAX_LIMIT
    assert len(kb.search("attack", limit="9")) == 4


def test_lazy_threadsafe_loading():
    base = KnowledgeBase(KB_DIR)
    results, errors = [], []

    def worker():
        try:
            results.append(tuple(c.chunk_id for c in base.search("lateral movement ssh")))
        except Exception as error:  # pragma: no cover - reported below
            errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors and len(set(results)) == 1 and results[0]


# ------------------------------------------------------------------ normalizer


def test_clean_markup_and_split():
    text = "Use [prepared statements](https://example.org/a_(b)) here.(Citation: Foo 2020) <code>x</code>"
    assert sync.clean_markup(text) == "Use prepared statements here. x"
    assert sync.clean_markup("<!-- note -->\nkeys-<username>/authorized_keys &lt;home&gt;") == \
        "keys-<username>/authorized_keys <home>"
    code = "Intro <b>x</b>\n\n```cf\n<cfquery>\n    a  =  [b](c) <!-- k -->\n</cfquery>\n```\nafter"
    assert sync.clean_markup(code) == \
        "Intro x\n\n```cf\n<cfquery>\n    a  =  [b](c) <!-- k -->\n</cfquery>\n```\nafter"
    pieces = sync.split_text("word " * 1000)
    assert all(len(p) <= 1200 for p in pieces) and len(pieces) > 1


FIXTURE_BUNDLE = {"type": "bundle", "objects": [
    {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Initial Access", "x_mitre_shortname": "initial-access"},
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Fixture Technique", "modified": "2025-01-01",
     "description": "Fixture text for the normalizer test.(Citation: Fixture) See [link](https://example.org).",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
     "x_mitre_platforms": ["Linux"],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1190",
                              "url": "https://attack.mitre.org/techniques/T1190"}]},
    {"type": "x-mitre-analytic", "id": "x-mitre-analytic--1", "description": "Fixture analytic.",
     "x_mitre_platforms": ["Linux"], "external_references": [
         {"source_name": "mitre-attack", "external_id": "AN0001", "url": "https://attack.mitre.org/detectionstrategies/DET0080#AN0001"}]},
    {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--1", "name": "Fixture strategy",
     "x_mitre_analytic_refs": ["x-mitre-analytic--1"], "external_references": [
         {"source_name": "mitre-attack", "external_id": "DET0080", "url": "https://attack.mitre.org/detectionstrategies/DET0080"}]},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "detects",
     "source_ref": "x-mitre-detection-strategy--1", "target_ref": "attack-pattern--1"},
]}
FIXTURE_MD = "# Fixture Sheet\n\n## Intro\n\nText [a](b).\n\n```\n## not a heading\n```\n\n## References\n\n- x\n"
FIXTURE_NIST = "\n".join([
    "2.1. Incident Response Life Cycle Model", "Fixture prose line one", "continues here.",
    "2.2. Roles", "3.1. Preparation and Lessons Learned",
    " CSF Element       CSF Element Description      Priority   Recommendations, Considerations, Notes",
    " ID.IM-01          Fixture improvement          High       R1: Fixture recommendation",
    "3.2. Incident Response",
    " CSF Element       CSF Element Description      Priority   Recommendations, Considerations, Notes",
    " RS.MI-01          Fixture containment          High       N1: Fixture note",
    "                                                           continues. R1: Next item.",
    "References", ""])


def _fixture_inputs(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "bundle.json").write_text(json.dumps(FIXTURE_BUNDLE), encoding="utf-8")
    (raw / "sheet.md").write_text(FIXTURE_MD, encoding="utf-8")
    (raw / "nist.txt").write_text(FIXTURE_NIST, encoding="utf-8")
    common = {"version": "fixture", "retrieved_at": "2000-01-01"}
    lock = {"sources": {
        "mitre-attack": {**common, "raw_file": "bundle.json"},
        "owasp-sqli-prevention": {**common, "raw_file": "sheet.md", "url": "https://example.org/a.html"},
        "owasp-query-parameterization": {**common, "raw_file": "sheet.md", "url": "https://example.org/b.html"},
        "owasp-os-command-injection": {**common, "raw_file": "sheet.md", "url": "https://example.org/c.html"},
        "nist-sp800-61r3": {**common, "text_file": "nist.txt"},
        "larp-runbooks": {**common},
    }}
    return raw, lock


def test_build_is_deterministic_on_fixtures(tmp_path):
    raw, lock = _fixture_inputs(tmp_path)
    first, missing = sync.build(raw, lock, KB_DIR / "runbooks")
    second, _ = sync.build(raw, lock, KB_DIR / "runbooks")
    assert sync.serialize(first) == sync.serialize(second)
    ids = {c.chunk_id for c in first}
    assert {"mitre-attack:T1190:description:0", "mitre-attack:DET0080:AN0001:0",
            "owasp-sqli-prevention:intro:0", "nist-sp800-61r3:rs-mi-01:0"} <= ids
    assert not any("references" in i for i in ids)
    assert "T1046" in missing["mitre-attack"]
    rs = next(c for c in first if c.chunk_id == "nist-sp800-61r3:rs-mi-01:0")
    assert "N1: Fixture note continues." in rs.text and "R1: Next item." in rs.text
    technique = next(c for c in first if c.chunk_id == "mitre-attack:T1190:description:0")
    assert "(Citation" not in technique.text and "See link." in technique.text


def test_build_from_raw_downloads_reproduces_committed_chunks():
    lock = json.loads((KB_DIR / "sources" / "sources.lock.json").read_text(encoding="utf-8"))
    raw = KB_DIR / "sources" / "raw"
    if not all((raw / name).exists() for meta in lock["sources"].values() for name in meta.get("files", {})):
        pytest.skip("requires raw downloads in knowledge/sources/raw/ (git-ignored); run scripts/sync_knowledge.py")
    sync.verify_raw(raw, lock)
    chunks, _ = sync.build(raw, lock, KB_DIR / "runbooks")
    committed = (KB_DIR / "chunks.jsonl").read_text(encoding="utf-8")
    assert "".join(f"{line}\n" for line in sync.serialize(chunks)) == committed
