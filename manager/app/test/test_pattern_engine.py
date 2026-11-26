"""Evidence-to-knowledge ladders, post-exploitation correlation and response playbooks."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models.agent import Agent
from app.models.auth_event import AuthEvent
from app.models.base import Base
from app.models.event import Event
from app.models.flow import Flow
from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.web_access_log import WebAccessLog
from app.services.ai.knowledge import pattern_engine as pe
from app.services.ai.knowledge.contracts import KnowledgeChunk
from app.services.detection.behavior_evidence import stable_id
from app.services.response import http_investigation, lab_waf

T0 = datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc)
AGENT, OTHER = "agent-web", "agent-other"
PEER = "100.67.222.3"
FLASK_START = T0.timestamp() - 3600 + 0.25   # psutil create_time: epoch seconds
SHELL_START = T0.timestamp() + 30
FLASK_CMD = "/usr/bin/python3 /opt/larp-agent/vulnerable_web/app.py"


def chunk(chunk_id, category, title, attack_ids=()):
    return KnowledgeChunk(chunk_id=chunk_id, source_id=chunk_id.split(":")[0], title=title, category=category,
                          text="excerpt", url="https://example.invalid/" + chunk_id, version="test",
                          synced_at="2026-11-01", attack_ids=tuple(attack_ids))


class FakeKB:
    version = "test-kb"

    def __init__(self):
        self.chunks = [
            chunk("owasp-sqli:defense:0", "sql_injection", "Defense Option 1"),
            chunk("attack:T1190:0", "sql_injection", "Exploit Public-Facing Application", ("T1190",)),
            chunk("attack:T1110:0", "authentication_abuse", "Brute Force", ("T1110",)),
            chunk("attack:T1046:0", "network_scanning", "Network Service Discovery", ("T1046",)),
            chunk("attack:T1059.004:0", "reverse_shell", "Unix Shell", ("T1059.004",)),
        ]
        self.queries = []

    def search(self, query, *, categories=None, attack_ids=None, limit=4):
        self.queries.append((query, categories, attack_ids))
        return [c for c in self.chunks if (not categories or c.category in categories)
                and (not attack_ids or set(attack_ids) & set(c.attack_ids))][:limit]

    def get(self, chunk_id):
        return next((c for c in self.chunks if c.chunk_id == chunk_id), None)

    def by_attack_id(self, tid):
        return [c for c in self.chunks if tid in c.attack_ids]


@pytest.fixture
def kb():
    return FakeKB()


# ----------------------------------------------------------------- investigate()-shaped fixtures


def http_fact(row_id, *, hint=None, indicators=(), status=200, at=T0, ip=PEER, method="POST"):
    return {"evidence_ids": [row_id], "provenance": "web_access_logs", "observed_at": at.isoformat(),
            "method": method, "http_status": status, "source_ip": ip, "automation_hint": hint,
            "payload_indicators": sorted(indicators)}


def grant_fact(row_id, auth_id, *, at=T0, ip=PEER):
    return {"evidence_ids": [row_id, auth_id], "provenance": "auth_events + web_access_logs",
            "observed_at": (at + timedelta(seconds=1)).isoformat(), "source_ip": ip, "outcome": "session_granted"}


def mismatch_fact(request_id, auth_id, row_id, *, at=T0, ip=PEER):
    return {"evidence_ids": [request_id, auth_id, row_id], "provenance": "lab grant_observation",
            "observed_at": at.isoformat(), "source_ip": ip, "outcome": "credential_mismatch_grant"}


def investigation(classification, facts):
    probe = classification in {"sqli_probe_observed", "sqli_exploitation_suspected", "sqli_exploitation_confirmed"}
    return {
        "asset_criticality": None, "recent_outcomes": [], "classification": classification, "observed_facts": facts,
        "behavioral_interpretation": "test", "attack_hypotheses": ["Possible application probing"],
        "evidence_completeness": "partial", "confidence": 0.6, "confidence_source": "detection rule",
        "risk_score": 55.0, "potential_impact": "Application impact undetermined.",
        "mitre_techniques": ["T1190"] if probe else [],
        "missing_evidence": ["Verified application-side credential mismatch"],
        "recommended_investigation": ["Correlate request, authentication and endpoint observations."],
        "recommended_responses": [],
    }


UA_ONLY = investigation("sqli_tool_indicator", [http_fact("wlog_1", hint="sqlmap")])
PROBE = investigation("sqli_probe_observed", [http_fact("wlog_1", hint="sqlmap", indicators=["sql_boolean_expression"])])
SUSPECTED = investigation("sqli_exploitation_suspected", [
    http_fact("wlog_1", indicators=["sql_boolean_expression"], status=302), grant_fact("wlog_1", "auth_1")])
CONFIRMED = investigation("sqli_exploitation_confirmed", [
    http_fact("wlog_1", indicators=["sql_boolean_expression"], status=302), grant_fact("wlog_1", "auth_1"),
    mismatch_fact("req_1234567890abcdef", "auth_1", "wlog_1")])


def techniques(result):
    return [m.technique_id for m in result.attack_mapping]


# ----------------------------------------------------------------- SQLi ladder


def test_user_agent_only_is_tool_indicator_without_attack_mapping(kb):
    result = pe.assess(UA_ONLY, kb=kb)
    assert (result.pattern_id, result.level, result.level_name) == ("sqli", 1, "tool_indicator")
    assert result.attack_mapping == ()
    assert "chưa được xác nhận" in result.conclusion
    assert result.evidence_refs == ("wlog_1",)
    assert result.playbook_id == "sqli_tool_indicator"
    assert all("[evidence: wlog_1]" in fact for fact in result.confirmed_facts)


def test_payload_is_probing_with_t1190_and_refs(kb):
    result = pe.assess(PROBE, kb=kb)
    assert (result.level, result.level_name) == (2, "probing")
    [mapping] = result.attack_mapping
    assert mapping.technique_id == "T1190" and mapping.evidence_refs == ("wlog_1",)
    assert mapping.name == "Exploit Public-Facing Application"
    assert mapping.knowledge_refs == ("attack:T1190:0",)
    assert "owasp-sqli:defense:0" in result.knowledge_refs
    assert set(result.knowledge_refs).isdisjoint(result.evidence_refs)


def test_evidence_refs_cite_only_discriminating_rows(kb):
    data = investigation("sqli_probe_observed", [
        http_fact("wlog_1", indicators=["sql_boolean_expression"]), http_fact("wlog_benign", method="GET")])
    result = pe.assess(data, kb=kb)
    assert result.level == 2 and result.evidence_refs == ("wlog_1",)


def test_get_with_tool_user_agent_does_not_claim_login_path(kb):
    assert "/login" not in pe.assess(UA_ONLY, kb=kb).conclusion
    get_only = investigation("sqli_tool_indicator", [http_fact("wlog_1", hint="sqlmap", method="GET")])
    assert pe.assess(get_only, kb=kb).level == 0


def test_session_grant_is_exploitation_suspected(kb):
    result = pe.assess(SUSPECTED, kb=kb)
    assert (result.level, result.level_name) == (3, "exploitation_suspected")
    assert result.attack_mapping[0].evidence_refs == ("wlog_1", "auth_1")
    assert result.playbook_id == "sqli_exploitation_suspected"


def test_credential_mismatch_grant_is_exploitation_confirmed(kb):
    result = pe.assess(CONFIRMED, kb=kb)
    assert (result.level, result.level_name) == (4, "exploitation_confirmed")
    assert set(result.attack_mapping[0].evidence_refs) == {"wlog_1", "auth_1", "req_1234567890abcdef"}
    assert any("không khớp" in fact and "req_1234567890abcdef" in fact for fact in result.confirmed_facts)


@pytest.mark.parametrize("classification", [
    "sqli_tool_indicator", "sqli_probe_observed", "sqli_exploitation_suspected", "sqli_exploitation_confirmed"])
def test_http_200_alone_never_above_level_one(kb, classification):
    result = pe.assess(investigation(classification, [http_fact("wlog_1", status=200)]), kb=kb)
    assert result.level == 0
    result = pe.assess(investigation(classification, [http_fact("wlog_1", hint="sqlmap", status=200)]), kb=kb)
    assert result.level <= 1 and result.attack_mapping == ()


def test_grant_without_matching_request_identity_or_time_is_not_suspected(kb):
    other_row = investigation("sqli_exploitation_suspected", [
        http_fact("wlog_1", indicators=["sql_boolean_expression"]), grant_fact("wlog_9", "auth_1")])
    late = investigation("sqli_exploitation_suspected", [
        http_fact("wlog_1", indicators=["sql_boolean_expression"]),
        grant_fact("wlog_1", "auth_1", at=T0 + timedelta(minutes=5))])
    assert pe.assess(other_row, kb=kb).level == 2
    assert pe.assess(late, kb=kb).level == 2


def test_mismatch_without_grant_is_not_confirmed(kb):
    data = investigation("sqli_exploitation_confirmed", [
        http_fact("wlog_1", indicators=["sql_boolean_expression"]), mismatch_fact("req_x", "auth_1", "wlog_1")])
    assert pe.assess(data, kb=kb).level == 2


@pytest.mark.parametrize("data", [UA_ONLY, PROBE, SUSPECTED, CONFIRMED])
def test_sqli_never_maps_brute_force_or_proxy_execution(kb, data):
    result = pe.assess(data, kb=kb)
    assert not {"T1110", "T1218"} & set(techniques(result))
    sqli = pe.catalog()[0]["sqli"]
    assert {"T1110", "T1218"} <= sqli["forbidden"]
    assert not any(tid in {"T1110", "T1218"} for level in sqli["levels"] for tid, _ in level["attack"])


def test_sqli_ban_holds_even_if_yaml_ban_is_missing(kb):
    """Code-level invariant: a pattern with category sql_injection never emits T1110/T1218."""
    sqli = dict(pe.catalog()[0]["sqli"], forbidden=frozenset())
    level = dict(sqli["levels"][0], attack=(("T1110", ("sqli_tool_user_agent",)), ("T1218", ("sqli_tool_user_agent",))))
    sqli["levels"] = (level,)
    result = pe.assess(UA_ONLY, kb=kb, patterns={"sqli": sqli})
    assert result.level == 1 and result.attack_mapping == ()


def test_correlated_tool_requests_reach_probing_but_t1190_without_payload_is_dropped(kb):
    facts = [http_fact(f"wlog_{i}", hint="sqlmap", at=T0 + timedelta(seconds=i)) for i in range(3)]
    result = pe.assess(investigation("sqli_tool_indicator", facts), kb=kb)
    assert result.level == 2
    assert result.attack_mapping == ()


def test_mapping_without_refs_is_dropped(kb):
    refs = {"sql_payload_indicators": (), "session_grant_correlated": ("wlog_1",)}
    assert pe.attack_mappings([("T1190", ("sql_payload_indicators",))], refs, kb) == ()
    assert pe.attack_mappings([("T1190", ("sql_payload_indicators", "session_grant_correlated"))], refs, kb) == ()
    kept = pe.attack_mappings([("T1190", ("session_grant_correlated",))], refs, kb)
    assert kept[0].evidence_refs == ("wlog_1",)
    assert pe.attack_mappings([("T1110", ("session_grant_correlated",))], refs, kb, forbidden={"T1110"}) == ()


def test_kb_unavailable_degrades_to_no_knowledge_refs(monkeypatch):
    monkeypatch.setattr(pe, "_default_kb", lambda: None)
    result = pe.assess(PROBE)
    assert result.level == 2 and result.knowledge_refs == ()
    assert result.attack_mapping[0].name == "T1190" and result.attack_mapping[0].knowledge_refs == ()


def test_failing_kb_search_is_ignored():
    class Broken(FakeKB):
        def search(self, *args, **kwargs):
            raise RuntimeError("index missing")
    result = pe.assess(PROBE, kb=Broken())
    assert result.knowledge_refs == () and techniques(result) == ["T1190"]


def test_assessment_is_deterministic_and_serializable(kb):
    first, second = pe.to_dict(pe.assess(CONFIRMED, kb=kb)), pe.to_dict(pe.assess(CONFIRMED, kb=FakeKB()))
    assert first == second
    assert json.loads(json.dumps(first)) == first
    assert isinstance(first["attack_mapping"][0]["evidence_refs"], list)


def test_automated_http_activity_has_no_technique(kb):
    data = investigation("automated_http_activity", [http_fact("wlog_1", hint="curl", method="GET")])
    result = pe.assess(data, kb=kb)
    assert (result.pattern_id, result.level) == ("automated_http_activity", 1)
    assert result.attack_mapping == ()


# ----------------------------------------------------------------- authentication, scanning, reverse shell


def auth_behavior(classification, *, criteria=None, failed=12, success=0, source_ip=PEER, username="alice"):
    data = {"evidence_id": "auth_group_1", "evidence_type": "authentication", "source": "auth_events",
            "source_event_ids": ["auth_a", "auth_b"], "agent_id": AGENT, "classification": classification,
            "service": "ssh", "source_ip": source_ip, "username": username,
            "failed_attempts": failed, "successful_attempts": success}
    if criteria:
        data["brute_force_criteria"] = criteria
    return data


def test_auth_ladder(kb):
    repeated = pe.assess(auth_behavior("repeated_auth_failures"), kb=kb)
    assert (repeated.level_name, repeated.attack_mapping) == ("repeated_auth_failures", ())
    no_criteria = pe.assess(auth_behavior("authentication_brute_force"), kb=kb)
    assert no_criteria.level == 1 and no_criteria.attack_mapping == ()
    brute = pe.assess(auth_behavior("authentication_brute_force", criteria="password_burst_same_account_source"), kb=kb)
    assert brute.level_name == "authentication_brute_force"
    assert techniques(brute) == ["T1110"]
    assert brute.attack_mapping[0].evidence_refs == ("auth_group_1", "auth_a", "auth_b")
    success = pe.assess({"behavior": auth_behavior(
        "authentication_brute_force", criteria="password_burst_same_account_source", success=1)}, kb=kb)
    assert (success.level_name, techniques(success)) == ("brute_force_success", ["T1110"])
    assert "cùng nguồn" not in success.conclusion and "chưa xác minh" in success.conclusion


def test_success_in_distributed_group_is_not_brute_force_success(kb):
    distributed = pe.assess(auth_behavior("authentication_brute_force", criteria="distributed_password_burst_same_account",
                                          success=1, source_ip=None, username="alice"), kb=kb)
    assert (distributed.level_name, techniques(distributed)) == ("authentication_brute_force", ["T1110"])


def scan_behavior(ports):
    return {"evidence_id": "scan_1", "evidence_type": "network", "source": "flows",
            "source_event_ids": [f"flow_{p}" for p in ports], "agent_id": AGENT,
            "classification": "network_service_scanning", "protocol": "TCP", "direction": "inbound",
            "source_ip": PEER, "destination_ports": list(ports)}


def test_network_scanning_ladder(kb):
    few = pe.assess(scan_behavior(range(20, 25)), kb=kb)
    assert (few.level, few.attack_mapping) == (1, ())
    many = pe.assess(scan_behavior(range(20, 30)), kb=kb)
    assert (many.level_name, techniques(many)) == ("service_scanning", ["T1046"])
    assert many.attack_mapping[0].evidence_refs[0] == "scan_1"


def shell_evidence(*, stdio=(0, 1, 2), fds=(0, 1, 2), classification="High-Confidence Reverse Shell",
                   ancestry=None, shell_start=SHELL_START):
    ancestry = ancestry if ancestry is not None else [
        {"pid": 4100, "parent_pid": 1, "process_start_time": FLASK_START, "exe_path": "/usr/bin/python3.12",
         "name": "python3", "cmdline": FLASK_CMD}]
    return {
        "rule_id": "builtin_linux_network_shell", "classification": classification, "entity": "ent_shell",
        "process": {"pid": 4242, "parent_pid": ancestry[0]["pid"] if ancestry else 4100, "process_start_time": shell_start, "exe_path": "/usr/bin/bash",
                    "name": "bash", "stdio_fds": list(stdio), "socket_fds": list(fds)},
        "ancestry": ancestry,
        "network": {"inode": "998877", "socket_id": "sock_1", "attribution": "inode_verified", "direction": "outbound",
                    "dst_ip": "203.0.113.9", "dst_port": 4444, "observed_at": (T0 + timedelta(seconds=30)).isoformat()},
    }


def test_reverse_shell_ladder(kb):
    confirmed = pe.assess({"incident_id": "inc_shell", **shell_evidence()}, kb=kb)
    assert (confirmed.pattern_id, confirmed.level_name) == ("reverse_shell", "reverse_shell_confirmed")
    assert techniques(confirmed) == ["T1059.004"]
    assert confirmed.attack_mapping[0].evidence_refs == ("inc_shell", "ent_shell", "sock_1")
    unlinked = pe.assess(shell_evidence(stdio=(), classification="Suspected Reverse Shell"), kb=kb)
    assert (unlinked.level_name, unlinked.attack_mapping) == ("suspicious_shell_socket", ())


def test_command_injection_requires_verified_web_ancestry(kb):
    verified = {"kind": "shell_with_network_socket", "correlation": "verified", "spawned_by_web_server": True,
                "evidence_refs": ["inc_shell", "pinfo_flask"], "reason": "ok"}
    result = pe.assess({}, host_evidence=[verified], kb=kb)
    assert (result.pattern_id, result.level_name, techniques(result)) == (
        "web_command_injection", "web_server_spawned_shell", ["T1059"])
    unverified = {**verified, "correlation": "unverified", "spawned_by_web_server": False}
    result = pe.assess({}, host_evidence=[unverified], kb=kb)
    assert (result.level_name, result.attack_mapping) == ("related_host_activity", ())


def test_sqli_conclusion_only_absorbs_verified_host_evidence(kb):
    unverified = {"kind": "shell_with_network_socket", "correlation": "unverified", "spawned_by_web_server": False,
                  "evidence_refs": ["inc_shell"], "reason": "PID reuse"}
    result = pe.assess(PROBE, host_evidence=[unverified], kb=kb)
    assert result.post_exploitation[0]["status"] == "related, not correlated"
    assert not any("inc_shell" in fact for fact in result.confirmed_facts)
    assert techniques(result) == ["T1190"]
    verified = {**unverified, "correlation": "verified", "spawned_by_web_server": True, "reason": "ancestry"}
    result = pe.assess(PROBE, host_evidence=[verified], kb=kb)
    assert result.post_exploitation[0]["status"] == "correlated"
    assert result.post_exploitation[0]["assessment"]["attack_mapping"][0]["technique_id"] == "T1059"
    assert any("inc_shell" in fact for fact in result.confirmed_facts)
    assert techniques(result) == ["T1190"]
    flow = {"kind": "outbound_connection", "correlation": "verified", "evidence_refs": ["flow_out", "inc_shell"],
            "reason": "socket held"}
    result = pe.assess(PROBE, host_evidence=[verified, flow], kb=kb)
    assert [item["status"] for item in result.post_exploitation] == ["correlated", "correlated"]
    assert "assessment" in result.post_exploitation[0] and "assessment" not in result.post_exploitation[1]


# ----------------------------------------------------------------- related_host_evidence (SQLite)


@pytest.fixture
async def db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'pattern.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for agent in (AGENT, OTHER):
            session.add(Agent(id=agent, hostname=agent, ip_address="192.0.2.1", mac_address="00:00:00:00:00:01"))
        session.add(Incident(id="inc_sqli", title="SQLi", agent_id=AGENT, created_at=T0, updated_at=T0, detection_evidence={
            "behavior": {"evidence_type": "http", "last_attempt_at": T0.isoformat()}}))
        session.add(ProcessInfo(id="pinfo_flask", agent_id=AGENT, pid=4100, parent_pid=1, name="python3",
                                exe="/usr/bin/python3.12", cmdline=FLASK_CMD, process_start_time=FLASK_START))
        await session.commit()
        yield session
    await engine.dispose()


async def add_shell(db, incident_id, *, agent=AGENT, at=T0 + timedelta(seconds=30), observed=None, **kwargs):
    """A shell incident created at ``at``; ``observed`` mimics rule_engine updating it in place later."""
    kwargs.setdefault("shell_start", at.timestamp())
    evidence = shell_evidence(**kwargs)
    last = observed or at
    evidence["network"]["observed_at"] = last.isoformat()
    evidence["first_seen"], evidence["last_observed_at"] = at.isoformat(), last.isoformat()
    db.add(Incident(id=incident_id, title="shell", agent_id=agent, created_at=at, updated_at=last,
                    detection_evidence=evidence))
    await db.commit()


async def test_web_spawned_shell_is_verified_with_outbound_flow(db):
    await add_shell(db, "inc_shell")
    db.add(Flow(id="flow_out", agent_id=AGENT, src_ip="192.0.2.1", dst_ip="203.0.113.9", src_port=50000,
                dst_port=4444, start_time=T0 + timedelta(seconds=31), pid=4242,
                socket_evidence={"direction": "outbound", "holders": [{"pid": 4242, "process_start_time": SHELL_START}]}))
    await db.commit()
    incident = await db.get(Incident, "inc_sqli")
    items = await pe.related_host_evidence(db, incident)
    shell, flow = items
    assert shell["correlation"] == "verified" and shell["spawned_by_web_server"] is True
    assert shell["source_incident_id"] == "inc_shell"
    assert shell["web_server_process"]["process_info_id"] == "pinfo_flask"
    assert set(shell["evidence_refs"]) == {"inc_shell", "ent_shell", "sock_1", "pinfo_flask"}
    assert (flow["kind"], flow["correlation"]) == ("outbound_connection", "verified")
    assert flow["evidence_refs"] == ["flow_out", "inc_shell"]


async def test_other_agent_and_outside_window_are_not_verified(db):
    await add_shell(db, "inc_other_agent", agent=OTHER)
    await add_shell(db, "inc_late", at=T0 + timedelta(seconds=900))
    incident = await db.get(Incident, "inc_sqli")
    assert await pe.related_host_evidence(db, incident) == []
    items = await pe.related_host_evidence(db, incident, window_seconds=1200)
    assert {item["source_incident_id"] for item in items} == {"inc_late"}
    assert all(item["agent_id"] == AGENT for item in items)
    assert items[0]["correlation"] == "verified"


async def sqli_spanning(db, minutes):
    incident = await db.get(Incident, "inc_sqli")
    incident.detection_evidence = {"behavior": {"evidence_type": "http", "first_attempt_at": T0.isoformat(),
                                                "last_attempt_at": (T0 + timedelta(minutes=minutes)).isoformat()}}
    await db.commit()
    return incident


async def test_shell_early_in_long_attack_is_found_after_in_place_updates(db):
    incident = await sqli_spanning(db, 30)
    await add_shell(db, "inc_early", at=T0 + timedelta(minutes=1), observed=T0 + timedelta(minutes=29))
    [item] = await pe.related_host_evidence(db, incident)
    assert (item["source_incident_id"], item["correlation"]) == ("inc_early", "verified")


async def test_shell_started_before_attack_is_listed_but_not_verified(db):
    await add_shell(db, "inc_before", at=T0 - timedelta(minutes=5))
    [item] = await pe.related_host_evidence(db, await db.get(Incident, "inc_sqli"))
    assert item["correlation"] == "unverified" and item["spawned_by_web_server"] is False
    assert "trước khi chuỗi request HTTP bắt đầu" in item["reason"]
    result = pe.assess(PROBE, host_evidence=[item], kb=FakeKB())
    assert result.post_exploitation[0]["status"] == "related, not correlated"
    assert not any("inc_before" in fact for fact in result.confirmed_facts)


async def test_web_child_process_without_socket_is_related_not_correlated(db):
    db.add(ProcessInfo(id="pinfo_id_cmd", agent_id=AGENT, pid=4500, parent_pid=4100, name="sh", exe="/usr/bin/sh",
                       cmdline="sh -c id", process_start_time=T0.timestamp() + 5))
    db.add(ProcessInfo(id="pinfo_old_child", agent_id=AGENT, pid=4501, parent_pid=4100, name="sh", exe="/usr/bin/sh",
                       cmdline="sh -c id", process_start_time=T0.timestamp() - 7200))
    await db.commit()
    [item] = await pe.related_host_evidence(db, await db.get(Incident, "inc_sqli"))
    assert (item["kind"], item["correlation"]) == ("web_server_child_process", "unverified")
    assert item["evidence_refs"] == ["pinfo_id_cmd", "pinfo_flask"]
    assert "thời điểm khởi động" in item["reason"]
    result = pe.assess(PROBE, host_evidence=[item], kb=FakeKB())
    assert result.post_exploitation[0]["status"] == "related, not correlated"
    assert "assessment" not in result.post_exploitation[0]
    alone = pe.assess({}, host_evidence=[item], kb=FakeKB())
    assert (alone.level_name, alone.attack_mapping) == ("related_host_activity", ())


async def test_pid_reuse_with_different_start_time_is_not_verified(db):
    reused = [{"pid": 4100, "parent_pid": 1, "process_start_time": FLASK_START + 10, "exe_path": "/usr/bin/python3",
               "name": "python3", "cmdline": FLASK_CMD}]
    await add_shell(db, "inc_reuse", ancestry=reused)
    incident = await db.get(Incident, "inc_sqli")
    [item] = await pe.related_host_evidence(db, incident)
    assert item["correlation"] == "unverified" and item["spawned_by_web_server"] is False
    assert "tái sử dụng" in item["reason"]
    result = pe.assess(PROBE, host_evidence=[item], kb=FakeKB())
    assert result.post_exploitation[0]["status"] == "related, not correlated"


async def test_non_web_parent_is_not_verified(db):
    db.add(ProcessInfo(id="pinfo_cron", agent_id=AGENT, pid=4300, parent_pid=1, name="cron", exe="/usr/sbin/cron",
                       cmdline="/usr/sbin/cron -f", process_start_time=FLASK_START))
    await db.commit()
    cron = [{"pid": 4300, "parent_pid": 1, "process_start_time": FLASK_START, "exe_path": "/usr/sbin/cron",
             "name": "cron", "cmdline": "/usr/sbin/cron -f"}]
    await add_shell(db, "inc_cron", ancestry=cron)
    shell = (await pe.related_host_evidence(db, await db.get(Incident, "inc_sqli")))[0]
    assert shell["correlation"] == "unverified"
    assert "Không có tiến trình cha nào khớp" in shell["reason"]


async def test_broken_ancestry_chain_is_not_verified(db):
    broken = [{"pid": 4100, "parent_pid": 1, "process_start_time": SHELL_START + 999, "exe_path": "/usr/bin/python3",
               "name": "python3", "cmdline": FLASK_CMD}]
    await add_shell(db, "inc_broken", ancestry=broken)
    shell = (await pe.related_host_evidence(db, await db.get(Incident, "inc_sqli")))[0]
    assert shell["correlation"] == "unverified" and "không liên tục" in shell["reason"]


async def test_investigate_output_feeds_the_ladder(db, monkeypatch, kb):
    """End-to-end with the real investigate(): stored rows -> L4 with T1190 refs."""
    request_id = "req_1234567890abcdef"
    row_id = stable_id("wlog_", AGENT, request_id)
    auth_id = stable_id("auth_", AGENT, "flask_web", request_id)
    session_ref = "a" * 64
    db.add(WebAccessLog(id=row_id, agent_id=AGENT, method="POST", path="/login", status_code=302, src_ip=PEER,
                        user_agent="sqlmap/1.9", timestamp=T0, raw_message=json.dumps({
                            "source": "normalized_http", "service": "flask_web", "request_id": request_id,
                            "session_ref": session_ref, "payload_indicators": ["sql_boolean_expression"]})))
    db.add(AuthEvent(id=auth_id, agent_id=AGENT, service="flask_web", source_ip=PEER, status="success", count=1,
                     timestamp=T0 + timedelta(seconds=1)))
    db.add(Event(id=auth_id, agent_id=AGENT, source="AGENT_AUTH", event_type="AUTH_OBSERVATION", details={
        "request_id": request_id, "session_ref": session_ref, "timestamp_source": "application",
        "request_method": "POST", "request_path": "/login"}))
    incident = await db.get(Incident, "inc_sqli")
    incident.detection_evidence = {"behavior": {"evidence_type": "http", "source": "web_access_logs", "agent_id": AGENT,
                                                "evidence_id": "http_group_1", "source_event_ids": [row_id],
                                                "last_attempt_at": T0.isoformat()}}
    await db.commit()
    monkeypatch.setattr(lab_waf, "direct_observation", lambda *args: False)
    for confirmed, level in ((False, 3), (True, 4)):
        monkeypatch.setattr(lab_waf, "credential_mismatch", lambda *args, ok=confirmed: ok)
        data, _ = await http_investigation.investigate(db, incident)
        result = pe.assess(data, kb=kb)
        assert result.level == level, data["classification"]
        assert techniques(result) == ["T1190"] and row_id in result.attack_mapping[0].evidence_refs


# ----------------------------------------------------------------- playbooks and schema validation


def test_every_level_playbook_exists_and_graphs_are_acyclic():
    patterns, playbooks = pe.catalog()
    for pattern in patterns.values():
        for level in pattern["levels"]:
            assert level["playbook"] in playbooks
    for book in playbooks.values():
        kinds = {a["action_type"] for a in book["actions"]}
        for action in book["actions"]:
            assert set(action["depends_on"]) <= kinds
            assert action["action_type"] not in pe._ancestors(action["action_type"],
                                                             {a["action_type"]: a["depends_on"] for a in book["actions"]})
            if action["execution"] == "executable":
                assert action["action_type"] in pe.EXECUTABLE_ACTIONS


def test_sqli_probing_block_chain():
    actions = {a["action_type"]: a for a in pe.playbook("sqli_probing")["actions"]}
    assert actions["temporary_ip_block"]["depends_on"] == ["collect_additional_evidence"]
    assert any("trực tiếp" in p for p in actions["temporary_ip_block"]["prerequisites"])
    assert "403" in actions["temporary_ip_block"]["verification_method"]
    assert actions["verify_block_enforcement"]["depends_on"] == ["temporary_ip_block"]
    assert actions["release_ip_block"]["depends_on"] == ["verify_block_enforcement"]
    assert {"recommend_parameterized_queries", "recommend_input_validation",
            "recommend_least_privilege_db_account", "recommend_safe_error_handling"} <= set(actions)
    assert "isolate" not in actions and "kill_process_tree" not in actions


def test_host_actions_only_in_verified_playbooks():
    _, playbooks = pe.catalog()
    host = {pid for pid, book in playbooks.items()
            if {"isolate", "kill_process_tree"} & {a["action_type"] for a in book["actions"]}}
    assert host == {"reverse_shell_confirmed", "web_post_exploitation"}
    actions = {a["action_type"]: a for a in playbooks["web_post_exploitation"]["actions"]}
    assert "isolate" in actions["temporary_ip_block"]["conflicts_with"]
    assert "temporary_ip_block" in actions["isolate"]["conflicts_with"]
    for book in ("web_post_exploitation", "reverse_shell_confirmed"):
        kill = next(a for a in playbooks[book]["actions"] if a["action_type"] == "kill_process_tree")
        assert kill["depends_on"] == ["collect_additional_evidence"]


GOOD_ACTION = {"action_type": "collect_additional_evidence", "category": "investigation", "priority": 1,
               "execution": "executable", "description": "x", "prerequisites": [], "depends_on": [],
               "conflicts_with": [], "operational_risk": "low", "rollback": "x", "verification_method": "x",
               "knowledge": {"terms": "x", "categories": [], "attack_ids": []}}


def write_playbook(tmp_path, *actions):
    import yaml
    (tmp_path / "book.yaml").write_text(yaml.safe_dump({"playbooks": {"book": {"actions": list(actions)}}}))
    return tmp_path


@pytest.mark.parametrize("actions, message", [
    ([{**GOOD_ACTION, "depends_on": ["isolate"]}], "missing action"),
    ([{**GOOD_ACTION, "depends_on": ["advise_x"]},
      {**GOOD_ACTION, "action_type": "advise_x", "execution": "advisory", "depends_on": ["collect_additional_evidence"]}],
     "cycle"),
    ([{**GOOD_ACTION, "category": "magic"}], "category"),
    ([{**GOOD_ACTION, "action_type": "made_up_action"}], "existing action_type"),
    ([GOOD_ACTION, {**GOOD_ACTION, "action_type": "temporary_ip_block", "category": "application_protection"},
      {**GOOD_ACTION, "action_type": "isolate", "category": "containment"}], "ordered or declared conflicting"),
    ([{**GOOD_ACTION, "action_type": "temporary_ip_block", "description": "Isolate the attacker host"}], "isolation"),
    ([{**GOOD_ACTION, "action_type": "temporary_ip_block", "description": "Cô lập máy kẻ tấn công"}], "isolation"),
    ([{**GOOD_ACTION, "action_type": "temporary_ip_block", "rollback": "Bỏ cô lập máy từ xa"}], "isolation"),
    ([{**GOOD_ACTION, "dependson": ["isolate"]}], "unknown key"),
    ([{**GOOD_ACTION, "knowledge": {"terms": "x", "categorie": ["sql_injection"]}}], "unknown key"),
    ([{**GOOD_ACTION, "knowledge": {"terms": "x", "categories": ["not_a_category"]}}], "knowledge category"),
])
def test_playbook_schema_errors_raised_at_load(tmp_path, actions, message):
    with pytest.raises(pe.PatternSchemaError, match=message):
        pe.load_playbooks(write_playbook(tmp_path, *actions))


def test_negated_isolation_wording_on_block_is_accepted(tmp_path):
    block = {**GOOD_ACTION, "action_type": "temporary_ip_block", "description": "Chặn nguồn; không cô lập máy từ xa."}
    assert "book" in pe.load_playbooks(write_playbook(tmp_path, block))


def test_unknown_playbook_level_keys_are_rejected(tmp_path):
    import yaml
    (tmp_path / "book.yaml").write_text(yaml.safe_dump({"playbooks": {"book": {"actions": [GOOD_ACTION], "note": 1}}}))
    with pytest.raises(pe.PatternSchemaError, match="unknown key"):
        pe.load_playbooks(tmp_path)


def test_ordered_block_and_isolate_are_accepted(tmp_path):
    block = {**GOOD_ACTION, "action_type": "temporary_ip_block", "category": "application_protection"}
    isolate = {**GOOD_ACTION, "action_type": "isolate", "category": "containment", "depends_on": ["temporary_ip_block"]}
    assert "book" in pe.load_playbooks(write_playbook(tmp_path, GOOD_ACTION, block, isolate))


def pattern_doc(**level_overrides):
    level = {"level": 1, "name": "one", "requires": {"all": ["sql_payload_indicators"]},
             "conclusion": "Một câu kết luận.", "confirmed": [], "suspected": [], "missing_evidence": [],
             "alternative_explanations": [], "investigation_steps": [], "attack": [], "playbook": "sqli_probing",
             "knowledge": []}
    level.update(level_overrides)
    return {"pattern_id": "demo", "category": "sql_injection", "applies_to": {"classifications": ["x"]},
            "forbidden_techniques": ["T1110"], "levels": [level]}


@pytest.mark.parametrize("overrides, message", [
    ({"requires": {"all": ["no_such_predicate"]}}, "unknown predicate"),
    ({"conclusion": "Câu một. Câu hai."}, "one sentence"),
    ({"attack": [{"technique_id": "T1110", "evidence_from": ["sql_payload_indicators"]}]}, "forbidden"),
    ({"attack": [{"technique_id": "T1190", "evidence_from": []}]}, "evidence_from"),
    ({"attack": [{"technique_id": "Exploit", "evidence_from": ["sql_payload_indicators"]}]}, "technique_id"),
    ({"level": 2}, "numbered"),
    ({"playbook": "no_such_playbook"}, "unknown playbook"),
    ({"missing_evidense": []}, "unknown key"),
    ({"attack": [{"technique_id": "T1190", "evidence_from": ["sql_payload_indicators"], "note": "x"}]}, "unknown key"),
    ({"confirmed": [{"predicate": "sql_payload_indicators", "text": "x", "txt": "y"}]}, "unknown key"),
    ({"requires": {"all": ["sql_payload_indicators"], "none": []}}, "unknown key"),
    ({"knowledge": [{"terms": "x", "attackids": ["T1190"]}]}, "unknown key"),
])
def test_pattern_schema_errors_raised_at_load(tmp_path, overrides, message):
    import yaml
    (tmp_path / "demo.yaml").write_text(yaml.safe_dump(pattern_doc(**overrides), allow_unicode=True))
    with pytest.raises(pe.PatternSchemaError, match=message):
        pe.load_patterns(tmp_path, playbook_ids=pe.catalog()[1])


@pytest.mark.parametrize("mutate, message", [
    (lambda doc: doc.update(forbiden_techniques=doc.pop("forbidden_techniques")), "unknown key"),
    (lambda doc: doc.pop("forbidden_techniques"), "forbidden_techniques"),
    (lambda doc: doc["applies_to"].update(classification=["x"]), "unknown key"),
])
def test_pattern_top_level_typos_are_rejected(tmp_path, mutate, message):
    import yaml
    doc = pattern_doc()
    mutate(doc)
    (tmp_path / "demo.yaml").write_text(yaml.safe_dump(doc, allow_unicode=True))
    with pytest.raises(pe.PatternSchemaError, match=message):
        pe.load_patterns(tmp_path)


def test_sqli_category_rejects_t1110_even_without_yaml_ban(tmp_path):
    import yaml
    doc = pattern_doc(attack=[{"technique_id": "T1110", "evidence_from": ["sql_payload_indicators"]}])
    doc["forbidden_techniques"] = []
    (tmp_path / "demo.yaml").write_text(yaml.safe_dump(doc, allow_unicode=True))
    with pytest.raises(pe.PatternSchemaError, match="forbidden"):
        pe.load_patterns(tmp_path)


def test_invalid_yaml_is_a_schema_error(tmp_path):
    (tmp_path / "broken.yaml").write_text("pattern_id: [unclosed\n")
    with pytest.raises(pe.PatternSchemaError, match="invalid YAML"):
        pe.load_patterns(tmp_path)
