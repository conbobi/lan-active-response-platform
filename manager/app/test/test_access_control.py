"""Block → verify → unblock → restore-access lifecycle, end to end.

Receipts are produced by the real Agent adapter (agent/ip_blocklist.py) on an in-memory nft double
and delivered through the Manager's COMMAND_ACK / BLOCKLIST_STATE handlers. No real firewall.
"""
import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select, update

from app.core.config import NetworkOperator, settings
from app.models.command import Command
from app.models.ip_block import IpBlock
from app.models.web_access_log import WebAccessLog
from app.services.response import access_control as ac
from app.websocket import agent_ws
from test_http_response_assist import ADMIN, ANALYST, lab  # noqa: F401  (fixture re-export)
from test_network_module import AGENT, digest, header

AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"
OPERATOR_TOKEN = "operator-token-for-access-control-tests"
OPERATOR = header(OPERATOR_TOKEN)
ATTACKER = "100.67.222.3"
API = "/api/v1/access-control"


def agent_module(name):
    sys.path.insert(0, str(AGENT_DIR))
    try:
        spec = importlib.util.spec_from_file_location(f"larp_agent_{name}", AGENT_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(AGENT_DIR))


ip_blocklist = agent_module("ip_blocklist")
FakeNft = agent_module("test_ip_blocklist").FakeNft


@pytest.fixture
def env(lab, monkeypatch):
    client, factory = lab
    operators = dict(settings.NETWORK_OPERATORS)
    operators["op"] = NetworkOperator(role="operator", agents={AGENT}, token_sha256=digest(OPERATOR_TOKEN))
    monkeypatch.setattr(settings, "NETWORK_OPERATORS", operators)
    state = {"online": True}
    monkeypatch.setattr(ac, "online", lambda agent_id: state["online"])
    nft = FakeNft()
    agent = ip_blocklist.Blocklist(runner=nft, manager_url="wss://manager.invalid/ws/agent",
                                   probe=lambda: {"reachable": True, "endpoint": "manager.invalid:443"})
    monkeypatch.setattr(agent, "protected", lambda: {})
    return client, factory, state, nft, agent


def request(client, ip=ATTACKER, headers=ADMIN):
    return client.post(f"{API}/blocks", headers=headers, json={
        "agent_id": AGENT, "target_ip": ip, "incident_id": "inc", "reason": "Reverse shell tới cổng 4444"})


async def commands(factory, action):
    async with factory() as db:
        return (await db.scalars(select(Command).where(Command.action == action))).all()


async def run_agent(factory, agent, action):
    """What the Agent does with the newest command of ``action``, delivered as COMMAND_ACK."""
    cmd = (await commands(factory, action))[-1]
    params = cmd.payload
    assert params["confirmed"] is True and params["action_id"]
    if action == "block_ip":
        receipt = agent.block(params["block_id"], params["ip"])
    elif action == "unblock_ip":
        receipt = agent.unblock(params["block_id"], params["unblock_id"], params["ip"])
    else:
        receipt = {"status": "success", **agent.status()}
    async with factory() as db:
        await agent_ws._handle_command_ack(AGENT, {"payload": {
            "command_id": cmd.id, "status": receipt["status"], "receipt": receipt,
            "error_message": receipt.get("message")}}, db)
        await db.commit()
    return receipt


async def blocked(client, factory, agent):
    block = request(client).json()
    view = client.post(f"{API}/blocks/{block['id']}/approve", headers=ADMIN).json()
    assert view["effective_state"] == "BLOCKING" and view["status"] == "DISPATCHED"
    await run_agent(factory, agent, "block_ip")
    return client.get(f"{API}/blocks/{block['id']}", headers=ANALYST).json()


@pytest.mark.asyncio
async def test_approved_block_is_executed_and_verified_from_the_firewall(env):
    client, factory, _, nft, agent = env
    view = await blocked(client, factory, agent)
    assert view["status"] == "VERIFIED" and view["effective_state"] == "BLOCKED"
    assert view["effective_label"] == "Đã chặn & xác minh" and view["verification"]["rule_verified"]
    assert view["verification"]["management_preserved"] is True
    assert view["approved_by"] == "admin" and view["can"]["unblock"] is True
    assert [h["event"] for h in view["history"]] == ["requested", "approved", "dispatched", "verified"]
    assert {r["comment"] for r in nft.rules} == {f"larp-block:{view['id']}"}


@pytest.mark.asyncio
async def test_roles_analyst_cannot_block_operator_cannot_approve(env):
    client, factory, *_ = env
    assert request(client, headers=ANALYST).status_code == 403
    block = request(client, headers=OPERATOR).json()
    assert block["status"] == "PENDING_APPROVAL" and block["requested_by"] == "op"
    assert client.post(f"{API}/blocks/{block['id']}/approve", headers=OPERATOR).status_code == 403
    assert client.post(f"{API}/blocks/{block['id']}/approve", headers=ANALYST).status_code == 403
    assert client.post(f"{API}/blocks/{block['id']}/approve").status_code == 401
    assert await commands(factory, "block_ip") == []


@pytest.mark.asyncio
async def test_repeated_requests_and_approvals_send_one_command_and_one_rule_pair(env):
    client, factory, _, nft, agent = env
    first = request(client).json()
    assert request(client).json()["id"] == first["id"]
    client.post(f"{API}/blocks/{first['id']}/approve", headers=ADMIN)
    client.post(f"{API}/blocks/{first['id']}/approve", headers=ADMIN)
    assert len(await commands(factory, "block_ip")) == 1
    await run_agent(factory, agent, "block_ip")
    await run_agent(factory, agent, "block_ip")  # receipt replay / re-delivery
    assert len(nft.rules) == 2


@pytest.mark.asyncio
async def test_protected_targets_are_refused(env, monkeypatch):
    client, factory, _, nft, agent = env
    monkeypatch.setenv("LARP_PROTECTED_CIDRS", "100.113.42.95/32")
    assert request(client, ip="100.113.42.95").status_code == 409
    assert request(client, ip="192.0.2.1").status_code == 409  # the Agent's own address
    assert request(client, ip="10.0.0.0/8").status_code == 422
    # The Agent's own preflight refuses what only it can see (e.g. an SSH admin peer).
    monkeypatch.setattr(agent, "protected", lambda: {ATTACKER: "phiên SSH quản trị đang mở"})
    block = request(client).json()
    client.post(f"{API}/blocks/{block['id']}/approve", headers=ADMIN)
    await run_agent(factory, agent, "block_ip")
    view = client.get(f"{API}/blocks/{block['id']}", headers=ADMIN).json()
    assert view["status"] == "FAILED" and view["effective_state"] == "NOT_BLOCKED" and "PROTECTED_TARGET" in view["error"]
    assert nft.rules == []


@pytest.mark.asyncio
async def test_unblock_removes_only_its_rule_then_access_is_verified_from_client_traffic(env):
    client, factory, _, nft, agent = env
    view = await blocked(client, factory, agent)
    assert client.post(f"{API}/blocks/{view['id']}/unblock", headers=ADMIN, json={"reason": ""}).status_code == 422
    view = client.post(f"{API}/blocks/{view['id']}/unblock", headers=OPERATOR,
                       json={"reason": "Đã vá lỗ hổng, khôi phục cho máy lab"}).json()
    unblock = view["unblock"]
    assert unblock["status"] == "PENDING_APPROVAL" and view["effective_state"] == "BLOCKED"
    assert client.post(f"{API}/unblocks/{unblock['id']}/approve", headers=OPERATOR).status_code == 403
    view = client.post(f"{API}/unblocks/{unblock['id']}/approve", headers=ADMIN).json()
    assert view["effective_state"] == "UNBLOCKING"
    await run_agent(factory, agent, "unblock_ip")
    view = client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()
    assert view["effective_state"] == "UNBLOCKED" and view["unblock"]["status"] == "VERIFIED"
    assert view["unblock"]["access_state"] == "UNVERIFIED"  # RULE_REMOVED — CONNECTIVITY_UNVERIFIED
    assert view["unblock"]["access_label"] == "Đã gỡ rule — chưa xác minh kết nối"
    assert view["can"]["unblock"] is False
    # Periodic state with no client packets yet: still unverified.
    async with factory() as db:
        await agent_ws._handle_blocklist_state(AGENT, {"payload": {"agent_id": AGENT, **agent.status()}}, db)
        await db.commit()
    assert client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()["unblock"]["access_state"] == "UNVERIFIED"
    # The client connects again: the verification counter on the Agent sees its packets.
    verify = next(r for r in nft.rules if r["comment"].startswith("larp-verify:"))
    verify["packets"] = 4
    async with factory() as db:
        await agent_ws._handle_blocklist_state(AGENT, {"payload": {"agent_id": AGENT, **agent.status()}}, db)
        await db.commit()
    view = client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()
    assert view["unblock"]["access_state"] == "RESTORED" and view["unblock"]["connectivity"]["packets_from_client"] == 4
    assert "access_restored" in [h["event"] for h in view["history"]]
    assert [h["event"] for h in view["history"]][:4] == ["requested", "approved", "dispatched", "verified"]


@pytest.mark.asyncio
async def test_http_request_from_the_client_also_proves_restoration(env):
    client, factory, _, nft, agent = env
    view = await blocked(client, factory, agent)
    view = client.post(f"{API}/blocks/{view['id']}/unblock", headers=ADMIN, json={"reason": "Khôi phục lab"}).json()
    client.post(f"{API}/unblocks/{view['unblock']['id']}/approve", headers=ADMIN)
    await run_agent(factory, agent, "unblock_ip")
    async with factory.begin() as db:
        db.add(WebAccessLog(id="wlog_back", agent_id=AGENT, method="GET", path="/login", status_code=200,
                            src_ip=ATTACKER, timestamp=datetime.now(timezone.utc) + timedelta(seconds=1)))
    async with factory() as db:
        await ac.reconcile(db, AGENT, {"blocks": {}, "verifications": {}})
        await db.commit()
    unblock = client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()["unblock"]
    assert unblock["access_state"] == "RESTORED" and unblock["connectivity"]["http_request"]["id"] == "wlog_back"


@pytest.mark.asyncio
async def test_unblock_while_another_larp_block_remains_is_not_restored(env):
    client, factory, _, nft, agent = env
    view = await blocked(client, factory, agent)
    agent.block("f" * 32, ATTACKER)  # another LARP policy on the Agent for the same address
    view = client.post(f"{API}/blocks/{view['id']}/unblock", headers=ADMIN, json={"reason": "Khôi phục lab"}).json()
    client.post(f"{API}/unblocks/{view['unblock']['id']}/approve", headers=ADMIN)
    await run_agent(factory, agent, "unblock_ip")
    unblock = client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()["unblock"]
    assert unblock["access_state"] == "STILL_BLOCKED" and unblock["firewall_removal"]["other_larp_blocks"] == ["f" * 32]
    assert {r["comment"] for r in nft.rules} == {"larp-block:" + "f" * 32}


@pytest.mark.asyncio
async def test_agent_offline_during_unblock_keeps_the_last_verified_state(env):
    client, factory, state, nft, agent = env
    view = await blocked(client, factory, agent)
    view = client.post(f"{API}/blocks/{view['id']}/unblock", headers=ADMIN, json={"reason": "Khôi phục lab"}).json()
    state["online"] = False
    response = client.post(f"{API}/unblocks/{view['unblock']['id']}/approve", headers=ADMIN)
    assert response.status_code == 409 and "offline" in response.json()["detail"]
    view = client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()
    assert view["effective_state"] == "BLOCKED" and view["unblock"]["status"] == "PENDING_APPROVAL"
    assert view["agent_online"] is False and view["verification"]["observed_at"]
    assert await commands(factory, "unblock_ip") == []


@pytest.mark.asyncio
async def test_timeout_is_unknown_not_failed_and_a_late_receipt_or_check_resolves_it(env):
    client, factory, _, nft, agent = env
    block = request(client).json()
    client.post(f"{API}/blocks/{block['id']}/approve", headers=ADMIN)
    async with factory.begin() as db:
        await db.execute(update(IpBlock).where(IpBlock.id == block["id"]).values(
            dispatched_at=datetime.now(timezone.utc) - timedelta(minutes=5)))
    view = client.get(f"{API}/blocks/{block['id']}", headers=ADMIN).json()
    assert view["status"] == "TIMEOUT" and view["effective_state"] == "UNKNOWN"
    assert view["effective_label"] == "Không xác minh được" and view["can"]["unblock"] is True
    # "Kiểm tra lại" sends a read-only status command, never a second block.
    assert client.post(f"{API}/blocks/{block['id']}/check", headers=ADMIN).status_code == 202
    assert len(await commands(factory, "block_ip")) == 1
    agent.block(block["id"], ATTACKER)  # it had in fact run on the Agent
    await run_agent(factory, agent, "blocklist_status")
    view = client.get(f"{API}/blocks/{block['id']}", headers=ADMIN).json()
    assert view["status"] == "VERIFIED" and view["effective_state"] == "BLOCKED"


@pytest.mark.asyncio
async def test_state_survives_manager_restart_and_detects_external_removal(env):
    client, factory, _, nft, agent = env
    view = await blocked(client, factory, agent)
    async with factory() as db:  # a new process reads the same rows
        stored = await db.get(IpBlock, view["id"])
        assert stored.effective_state == "BLOCKED" and stored.receipt["rule_verified"]
    nft.rules.clear()  # someone removed the rules outside LARP
    async with factory() as db:
        await agent_ws._handle_blocklist_state(AGENT, {"payload": {"agent_id": AGENT, **agent.status()}}, db)
        await db.commit()
    view = client.get(f"{API}/blocks/{view['id']}", headers=ADMIN).json()
    assert view["effective_state"] == "NOT_BLOCKED" and view["history"][-1]["detail"]["note"]


@pytest.mark.asyncio
async def test_concurrent_approvals_dispatch_once(env):
    import asyncio
    client, factory, *_ = env
    block = request(client).json()

    async def approve(name):
        async with factory() as db:
            try:
                await ac.approve_block(db, block["id"], name)
                await db.commit()
            except Exception:  # noqa: BLE001 - SQLite may refuse the second writer outright
                await db.rollback()
    await asyncio.gather(approve("admin"), approve("admin2"))
    assert len(await commands(factory, "block_ip")) == 1


@pytest.mark.asyncio
async def test_suggestions_come_from_correlated_incident_evidence(env, monkeypatch):
    from app.models.incident import Incident
    client, factory, *_ = env
    monkeypatch.setenv("LARP_PROTECTED_CIDRS", "100.113.42.95/32")
    async with factory.begin() as db:
        db.add(Incident(id="inc_chain", title="Web Application Compromise", risk_score=100, agent_id=AGENT,
                        detection_evidence={"rule_id": "web_compromise_chain", "chain": {
                            "source_ips": [ATTACKER, "100.113.42.95"],
                            "network": [{"flow_id": "flow_1", "dst": f"{ATTACKER}:4444", "pid": 154107}]}}))
    items = {i["ip"]: i for i in client.get(f"{API}/incidents/inc_chain/suggestions", headers=ANALYST).json()["items"]}
    assert items[ATTACKER]["allowed"] and items[ATTACKER]["evidence_ids"] == ["flow_1"] and len(items[ATTACKER]["basis"]) == 2
    assert items["100.113.42.95"]["allowed"] is False and items["100.113.42.95"]["protected_reason"]
