from datetime import datetime, timezone
import pytest
from app.models.agent import Agent
from app.models.topology_link import TopologyLink
from app.models.notification import NotificationConfig, NotificationLog
from app.models.risk_score import RiskScoreRecord
from app.models.whitelist import WhitelistEntry
from app.repositories.agent_repository import AgentRepository
from app.repositories.topology_link_repository import TopologyLinkRepository
from app.repositories.notification_repository import NotificationRepository
from app.repositories.risk_score_repository import RiskScoreRepository
from app.repositories.whitelist_repository import WhitelistRepository
from app.schemas.enums import AgentStatus

pytestmark = pytest.mark.asyncio


async def test_agent_repository_db(db_session):
    repo = AgentRepository(db_session)

    # 1. Add
    agent = Agent(
        id="repo-agent-1",
        hostname="repo-host",
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        status=AgentStatus.ACTIVE
    )
    added = await repo.add(agent)
    await db_session.commit()
    assert added.id == "repo-agent-1"

    # 2. Get
    fetched = await repo.get("repo-agent-1")
    assert fetched is not None
    assert fetched.hostname == "repo-host"

    # 3. List
    agents = await repo.list()
    assert len(agents) == 1
    assert agents[0].id == "repo-agent-1"


async def test_topology_link_repository_db(db_session):
    agent_repo = AgentRepository(db_session)
    for aid in ["agent-A", "agent-B", "agent-C"]:
        await agent_repo.add(Agent(
            id=aid, hostname=aid, ip_address="192.168.1.1", mac_address="00:00:00:00:00:00"
        ))
    await db_session.commit()

    repo = TopologyLinkRepository(db_session)
    link1 = TopologyLink(
        id="link-db-1",
        source_agent_id="agent-A",
        target_agent_id="agent-B",
        capacity=1000.0,
        reserved_bandwidth=0.0,
        latency=2.5,
        load=10.0,
        packet_loss=0.0,
        is_active=True
    )
    link2 = TopologyLink(
        id="link-db-2",
        source_agent_id="agent-B",
        target_agent_id="agent-C",
        capacity=1000.0,
        reserved_bandwidth=0.0,
        latency=5.0,
        load=20.0,
        packet_loss=0.0,
        is_active=False
    )
    await repo.add(link1)
    await repo.add(link2)
    await db_session.commit()

    # get_active_links
    active_links = await repo.get_active_links()
    assert len(active_links) == 1
    assert active_links[0].id == "link-db-1"

    # find_by_agent
    b_links = await repo.find_by_agent("agent-B")
    assert len(b_links) == 2


async def test_notification_repository_db(db_session):
    repo = NotificationRepository(db_session)

    config = NotificationConfig(
        id="cfg-db-1",
        channel="discord",
        webhook_url="https://discord.com/api/webhooks/test",
        enabled=True
    )
    await repo.add(config)
    await db_session.commit()

    # get_enabled_configs
    enabled = await repo.get_enabled_configs(channel="discord")
    assert len(enabled) == 1
    assert enabled[0].webhook_url == "https://discord.com/api/webhooks/test"

    # add_log
    log = NotificationLog(
        id="log-db-1",
        channel="discord",
        recipient="webhook",
        message="Test alert log",
        status="sent"
    )
    added_log = await repo.add_log(log)
    await db_session.commit()
    assert added_log.id == "log-db-1"

    logs = await repo.list_logs()
    assert len(logs) == 1
    assert logs[0].message == "Test alert log"


async def test_risk_score_repository_db(db_session):
    agent_repo = AgentRepository(db_session)
    await agent_repo.add(Agent(
        id="agent-X", hostname="agent-X", ip_address="192.168.1.1", mac_address="00:00:00:00:00:00"
    ))
    await db_session.commit()

    repo = RiskScoreRepository(db_session)
    record1 = RiskScoreRecord(
        id="risk-db-1",
        agent_id="agent-X",
        score=35.0,
        factors={"cpu": "low"},
        timestamp=datetime.now(timezone.utc)
    )
    record2 = RiskScoreRecord(
        id="risk-db-2",
        agent_id="agent-X",
        score=85.0,
        factors={"cpu": "high"},
        timestamp=datetime.now(timezone.utc)
    )
    await repo.add(record1)
    await repo.add(record2)
    await db_session.commit()

    latest = await repo.get_latest_by_agent("agent-X", limit=5)
    assert len(latest) == 2


async def test_whitelist_repository_db(db_session):
    agent_repo = AgentRepository(db_session)
    await agent_repo.add(Agent(
        id="agent-Y", hostname="agent-Y", ip_address="192.168.1.1", mac_address="00:00:00:00:00:00"
    ))
    await db_session.commit()

    repo = WhitelistRepository(db_session)
    entry = WhitelistEntry(
        id="wl-db-1",
        agent_id="agent-Y",
        process_name="notepad.exe",
        path="C:\\Windows\\notepad.exe",
        reason="System tool"
    )
    await repo.add(entry)
    await db_session.commit()

    is_whitelisted = await repo.is_whitelisted(agent_id="agent-Y", process_name="notepad.exe")
    assert is_whitelisted is True

    is_not_whitelisted = await repo.is_whitelisted(agent_id="agent-Y", process_name="malware.exe")
    assert is_not_whitelisted is False
