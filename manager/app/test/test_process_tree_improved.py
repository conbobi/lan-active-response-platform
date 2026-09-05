import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.process_tree_service import ProcessTreeService
from app.models.process_info import ProcessInfo

pytestmark = pytest.mark.asyncio


async def test_build_tree_attaches_orphan_nodes_to_root():
    mock_session = AsyncMock()
    service = ProcessTreeService(mock_session)

    # 3 processes:
    # PID 100 with parent_pid 9999 (missing parent)
    # PID 200 with parent_pid 100 (child of 100)
    # PID 300 with parent_pid None (orphan)
    procs = [
        ProcessInfo(
            id="p1",
            agent_id="test-agent",
            pid=100,
            parent_pid=9999,
            name="python3",
            exe="/usr/bin/python3",
            cmdline="python3 server.py",
            cpu_percent=1.0,
            memory_percent=2.0
        ),
        ProcessInfo(
            id="p2",
            agent_id="test-agent",
            pid=200,
            parent_pid=100,
            name="worker",
            exe="/usr/bin/worker",
            cmdline="worker run",
            cpu_percent=0.5,
            memory_percent=1.0
        ),
        ProcessInfo(
            id="p3",
            agent_id="test-agent",
            pid=300,
            parent_pid=None,
            name="cron",
            exe="/usr/sbin/cron",
            cmdline="cron -f",
            cpu_percent=0.1,
            memory_percent=0.2
        )
    ]

    service.process_repo.get_by_agent = AsyncMock(return_value=procs)

    tree_result = await service.build_tree("test-agent")

    assert tree_result["agent_id"] == "test-agent"
    assert tree_result["root_count"] >= 1
    # Check that root node exists (PID 1 virtual root)
    root_node = tree_result["tree"][0]
    assert root_node["pid"] == 1

    # Check children of root PID 1
    children_pids = [c["pid"] for c in root_node.get("children", [])]
    assert 100 in children_pids
    assert 300 in children_pids

    # Find node 100 and verify child 200 is attached to 100
    node_100 = next(c for c in root_node["children"] if c["pid"] == 100)
    assert any(child["pid"] == 200 for child in node_100.get("children", []))
