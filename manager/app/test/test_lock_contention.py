import sys
import asyncio
import json
from pathlib import Path
import pytest
from unittest.mock import AsyncMock

# Ensure agent directory is importable
agent_dir = Path(__file__).resolve().parents[3] / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

import agent

pytestmark = pytest.mark.asyncio


async def test_send_ws_json_no_wait_not_blocked_by_request_lock():
    """Verify that send_ws_json_no_wait is not blocked when send_ws_json_and_wait is holding ws_request_lock."""
    # Ensure fresh locks
    agent.ws_request_lock = asyncio.Lock()
    agent.ws_send_lock = asyncio.Lock()

    no_wait_completed = False
    request_lock_released = False

    mock_ws = AsyncMock()
    mock_ws.send = AsyncMock()

    # Simulate a slow websocket recv that holds ws_request_lock
    async def slow_recv():
        # While holding ws_request_lock, sleep briefly
        await asyncio.sleep(0.2)
        return json.dumps({"status": "ok"})

    mock_ws.recv = slow_recv

    async def run_and_wait():
        nonlocal request_lock_released
        res = await agent.send_ws_json_and_wait(mock_ws, {"type": "HEARTBEAT"})
        request_lock_released = True
        return res

    async def run_no_wait():
        nonlocal no_wait_completed
        # Small sleep so run_and_wait starts first and acquires ws_request_lock
        await asyncio.sleep(0.05)
        # Verify ws_request_lock is currently locked
        assert agent.ws_request_lock.locked()
        await agent.send_ws_json_no_wait(mock_ws, {"type": "FLOW_STATS", "delta": 100})
        no_wait_completed = True
        # At this point, request_lock should still be held by run_and_wait
        assert not request_lock_released

    task_wait = asyncio.create_task(run_and_wait())
    task_no_wait = asyncio.create_task(run_no_wait())

    await asyncio.gather(task_wait, task_no_wait)

    assert no_wait_completed is True
    assert request_lock_released is True


async def test_send_ws_json_no_wait_concurrency():
    """Verify that multiple concurrent send_ws_json_no_wait calls succeed without deadlock or message loss."""
    agent.ws_send_lock = asyncio.Lock()

    sent_messages = []

    mock_ws = AsyncMock()
    async def fake_send(data):
        # Emulate network write delay
        await asyncio.sleep(0.01)
        sent_messages.append(json.loads(data))

    mock_ws.send = fake_send

    # Concurrently launch 10 background send operations
    tasks = [
        agent.send_ws_json_no_wait(mock_ws, {"type": "TELEMETRY", "index": i})
        for i in range(10)
    ]
    await asyncio.gather(*tasks)

    assert len(sent_messages) == 10
    indices = {msg["index"] for msg in sent_messages}
    assert indices == set(range(10))


async def test_send_ws_json_and_wait_receives_correct_response():
    """Verify send_ws_json_and_wait transmits payload and parses response correctly."""
    agent.ws_request_lock = asyncio.Lock()

    mock_ws = AsyncMock()
    expected_response = {"status": "success", "pending_commands": [{"id": 1, "action": "ping"}]}
    mock_ws.recv = AsyncMock(return_value=json.dumps(expected_response))
    mock_ws.send = AsyncMock()

    result = await agent.send_ws_json_and_wait(mock_ws, {"type": "HEARTBEAT", "agent_id": "test_agent"})

    assert result == expected_response
    mock_ws.send.assert_called_once()
    sent_payload = json.loads(mock_ws.send.call_args[0][0])
    assert sent_payload.get("type") == "HEARTBEAT"
    assert sent_payload.get("agent_id") == "test_agent"


async def test_send_ws_json_and_wait_handles_timeout_gracefully():
    """Verify send_ws_json_and_wait returns None on timeout without throwing unhandled exceptions."""
    agent.ws_request_lock = asyncio.Lock()

    mock_ws = AsyncMock()
    # Simulate timeout during recv
    async def timeout_recv():
        raise asyncio.TimeoutError()

    mock_ws.recv = timeout_recv
    mock_ws.send = AsyncMock()

    result = await agent.send_ws_json_and_wait(mock_ws, {"type": "HEARTBEAT"})
    assert result is None
    # Verify ws_request_lock is released even after timeout
    assert not agent.ws_request_lock.locked()
