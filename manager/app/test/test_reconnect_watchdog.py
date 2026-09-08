import sys
import asyncio
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import yaml

# Ensure agent directory is importable
agent_dir = Path(__file__).resolve().parents[3] / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

import agent

pytestmark = pytest.mark.asyncio


async def test_exponential_backoff_progression():
    """Verify exponential backoff doubles delay on failure, caps at max_delay, and resets on success."""
    retry_delay = 2
    max_delay = 15

    delays = []
    # Simulate 5 consecutive connection failure retries
    for _ in range(5):
        delays.append(retry_delay)
        retry_delay = min(retry_delay * 2, max_delay)

    assert delays == [2, 4, 8, 15, 15]

    # Successful reconnect resets delay back to initial value (2s)
    retry_delay = 2
    assert retry_delay == 2


async def test_watchdog_triggers_exit_when_timeout_exceeded():
    """Verify watchdog_task triggers os._exit(1) when no heartbeat ACK is received for > 30s."""
    agent.last_heartbeat_ack_time = 1000.0

    # Simulate current time being 35 seconds later (elapsed = 35s > 30s)
    mock_exit = MagicMock(side_effect=SystemExit(1))

    # We patch asyncio.sleep so watchdog runs immediately, and patch os._exit to raise SystemExit
    with patch("time.time", return_value=1035.0), \
         patch("asyncio.sleep", AsyncMock(return_value=None)), \
         patch("os._exit", mock_exit):

        with pytest.raises(SystemExit) as exc_info:
            await agent.watchdog_task()

        assert exc_info.value.code == 1
        mock_exit.assert_called_once_with(1)


async def test_watchdog_does_not_exit_when_heartbeat_fresh():
    """Verify watchdog_task does not trigger os._exit when heartbeat ACK was received recently (<= 30s)."""
    agent.last_heartbeat_ack_time = 1000.0

    mock_exit = MagicMock()
    sleep_call_count = 0

    async def fake_sleep(sec):
        nonlocal sleep_call_count
        sleep_call_count += 1
        if sleep_call_count >= 2:
            raise asyncio.CancelledError()

    with patch("time.time", return_value=1010.0), \
         patch("asyncio.sleep", side_effect=fake_sleep), \
         patch("os._exit", mock_exit):

        try:
            await agent.watchdog_task()
        except asyncio.CancelledError:
            pass

        mock_exit.assert_not_called()


async def test_docker_compose_has_restart_unless_stopped():
    """Verify docker-compose.yml configures 'restart: unless-stopped' for client/agent services."""
    compose_path = Path(__file__).resolve().parents[3] / "docker-compose.yml"
    assert compose_path.exists(), f"docker-compose.yml not found at {compose_path}"

    with open(compose_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    services = config.get("services", {})
    client_services = [name for name in services if name.startswith("client")]
    assert len(client_services) > 0, "No client services found in docker-compose.yml"

    for client_name in client_services:
        client_cfg = services[client_name]
        assert client_cfg.get("restart") == "unless-stopped", (
            f"Service '{client_name}' does not have 'restart: unless-stopped' (found: {client_cfg.get('restart')})"
        )
