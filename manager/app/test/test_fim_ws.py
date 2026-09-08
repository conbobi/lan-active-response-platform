import sys
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocketDisconnect

# Ensure agent directory is importable
agent_dir = Path(__file__).resolve().parents[3] / "agent"
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from fim import FileIntegrityMonitor
from app.websocket.agent_ws import agent_websocket_endpoint
from app.schemas.enums import IncidentSeverity

pytestmark = pytest.mark.asyncio


async def test_fim_monitor_detects_changes_and_single_alert(tmp_path):
    """
    Verify FileIntegrityMonitor detects file modification/deletion/creation
    and only emits an alert once per state transition (no repeated alert flooding).
    """
    test_file = tmp_path / "config.txt"
    test_file.write_text("initial content")

    watched_dir = tmp_path / "extra"
    watched_dir.mkdir()

    # 1. Initialize monitor
    monitor = FileIntegrityMonitor(
        agent_id="agent-test",
        watched_files=[str(test_file)],
        watched_dirs=[str(watched_dir)]
    )

    # Initial check right after baseline: no changes
    alerts = monitor.check_integrity()
    assert len(alerts) == 0

    # 2. Modify file -> should trigger 1 alert
    test_file.write_text("tampered content")
    alerts = monitor.check_integrity()
    assert len(alerts) == 1
    assert alerts[0]["action"] == "MODIFIED"
    assert alerts[0]["file_path"] == str(test_file)
    assert alerts[0]["old_hash"] != alerts[0]["new_hash"]

    # 3. Subsequent check with NO changes -> must NOT send alert again
    repeat_alerts = monitor.check_integrity()
    assert len(repeat_alerts) == 0, "FIM must not flood repeated alerts for already recorded hash"

    # 4. Create new file in watched directory -> triggers CREATED alert
    new_file = watched_dir / "backdoor.sh"
    new_file.write_text("#!/bin/bash\necho bad")

    alerts = monitor.check_integrity()
    assert len(alerts) == 1
    assert alerts[0]["action"] == "CREATED"
    assert alerts[0]["file_path"] == str(new_file)

    # 5. Check again -> no duplicate CREATED alert
    assert len(monitor.check_integrity()) == 0

    # 6. Delete file -> triggers DELETED alert
    test_file.unlink()
    alerts = monitor.check_integrity()
    assert len(alerts) == 1
    assert alerts[0]["action"] == "DELETED"
    assert alerts[0]["file_path"] == str(test_file)

    # 7. Check again -> no duplicate DELETED alert
    assert len(monitor.check_integrity()) == 0


async def test_fim_alert_critical_file_creates_incident():
    """Verify backend agent_ws receives FIM_ALERT on sensitive file (/etc/passwd) and creates CRITICAL Incident."""
    mock_ws = MagicMock()
    mock_ws.query_params = {"agent_id": "client1"}

    fim_msg = {
        "type": "FIM_ALERT",
        "payload": {
            "agent_id": "client1",
            "file_path": "/etc/passwd",
            "old_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "new_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            "action": "MODIFIED",
            "timestamp": "2026-09-04T12:00:00Z"
        },
        "wait_ack": True
    }

    import json
    mock_ws.receive_text = AsyncMock(side_effect=[
        json.dumps(fim_msg),
        WebSocketDisconnect()
    ])
    mock_ws.send_json = AsyncMock()

    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    mock_session_local = MagicMock(return_value=mock_session)
    mock_session_local.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_local.__aexit__ = AsyncMock(return_value=None)

    mock_inc_service = MagicMock()
    mock_inc_service.create_incident = AsyncMock()

    mock_event_repo = MagicMock()
    mock_event_repo.add = AsyncMock()

    with patch("app.websocket.agent_ws.connection_manager.connect", AsyncMock()), \
         patch("app.websocket.agent_ws.connection_manager.disconnect", MagicMock()), \
         patch("app.websocket.agent_ws.AsyncSessionLocal", mock_session_local), \
         patch("app.websocket.agent_ws.EventRepository", return_value=mock_event_repo), \
         patch("app.websocket.agent_ws.IncidentService", return_value=mock_inc_service):

        await agent_websocket_endpoint(mock_ws)

        # 1. Verify Event was added via EventRepository
        mock_event_repo.add.assert_awaited_once()
        event_obj = mock_event_repo.add.call_args[0][0]
        assert event_obj.event_type == "FIM_ALERT"
        assert event_obj.severity == IncidentSeverity.HIGH
        assert event_obj.agent_id == "client1"

        # 2. Verify CRITICAL incident was created for /etc/passwd
        mock_inc_service.create_incident.assert_awaited_once()
        inc_dto = mock_inc_service.create_incident.call_args[0][0]
        assert inc_dto.severity == IncidentSeverity.CRITICAL
        assert "/etc/passwd" in inc_dto.title
        assert inc_dto.agent_id == "client1"

        # 3. Verify response ACK
        mock_ws.send_json.assert_called_once_with({
            "status": "ack",
            "message": "FIM alert processed"
        })
