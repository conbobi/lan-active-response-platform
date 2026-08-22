import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.services.command_dispatcher import CommandDispatcher
from app.schemas.command_ack import CommandAckDTO
from app.schemas.enums import CommandStatus

pytestmark = pytest.mark.asyncio


async def test_push_and_pull_commands(db_session):
    dispatcher = CommandDispatcher()
    await dispatcher.push_command("cmd-001", "agent-1")
    assert "agent-1" in dispatcher._agent_queues
    assert "cmd-001" in dispatcher._agent_queues["agent-1"]

    mock_cmd = MagicMock(id="cmd-001", action="isolate", payload={}, send_to_agent=MagicMock())
    with patch("app.repositories.command_repository.CommandRepository.get_pending_by_agent", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = [mock_cmd]
        pending = await dispatcher.pull_pending_commands("agent-1", db_session)

    assert len(pending) == 1
    assert pending[0].id == "cmd-001"
    mock_cmd.send_to_agent.assert_called_once()
    assert "agent-1" not in dispatcher._agent_queues


async def test_verify_execution_success(db_session):
    dispatcher = CommandDispatcher()
    ack_dto = CommandAckDTO(
        command_id="cmd-001",
        status=CommandStatus.SUCCESS,
        error_message=None
    )
    mock_cmd = MagicMock(
        id="cmd-001",
        agent_id="agent-1",
        acknowledge=MagicMock()
    )
    with patch("app.repositories.command_repository.CommandRepository.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_cmd
        result = await dispatcher.verify_execution(ack_dto, db_session)

    assert result is not None
    mock_cmd.acknowledge.assert_called_once_with(CommandStatus.SUCCESS, None)


async def test_verify_execution_failed_retry(db_session):
    dispatcher = CommandDispatcher()
    ack_dto = CommandAckDTO(
        command_id="cmd-001",
        status=CommandStatus.FAILED,
        error_message="Process not found"
    )
    mock_cmd = MagicMock(
        id="cmd-001",
        agent_id="agent-1",
        acknowledge=MagicMock(),
        retry=MagicMock(return_value=True),
        retry_count=1,
        max_retries=3
    )
    with patch("app.repositories.command_repository.CommandRepository.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_cmd
        result = await dispatcher.verify_execution(ack_dto, db_session)

    assert result is not None
    mock_cmd.retry.assert_called_once()
    assert "agent-1" in dispatcher._agent_queues
