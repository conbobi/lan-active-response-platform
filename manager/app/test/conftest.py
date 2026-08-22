import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
def mock_db():
    session = AsyncMock(spec=AsyncSession)
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    return session

@pytest.fixture
def mock_repo():
    return MagicMock()

@pytest.fixture
def mock_command_dispatcher():
    dispatcher = MagicMock()
    dispatcher.push_command = AsyncMock()
    return dispatcher

@pytest.fixture
def mock_notification_service():
    service = MagicMock()
    service.send_alert = AsyncMock()
    return service
@pytest.fixture
def mock_notification_repo():
    repo = AsyncMock()
    repo.get_enabled_configs.return_value = []  # không có cấu hình telegram
    repo.add_log.return_value = AsyncMock()
    repo.list_logs.return_value = []
    return repo
