from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock
from app.services.whitelist_service import WhitelistService
from app.models.whitelist import WhitelistEntry
from app.schemas.whitelist import WhitelistEntryCreate

pytestmark = pytest.mark.asyncio


async def test_add_entry(mock_db):
    service = WhitelistService(mock_db)
    dto = WhitelistEntryCreate(
        agent_id="agent-1",
        process_name="excel.exe",
        path="C:\\Program Files\\Microsoft Office\\excel.exe",
        reason="Office app"
    )

    service.repository.add = AsyncMock(return_value=WhitelistEntry(
        id="whitelist-1",
        agent_id=dto.agent_id,
        process_name=dto.process_name,
        path=dto.path,
        reason=dto.reason,
        created_at=datetime.now(timezone.utc)
    ))

    result = await service.add_entry(dto)

    assert result.process_name == "excel.exe"
    service.repository.add.assert_awaited_once()


async def test_is_whitelisted_true(mock_db):
    service = WhitelistService(mock_db)
    service.repository.is_whitelisted = AsyncMock(return_value=True)

    result = await service.is_whitelisted("agent-1", "excel.exe")

    assert result is True
    service.repository.is_whitelisted.assert_awaited_once_with(
        agent_id="agent-1",
        process_name="excel.exe",
        path=None
    )


async def test_remove_entry(mock_db):
    service = WhitelistService(mock_db)
    service.repository.delete = AsyncMock(return_value=True)

    result = await service.remove_entry("whitelist-1")

    assert result is True
    service.repository.delete.assert_awaited_once_with("whitelist-1")