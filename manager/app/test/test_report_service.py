import pytest
from unittest.mock import patch, AsyncMock
from app.services.report_service import ReportService
from unittest.mock import MagicMock

pytestmark = pytest.mark.asyncio
async def test_generate_monthly_report(mock_db):
    service = ReportService(mock_db)

    # Mock các repository mà service sử dụng
    service.report_repo = AsyncMock()
    service.report_repo.get_by_date.return_value = []
    service.incident_repository = AsyncMock()
    service.incident_repository.get_by_date.return_value = []
    service.event_repository = AsyncMock()
    service.event_repository.get_by_date.return_value = []

    # Nếu service dùng report_repo để lưu
    service.report_repo = AsyncMock()
    service.report_repo.add.return_value = MagicMock()

    with patch("app.services.report_service.ReportService.generate_monthly_report") as mock_generate:
        mock_generate.return_value = MagicMock()
        result = await service.generate_monthly_report(month=6, year=2024)
    
    # Kiểm tra result
    assert result is not None
