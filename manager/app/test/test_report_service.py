import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.report_service import ReportService
from app.models.report import Report

pytestmark = pytest.mark.asyncio


async def test_generate_monthly_report(mock_db):
    mock_execute_result = MagicMock()
    mock_execute_result.scalar.return_value = 5
    mock_db.execute = AsyncMock(return_value=mock_execute_result)

    service = ReportService(mock_db)

    dummy_report = Report(
        id="rep-123",
        title="LARP Security Operations Monthly Report",
        file_path="/tmp/test_report.pdf",
        format="pdf"
    )
    service.report_repo.add = AsyncMock(return_value=dummy_report)

    with patch("reportlab.platypus.SimpleDocTemplate.build"):
        report = await service.generate_monthly_report(month=6, year=2024)

    assert report is not None
    assert report.id == "rep-123"
    service.report_repo.add.assert_awaited_once()
