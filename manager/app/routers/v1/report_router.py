import os
from typing import List
from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.core.exceptions import NotFoundError
from app.schemas.report import ReportGenerateRequest, ReportOut
from app.repositories.report_repository import ReportRepository
from app.services.report_service import ReportService

router = APIRouter(tags=["Reports"])


@router.get("/", response_model=List[ReportOut])
async def list_reports(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Retrieve list of generated PDF security reports."""
    repo = ReportRepository(db)
    return await repo.list(skip=skip, limit=limit)


@router.post("/generate", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def generate_report(dto: ReportGenerateRequest, db: AsyncSession = Depends(get_db)):
    """Trigger creation of a monthly PDF security report."""
    service = ReportService(db)
    report = await service.generate_monthly_report(
        month=dto.month,
        year=dto.year,
        start_date=dto.start_date,
        end_date=dto.end_date
    )
    return report


@router.get("/{report_id}/download")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Download a generated PDF security report by ID."""
    repo = ReportRepository(db)
    report = await repo.get(report_id)
    if not report:
        raise NotFoundError(f"Report with ID '{report_id}' was not found.")

    if not os.path.exists(report.file_path):
        raise NotFoundError(f"Report PDF file '{report.file_path}' does not exist on server.")

    return FileResponse(
        path=report.file_path,
        filename=os.path.basename(report.file_path),
        media_type="application/pdf"
    )
