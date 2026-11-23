from typing import Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.deps import get_db
from app.services.dashboard.dashboard_service import DashboardService

router = APIRouter(tags=["Dashboard"])


@router.get("/summary", response_model=Dict[str, Any])
async def get_dashboard_summary(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours for active incidents"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve high-level dashboard metrics: health score, active threat counts, agent postures."""
    service = DashboardService(db)
    return await service.get_summary(hours=hours, limit=limit, offset=offset)

