from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.threat_intel import ThreatCheckDTO
from app.services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter(tags=["Threat Intelligence"])


@router.post("/check", status_code=status.HTTP_200_OK)
async def check_threat_indicator(dto: ThreatCheckDTO, db: AsyncSession = Depends(get_db)):
    """Check a file hash, IP address, or domain against Threat Intelligence sources."""
    service = ThreatIntelligenceService(db)
    result = await service.check_indicator(dto.value, dto.indicator_type)
    return result
