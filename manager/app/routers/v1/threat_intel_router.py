from typing import List, Optional
from fastapi import APIRouter, Depends, status, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.threat_intel import ThreatCheckDTO
from app.schemas.threat_feed import ThreatFeedCreate, ThreatFeedUpdate, ThreatFeedOut, ThreatFeedSyncResult
from app.services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter(tags=["Threat Intelligence"])


@router.post("/check", status_code=status.HTTP_200_OK)
async def check_threat_indicator(dto: ThreatCheckDTO, db: AsyncSession = Depends(get_db)):
    """Check a file hash, IP address, or domain against Threat Intelligence sources."""
    service = ThreatIntelligenceService(db)
    return await service.check_indicator(dto.value, dto.indicator_type)


@router.get("/feeds", response_model=List[ThreatFeedOut], status_code=status.HTTP_200_OK)
async def list_threat_feeds(db: AsyncSession = Depends(get_db)):
    """List all configured open-source threat intelligence feeds."""
    service = ThreatIntelligenceService(db)
    return await service.list_feeds()


@router.post("/feeds", response_model=ThreatFeedOut, status_code=status.HTTP_201_CREATED)
async def create_threat_feed(dto: ThreatFeedCreate, db: AsyncSession = Depends(get_db)):
    """Create a new threat intelligence feed subscription."""
    service = ThreatIntelligenceService(db)
    return await service.create_feed(dto)


@router.put("/feeds/{feed_id}", response_model=ThreatFeedOut, status_code=status.HTTP_200_OK)
async def update_threat_feed(feed_id: str, dto: ThreatFeedUpdate, db: AsyncSession = Depends(get_db)):
    """Update feed configuration (enable/disable, URL, interval)."""
    service = ThreatIntelligenceService(db)
    updated = await service.update_feed(feed_id, dto)
    if not updated:
        raise HTTPException(status_code=404, detail="Threat feed not found")
    return updated


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat_feed(feed_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a threat feed subscription."""
    service = ThreatIntelligenceService(db)
    deleted = await service.delete_feed(feed_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Threat feed not found")


@router.post("/feeds/{feed_id}/sync", response_model=ThreatFeedSyncResult, status_code=status.HTTP_200_OK)
async def sync_single_feed(feed_id: str, db: AsyncSession = Depends(get_db)):
    """Trigger immediate sync for a specific threat feed."""
    service = ThreatIntelligenceService(db)
    return await service.sync_feed(feed_id)


@router.post("/sync-all", response_model=List[ThreatFeedSyncResult], status_code=status.HTTP_200_OK)
async def sync_all_feeds(db: AsyncSession = Depends(get_db)):
    """Trigger immediate sync across all enabled threat intelligence feeds."""
    service = ThreatIntelligenceService(db)
    return await service.sync_all_feeds()


@router.get("/indicators", status_code=status.HTTP_200_OK)
async def list_indicators(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    query: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """Search and paginate cached threat intelligence indicators."""
    service = ThreatIntelligenceService(db)
    items, total = await service.list_indicators(skip=skip, limit=limit, query=query, indicator_type=indicator_type)
    return {
        "total": total,
        "items": [
            {
                "id": item.id,
                "indicator_type": item.indicator_type,
                "value": item.value,
                "threat_type": item.threat_type,
                "confidence": item.confidence,
                "source": item.source,
                "created_at": item.created_at
            }
            for item in items
        ]
    }
