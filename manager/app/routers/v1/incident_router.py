from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentOut
from app.services.incident_service import IncidentService

router = APIRouter(tags=["Incidents"])


@router.post("/", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(dto: IncidentCreate, db: AsyncSession = Depends(get_db)):
    """Create a security incident record."""
    service = IncidentService(db)
    return await service.create_incident(dto)


@router.get("/", response_model=List[IncidentOut])
async def list_incidents(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List security incidents."""
    service = IncidentService(db)
    return await service.list_incidents(skip=skip, limit=limit)


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Get security incident detail."""
    service = IncidentService(db)
    return await service.get_incident(incident_id)


@router.put("/{incident_id}", response_model=IncidentOut)
async def update_incident(incident_id: str, dto: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    """Update incident parameters."""
    service = IncidentService(db)
    return await service.update_incident(incident_id, dto)


@router.post("/{incident_id}/assign", response_model=IncidentOut)
async def assign_incident(incident_id: str, user_id: str, db: AsyncSession = Depends(get_db)):
    """Assign incident to operator/analyst."""
    service = IncidentService(db)
    return await service.assign_incident(incident_id, user_id)


@router.post("/{incident_id}/resolve", response_model=IncidentOut)
async def resolve_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Mark incident as resolved."""
    service = IncidentService(db)
    return await service.resolve_incident(incident_id)
