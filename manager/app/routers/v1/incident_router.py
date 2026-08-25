from typing import List, Dict, Any
from fastapi import APIRouter, Depends, status, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentOut,
    IncidentAssignDTO,
    IncidentNoteAddDTO,
    IncidentNoteOut
)
from app.services.incident_service import IncidentService

router = APIRouter(tags=["Incidents"])


@router.post("/", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(dto: IncidentCreate, db: AsyncSession = Depends(get_db)):
    """Create a security incident record."""
    service = IncidentService(db)
    return await service.create_incident(dto)


@router.get("/", response_model=List[IncidentOut])
async def list_incidents(skip: int = 0, limit: int = 200, db: AsyncSession = Depends(get_db)):
    """List security incidents."""
    service = IncidentService(db)
    return await service.list_incidents(skip=skip, limit=limit)


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Get security incident detail."""
    service = IncidentService(db)
    return await service.get_incident(incident_id)


@router.put("/{incident_id}", response_model=IncidentOut)
@router.patch("/{incident_id}", response_model=IncidentOut)
async def update_incident(incident_id: str, dto: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    """Update incident parameters or status."""
    service = IncidentService(db)
    return await service.update_incident(incident_id, dto)


@router.post("/{incident_id}/assign", response_model=IncidentOut)
async def assign_incident(incident_id: str, dto: IncidentAssignDTO, db: AsyncSession = Depends(get_db)):
    """Assign incident to operator/analyst."""
    service = IncidentService(db)
    return await service.assign_incident(incident_id, dto.user_id)


@router.post("/{incident_id}/contain", response_model=IncidentOut)
async def contain_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Mark incident as contained."""
    service = IncidentService(db)
    return await service.contain_incident(incident_id)


@router.post("/{incident_id}/resolve", response_model=IncidentOut)
async def resolve_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Mark incident as resolved."""
    service = IncidentService(db)
    return await service.resolve_incident(incident_id)


@router.post("/{incident_id}/false-positive", response_model=IncidentOut)
async def mark_incident_false_positive(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Mark incident as false positive."""
    service = IncidentService(db)
    return await service.mark_false_positive(incident_id)


@router.post("/{incident_id}/close", response_model=IncidentOut)
async def close_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Mark incident as closed."""
    service = IncidentService(db)
    return await service.close_incident(incident_id)


@router.post("/{incident_id}/action", response_model=Dict[str, Any])
async def execute_incident_action(
    incident_id: str,
    payload: Dict[str, Any] = Body(..., example={"action_type": "isolate", "params": {}}),
    db: AsyncSession = Depends(get_db)
):
    """Execute quick response action directly from an Incident (Isolate, Kill Tree, Block IP)."""
    action_type = payload.get("action_type")
    params = payload.get("params", {})
    user = payload.get("user", "admin")

    service = IncidentService(db)
    return await service.execute_action(incident_id, action_type=action_type, params=params, user=user)


@router.post("/{incident_id}/notes", response_model=IncidentNoteOut, status_code=status.HTTP_201_CREATED)
async def add_incident_note(incident_id: str, dto: IncidentNoteAddDTO, db: AsyncSession = Depends(get_db)):
    """Add a note or audit log entry to an incident."""
    service = IncidentService(db)
    return await service.add_note(incident_id, content=dto.content, user=dto.user)


@router.get("/{incident_id}/notes", response_model=List[IncidentNoteOut])
async def list_incident_notes(incident_id: str, db: AsyncSession = Depends(get_db)):
    """List notes attached to an incident."""
    service = IncidentService(db)
    return await service.list_notes(incident_id)
