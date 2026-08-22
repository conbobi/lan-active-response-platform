
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import uuid4
from datetime import datetime, timezone
from app.core.deps import get_db
from app.schemas.event import EventOut, EventCreate  # Giả sử bạn đã có schema này
from app.repositories.event_repository import EventRepository
from app.models.event import Event

router = APIRouter()

@router.get("/", response_model=List[EventOut])
async def list_events(db: AsyncSession = Depends(get_db)):
    repo = EventRepository(db)
    events = await repo.list()
    return events

@router.post("/", response_model=EventOut, status_code=201)
async def create_event(dto: EventCreate, db: AsyncSession = Depends(get_db)):
    repo = EventRepository(db)
    event_id = dto.id or uuid4().hex
    event = Event(
        id=event_id,  # hoặc sinh id theo cách của bạn
        agent_id=dto.agent_id,
        event_type=dto.event_type,
        severity=dto.severity,
        source=dto.source,
        details=dto.details,
        processed=False,
        created_at=datetime.now(timezone.utc)

    )
    created = await repo.add(event)
    return created