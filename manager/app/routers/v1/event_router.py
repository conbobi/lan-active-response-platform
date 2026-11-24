
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import uuid4
from datetime import datetime, timezone
from app.core.deps import get_db
from app.schemas.event import EventOut, EventCreate  # Giả sử bạn đã có schema này
from app.repositories.event_repository import EventRepository
from app.models.event import Event

router = APIRouter()

@router.get("", response_model=List[EventOut], include_in_schema=False)
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

@router.delete("/", status_code=200)
@router.post("/clear", status_code=200)
async def clear_events(db: AsyncSession = Depends(get_db)):
    """Xóa tất cả các event alerts khỏi database."""
    repo = EventRepository(db)
    count = await repo.clear_all()
    return {"message": "All events cleared", "deleted_count": count}

@router.delete("/{event_id}", status_code=200)
async def delete_event(event_id: str, db: AsyncSession = Depends(get_db)):
    """Xóa một event alert cụ thể."""
    repo = EventRepository(db)
    deleted = await repo.delete_by_id(event_id)
    if not deleted:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Event not found")
    return {"message": f"Event {event_id} deleted"}
