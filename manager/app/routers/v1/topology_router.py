from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.topology import TopologyUpdateDTO, TopologyLinkCreate, TopologyLinkUpdate, TopologyLinkOut
from app.services.topology_service import topology_facade
from app.repositories.topology_link_repository import TopologyLinkRepository
from app.models.topology_link import TopologyLink
from app.core.exceptions import NotFoundError

router = APIRouter(tags=["Topology"])


@router.post("/update", status_code=status.HTTP_200_OK)
async def update_topology(dto: TopologyUpdateDTO, db: AsyncSession = Depends(get_db)):
    """Process agent topology update metrics."""
    await topology_facade.handle_topology_update(dto, db)
    return {"status": "ok", "message": "Topology updated successfully"}


@router.get("/links", response_model=List[TopologyLinkOut])
async def list_topology_links(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List all network topology links."""
    repo = TopologyLinkRepository(db)
    return await repo.list(skip=skip, limit=limit)


@router.post("/links", response_model=TopologyLinkOut, status_code=status.HTTP_201_CREATED)
async def create_topology_link(dto: TopologyLinkCreate, db: AsyncSession = Depends(get_db)):
    """Create a new topology link manually."""
    repo = TopologyLinkRepository(db)
    link = TopologyLink(
        id=dto.id,
        source_agent_id=dto.source_agent_id,
        target_agent_id=dto.target_agent_id,
        capacity=dto.capacity,
        reserved_bandwidth=dto.reserved_bandwidth,
        latency=dto.latency,
        load=dto.load,
        packet_loss=dto.packet_loss,
        is_active=dto.is_active
    )
    created = await repo.add(link)
    await topology_facade.manager.recalculate_all_costs(db)
    return created


@router.get("/links/{link_id}", response_model=TopologyLinkOut)
async def get_topology_link(link_id: str, db: AsyncSession = Depends(get_db)):
    """Get topology link detail."""
    repo = TopologyLinkRepository(db)
    link = await repo.get(link_id)
    if not link:
        raise NotFoundError(f"Topology link '{link_id}' not found.")
    return link


@router.put("/links/{link_id}", response_model=TopologyLinkOut)
async def update_topology_link(link_id: str, dto: TopologyLinkUpdate, db: AsyncSession = Depends(get_db)):
    """Update topology link parameters."""
    repo = TopologyLinkRepository(db)
    updated = await repo.update(link_id, dto)
    if not updated:
        raise NotFoundError(f"Topology link '{link_id}' not found.")
    await topology_facade.manager.recalculate_all_costs(db)
    return updated


@router.delete("/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_topology_link(link_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a topology link."""
    repo = TopologyLinkRepository(db)
    deleted = await repo.delete(link_id)
    if not deleted:
        raise NotFoundError(f"Topology link '{link_id}' not found.")
    await topology_facade.manager.recalculate_all_costs(db)