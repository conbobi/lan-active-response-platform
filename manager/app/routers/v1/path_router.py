from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.path import PathRequestDTO, PathResult
from app.schemas.path_release import PathReleaseDTO
from app.services.topology_service import topology_facade

router = APIRouter(tags=["Pathfinding"])


@router.post("/request", response_model=PathResult, status_code=status.HTTP_200_OK)
async def request_path(dto: PathRequestDTO, db: AsyncSession = Depends(get_db)):
    """Request optimal path route with required bandwidth allocation."""
    return await topology_facade.request_path(dto, db)


@router.post("/release", status_code=status.HTTP_200_OK)
async def release_path(dto: PathReleaseDTO, db: AsyncSession = Depends(get_db)):
    """Release path bandwidth allocation."""
    success = await topology_facade.release_path(dto, db)
    return {"status": "ok" if success else "failed", "released": success}
