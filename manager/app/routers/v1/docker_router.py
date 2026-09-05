import logging
from typing import List
from fastapi import APIRouter, HTTPException, status, Query

from app.schemas.docker_status import ContainerStatusOut
from app.services.docker_monitor_service import DockerMonitorService

logger = logging.getLogger("docker_router")

try:
    from docker.errors import DockerException
except ImportError:
    DockerException = Exception

router = APIRouter(tags=["Docker Monitor"])


@router.get("/status", response_model=List[ContainerStatusOut], status_code=status.HTTP_200_OK)
async def get_docker_status(
    stats_timeout: float = Query(5.0, ge=1.0, le=20.0, description="Timeout in seconds for querying container stats")
):
    """Retrieve real-time status, uptime, CPU, Memory, and Network I/O metrics of all Docker containers."""
    service = DockerMonitorService()
    try:
        containers = await service.get_containers_status(stats_timeout=stats_timeout)
        return containers
    except (DockerException, FileNotFoundError, PermissionError, RuntimeError) as e:
        logger.warning(f"Docker connection/permission error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error while fetching Docker status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to inspect Docker containers: {str(e)}"
        )
