from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.risk import RiskAssessmentDTO, RiskScoreOut
from app.services.risk_assessment_service import RiskAssessmentService
from app.repositories.risk_score_repository import RiskScoreRepository

router = APIRouter(tags=["Risk Assessment"])


@router.post("/evaluate", response_model=RiskScoreOut, status_code=status.HTTP_200_OK)
async def evaluate_agent_risk(dto: RiskAssessmentDTO, db: AsyncSession = Depends(get_db)):
    """Evaluate telemetry data and process automated risk scoring & response workflows."""
    service = RiskAssessmentService(db)
    record = await service.process_risk(dto.agent_id, dto)
    return record


@router.get("/{agent_id}/history", response_model=List[RiskScoreOut])
async def get_agent_risk_history(agent_id: str, limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Get historical risk assessment records for a specific agent."""
    repo = RiskScoreRepository(db)
    return await repo.get_latest_by_agent(agent_id, limit=limit)
