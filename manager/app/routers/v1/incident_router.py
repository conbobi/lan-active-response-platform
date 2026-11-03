from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, status, Body, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import BackgroundTasks, HTTPException, status
from app.core.database import AsyncSessionLocal
import logging
from app.core.deps import get_db
from app.models.ai_analysis import AIAnalysis
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentOut,
    IncidentAssignDTO,
    IncidentNoteAddDTO,
    IncidentNoteOut,
    AIAnalysisOut,
    AIAnalysisRateDTO,
)
from app.services.incident.incident_service import IncidentService
from app.services.incident.incident_timeline_service import IncidentTimelineService
from app.services.ai.ai_triage_service import AITriageService

router = APIRouter(tags=["Incidents"])

logger = logging.getLogger(__name__)
@router.post("/", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(dto: IncidentCreate, db: AsyncSession = Depends(get_db)):
    """Create a security incident record."""
    service = IncidentService(db)
    return await service.create_incident(dto)


@router.get("", response_model=List[IncidentOut], include_in_schema=False)
@router.get("/", response_model=List[IncidentOut])
async def list_incidents(skip: int = 0, limit: int = 200, db: AsyncSession = Depends(get_db)):
    """List security incidents."""
    service = IncidentService(db)
    return await service.list_incidents(skip=skip, limit=limit)


@router.get("/{incident_id}/timeline", response_model=Dict[str, Any])
async def get_incident_timeline(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve chronological investigation timeline aggregated from process, network, risk rules, and actions."""
    service = IncidentTimelineService(db)
    return await service.build_timeline(incident_id)


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Get security incident detail."""
    service = IncidentService(db)
    return await service.get_incident(incident_id)


@router.put("/{incident_id}", response_model=IncidentOut)
@router.put("/{incident_id}/", response_model=IncidentOut, include_in_schema=False)
@router.patch("/{incident_id}", response_model=IncidentOut)
@router.patch("/{incident_id}/", response_model=IncidentOut, include_in_schema=False)
async def update_incident(incident_id: str, dto: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    """Update incident parameters, ground truth label, or status."""
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


# ============================================================================
# Layer 1 AI Investigation (AI Triage Analysis & Feedback)
# ============================================================================

@router.get("/{incident_id}/ai-analysis", response_model=AIAnalysisOut)
@router.get("/{incident_id}/ai-analysis/", response_model=AIAnalysisOut, include_in_schema=False)
async def get_ai_analysis(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Lấy AI analysis gần nhất của incident (không chạy lại)."""
    stmt = (
        select(AIAnalysis)
        .where(AIAnalysis.incident_id == incident_id, AIAnalysis.analysis_type == "triage")
        .order_by(AIAnalysis.created_at.desc())
        .limit(1)
    )
    res = await db.execute(stmt)
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI analysis not found for this incident"
        )
    return analysis


@router.post("/{incident_id}/ai-analysis/regenerate")
@router.post("/{incident_id}/ai-analysis/regenerate/", include_in_schema=False)
async def regenerate_ai_analysis(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger AI re-analysis asynchronously — returns immediately with status='analyzing'."""
    # Validate incident exists (quick DB check)
    from app.models.incident import Incident
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    async def _run_ai():
        async with AsyncSessionLocal() as session:
            try:
                from app.services.ai.ai_triage_service import AITriageService
                await AITriageService().analyze_incident(incident_id, session)
                logger.info(f"Background AI triage completed for {incident_id}")
            except Exception as e:
                logger.error(f"Background AI triage failed for {incident_id}: {e}", exc_info=True)
    
    background_tasks.add_task(_run_ai)
    
    return {
        "status": "analyzing",
        "incident_id": incident_id,
        "estimated_seconds": 200,
        "message": "AI analysis started. Poll GET /ai-analysis to retrieve result.",
    }


@router.post("/{incident_id}/ai-analysis/rate", response_model=Dict[str, Any])
@router.post("/{incident_id}/ai-analysis/rate/", response_model=Dict[str, Any], include_in_schema=False)
async def rate_ai_analysis(
    incident_id: str,
    payload: Dict[str, Any] = Body(..., example={"rating": "helpful"}),
    db: AsyncSession = Depends(get_db),
):
    """Analyst rate AI summary ('helpful' | 'wrong')."""
    rating = payload.get("rating")
    if rating not in ("helpful", "wrong", None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rating must be 'helpful' or 'wrong'"
        )

    stmt = (
        select(AIAnalysis)
        .where(AIAnalysis.incident_id == incident_id, AIAnalysis.analysis_type == "triage")
        .order_by(AIAnalysis.created_at.desc())
        .limit(1)
    )
    res = await db.execute(stmt)
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI analysis not found for this incident"
        )

    analysis.analyst_rating = rating
    await db.commit()
    await db.refresh(analysis)
    return {
        "status": "ok",
        "incident_id": incident_id,
        "rating": rating,
        "analysis_id": analysis.id
    }


@router.post("/{incident_id}/ai-analysis/suggest-response")
@router.post("/{incident_id}/ai-analysis/suggest-response/", include_in_schema=False)
async def suggest_ai_response(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger AI response suggestion generation asynchronously (<2s)."""
    from app.models.incident import Incident
    incident = await db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    async def _run_suggest():
        async with AsyncSessionLocal() as session:
            try:
                from app.services.ai.ai_response_service import AIResponseService
                await AIResponseService().suggest_response(incident_id, session)
                logger.info(f"Background AI response suggestion completed for {incident_id}")
            except Exception as e:
                logger.error(f"Background AI response suggestion failed for {incident_id}: {e}", exc_info=True)

    background_tasks.add_task(_run_suggest)

    return {
        "status": "suggesting",
        "incident_id": incident_id,
        "message": "AI response suggestion started. Poll GET /ai-analysis to retrieve result.",
    }


@router.post("/{incident_id}/ai-analysis/apply-suggestion")
@router.post("/{incident_id}/ai-analysis/apply-suggestion/", include_in_schema=False)
async def apply_ai_suggestion(
    incident_id: str,
    payload: Dict[str, Any] = Body(default={"analyst": "current_user"}),
    db: AsyncSession = Depends(get_db),
):
    """Apply AI response suggestion — delegates to ResponseActionService."""
    analyst = payload.get("analyst", "current_user")
    from app.services.ai.ai_response_service import AIResponseService
    action = await AIResponseService().apply_suggestion(incident_id, analyst, db)
    return {
        "status": "applied",
        "incident_id": incident_id,
        "action_id": action.id,
        "action_type": action.action_type,
    }


@router.post("/{incident_id}/ai-analysis/dismiss-suggestion")
@router.post("/{incident_id}/ai-analysis/dismiss-suggestion/", include_in_schema=False)
async def dismiss_ai_suggestion(
    incident_id: str,
    payload: Dict[str, Any] = Body(default={"analyst": "current_user", "reason": ""}),
    db: AsyncSession = Depends(get_db),
):
    """Analyst dismisses AI response suggestion with reasoning."""
    analyst = payload.get("analyst", "current_user")
    reason = payload.get("reason", "")
    from app.services.ai.ai_response_service import AIResponseService
    analysis = await AIResponseService().dismiss_suggestion(incident_id, analyst, reason, db)
    return {
        "status": "dismissed",
        "incident_id": incident_id,
        "analysis_id": analysis.id,
        "dismiss_reason": analysis.dismiss_reason,
    }

