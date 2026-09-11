from typing import List, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.models.risk_score import RiskScoreRecord
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


@router.get("/verify-phase2")
async def verify_phase2(db: AsyncSession = Depends(get_db)):
    """Kiểm tra Phase 2 đã fix đúng chưa."""
    # 1. Check Manager IP không còn trong beaconing
    try:
        stmt = text("""
            SELECT COUNT(*) FROM risk_score_records
            WHERE timestamp > NOW() - INTERVAL '5 minutes'
              AND factors::text LIKE '%172.19.0.3%'
        """)
        manager_ip_count = (await db.execute(stmt)).scalar() or 0
    except Exception:
        stmt = text("""
            SELECT COUNT(*) FROM risk_score_records
            WHERE timestamp > datetime('now', '-5 minutes')
              AND factors LIKE '%172.19.0.3%'
        """)
        manager_ip_count = (await db.execute(stmt)).scalar() or 0

    # 2. Check idle agents score
    try:
        stmt = text("""
            SELECT MAX(score) FROM risk_score_records
            WHERE timestamp > NOW() - INTERVAL '5 minutes'
              AND agent_id LIKE 'client%'
        """)
        max_idle_score = (await db.execute(stmt)).scalar() or 0
    except Exception:
        stmt = text("""
            SELECT MAX(score) FROM risk_score_records
            WHERE timestamp > datetime('now', '-5 minutes')
              AND agent_id LIKE 'client%'
        """)
        max_idle_score = (await db.execute(stmt)).scalar() or 0

    # 3. Check baseline freshness
    stmt = text("""
        SELECT MAX(updated_at) FROM agent_baselines
    """)
    latest_baseline = (await db.execute(stmt)).scalar()
    now_utc = datetime.now(timezone.utc)
    baseline_fresh = (
        latest_baseline is not None
        and (
            (now_utc - (latest_baseline if latest_baseline.tzinfo else latest_baseline.replace(tzinfo=timezone.utc))).total_seconds() < 3600
        )
    )

    # 4. Check EMA
    try:
        stmt = text("""
            SELECT COUNT(*) FROM risk_score_records
            WHERE timestamp > NOW() - INTERVAL '5 minutes'
              AND ABS(score - smoothed_score) > 0.01
        """)
        ema_diff_count = (await db.execute(stmt)).scalar() or 0
    except Exception:
        stmt = text("""
            SELECT COUNT(*) FROM risk_score_records
            WHERE timestamp > datetime('now', '-5 minutes')
              AND ABS(score - smoothed_score) > 0.01
        """)
        ema_diff_count = (await db.execute(stmt)).scalar() or 0

    return {
        "manager_ip_bypassed": manager_ip_count == 0,
        "idle_agents_safe": max_idle_score < 5,
        "baseline_fresh": baseline_fresh,
        "ema_working": ema_diff_count > 0,
        "details": {
            "manager_ip_records": manager_ip_count,
            "max_idle_score": float(max_idle_score),
            "latest_baseline": latest_baseline.isoformat() if latest_baseline else None,
            "ema_diff_records": ema_diff_count,
        }
    }


@router.get("/agent/{agent_id}")
async def get_agent_risk_scores(
    agent_id: str,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """Lấy lịch sử risk score của 1 agent."""
    stmt = (
        select(RiskScoreRecord)
        .where(RiskScoreRecord.agent_id == agent_id)
        .order_by(RiskScoreRecord.timestamp.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    records = result.scalars().all()
    return [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "score": r.score,
            "smoothed_score": r.smoothed_score if r.smoothed_score is not None else r.score,
            "factors": r.factors,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in records
    ]


@router.get("/agent/{agent_id}/summary")
async def get_agent_risk_summary(
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Lấy tóm tắt risk score của 1 agent."""
    repo = RiskScoreRepository(db)
    latest = await repo.get_latest_one_by_agent(agent_id)
    if not latest:
        return {"agent_id": agent_id, "score": 0.0, "smoothed_score": 0.0, "factors": {}}
    return {
        "agent_id": latest.agent_id,
        "score": latest.score,
        "smoothed_score": latest.smoothed_score if latest.smoothed_score is not None else latest.score,
        "factors": latest.factors,
        "timestamp": latest.timestamp.isoformat(),
    }


@router.get("/{agent_id}/history", response_model=List[RiskScoreOut])
async def get_agent_risk_history(agent_id: str, limit: int = 20, db: AsyncSession = Depends(get_db)):
    """Get historical risk assessment records for a specific agent."""
    repo = RiskScoreRepository(db)
    return await repo.get_latest_by_agent(agent_id, limit=limit)

