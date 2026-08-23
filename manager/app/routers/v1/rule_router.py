from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.rule import RuleCreate, RuleOut
from app.services.rule_service import RuleService
from app.schemas.detection_rule import DetectionRuleCreate, DetectionRuleUpdate, DetectionRuleOut
from app.services.detection_rule_service import DetectionRuleService

router = APIRouter(tags=["Rules"])


# --- Detection Rules Management APIs ---

@router.get("/detection", response_model=List[DetectionRuleOut])
async def list_detection_rules(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List dynamic detection rules for risk assessment engine."""
    service = DetectionRuleService(db)
    return await service.list_rules(skip=skip, limit=limit)


@router.post("/detection", response_model=DetectionRuleOut, status_code=status.HTTP_201_CREATED)
async def create_detection_rule(dto: DetectionRuleCreate, db: AsyncSession = Depends(get_db)):
    """Add a new dynamic detection rule."""
    service = DetectionRuleService(db)
    return await service.create_rule(dto)


@router.get("/detection/{rule_id}", response_model=DetectionRuleOut)
async def get_detection_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Get detection rule by ID."""
    service = DetectionRuleService(db)
    return await service.get_rule(rule_id)


@router.put("/detection/{rule_id}", response_model=DetectionRuleOut)
async def update_detection_rule(rule_id: str, dto: DetectionRuleUpdate, db: AsyncSession = Depends(get_db)):
    """Update detection rule configuration, enabled status, or score weight."""
    service = DetectionRuleService(db)
    return await service.update_rule(rule_id, dto)


@router.delete("/detection/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_detection_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Delete detection rule."""
    service = DetectionRuleService(db)
    await service.delete_rule(rule_id)


# --- Legacy Event/Flow Security Rules APIs ---

@router.post("/", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(dto: RuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a security detection rule."""
    service = RuleService(db)
    return await service.create_rule(dto)


@router.get("/", response_model=List[RuleOut])
async def list_rules(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List detection rules."""
    service = RuleService(db)
    return await service.list_rules(skip=skip, limit=limit)


@router.get("/{rule_id}", response_model=RuleOut)
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Get rule detail."""
    service = RuleService(db)
    return await service.get_rule(rule_id)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a detection rule."""
    service = RuleService(db)
    await service.delete_rule(rule_id)
