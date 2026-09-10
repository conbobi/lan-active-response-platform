from typing import List
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_db
from app.schemas.yara import YaraRuleCreate, YaraRuleUpdate, YaraRuleOut, YaraScanRequest
from app.services.yara_service import YaraService

router = APIRouter(tags=["YARA Rules"])


@router.get("", response_model=List[YaraRuleOut], status_code=status.HTTP_200_OK)
async def list_yara_rules(db: AsyncSession = Depends(get_db)):
    """List all registered YARA rules."""
    service = YaraService(db)
    return await service.list_rules()


@router.post("", response_model=YaraRuleOut, status_code=status.HTTP_201_CREATED)
async def create_yara_rule(dto: YaraRuleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new YARA signature rule with syntax validation."""
    service = YaraService(db)
    return await service.create_rule(dto)


@router.put("/{rule_id}", response_model=YaraRuleOut, status_code=status.HTTP_200_OK)
async def update_yara_rule(rule_id: str, dto: YaraRuleUpdate, db: AsyncSession = Depends(get_db)):
    """Update YARA rule content or metadata."""
    service = YaraService(db)
    return await service.update_rule(rule_id, dto)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_yara_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a YARA signature rule."""
    service = YaraService(db)
    await service.delete_rule(rule_id)


@router.post("/scan", status_code=status.HTTP_200_OK)
async def trigger_yara_scan(dto: YaraScanRequest, db: AsyncSession = Depends(get_db)):
    """Dispatch YARA scan command to targeted agent."""
    service = YaraService(db)
    return await service.trigger_agent_scan(dto)


@router.get("/bundle", status_code=status.HTTP_200_OK)
async def get_rules_bundle(db: AsyncSession = Depends(get_db)):
    """Get all enabled YARA rules bundled as single text."""
    service = YaraService(db)
    bundle = await service.get_combined_rules_bundle()
    return {"rules": bundle}
