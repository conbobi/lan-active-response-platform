import logging
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.detection_rule import DetectionRule
from app.schemas.detection_rule import DetectionRuleCreate, DetectionRuleUpdate
from app.repositories.detection_rule_repository import DetectionRuleRepository
from app.services.risk_rules import create_default_registry, RiskRuleRegistry
from app.core.exceptions import AppException

logger = logging.getLogger(__name__)


class DetectionRuleService:
    """Service for managing database-driven detection rules and registry sync."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = DetectionRuleRepository(session)

    async def list_rules(self, skip: int = 0, limit: int = 100) -> List[DetectionRule]:
        rules = await self.repo.list(skip=skip, limit=limit)
        if not rules and skip == 0:
            # Seed default rules into DB if none exist
            logger.info("No detection rules found in DB. Seeding default risk rules...")
            default_reg = create_default_registry()
            seeded = []
            for r in default_reg.get_all_rules():
                db_rule = DetectionRule(
                    rule_id=r.rule_id,
                    name=r.name,
                    description=r.description,
                    enabled=r.enabled,
                    weight=r.weight,
                    base_score=getattr(r, "base_score", 1.0),
                    category=getattr(r, "category", "os"),
                    config=getattr(r, "config", {})
                )
                await self.repo.add(db_rule)
                seeded.append(db_rule)
            await self.session.commit()
            return seeded
        return rules

    async def get_rule(self, rule_id: str) -> DetectionRule:
        rule = await self.repo.get_by_rule_id(rule_id)
        if not rule:
            # Fallback check by primary key ID
            rule = await self.repo.get(rule_id)
        if not rule:
            raise AppException(f"Detection rule '{rule_id}' not found.", status_code=404)
        return rule

    async def create_rule(self, dto: DetectionRuleCreate) -> DetectionRule:
        existing = await self.repo.get_by_rule_id(dto.rule_id)
        if existing:
            raise AppException(f"Detection rule with rule_id '{dto.rule_id}' already exists.", status_code=400)

        db_rule = DetectionRule(
            rule_id=dto.rule_id,
            name=dto.name,
            description=dto.description,
            enabled=dto.enabled,
            weight=dto.weight,
            base_score=dto.base_score,
            category=dto.category,
            config=dto.config
        )
        await self.repo.add(db_rule)
        await self.session.commit()
        return db_rule

    async def update_rule(self, rule_id: str, dto: DetectionRuleUpdate) -> DetectionRule:
        rule = await self.get_rule(rule_id)
        updated = await self.repo.update(rule.id, dto)
        await self.session.commit()
        return updated or rule

    async def delete_rule(self, rule_id: str) -> None:
        rule = await self.get_rule(rule_id)
        await self.repo.delete(rule.id)
        await self.session.commit()

    async def sync_registry(self, registry: RiskRuleRegistry) -> RiskRuleRegistry:
        """Fetch all detection rules from DB and update rule registry settings."""
        try:
            db_rules = await self.repo.list()
            if isinstance(db_rules, list):
                registry.sync_from_db_records(db_rules)
            else:
                logger.warning("repo.list() returned non-list value")
        except Exception as e:
            logger.debug(f"Could not sync risk rules from DB: {e}")
        return registry
