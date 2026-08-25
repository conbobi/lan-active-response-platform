import logging
from typing import Dict, List, Optional, Any
from app.services.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)


class RiskRuleRegistry:
    """
    Registry Pattern for managing all active risk assessment rules dynamically.
    Allows registering, enabling/disabling, configuring weights and loading rules from DB.
    """

    def __init__(self):
        self._rules: Dict[str, RiskRule] = {}

    def register(self, rule: RiskRule) -> None:
        """Register a RiskRule instance."""
        if not hasattr(rule, "rule_id") or not rule.rule_id:
            raise ValueError("Rule must have a non-empty rule_id")
        self._rules[rule.rule_id] = rule
        logger.debug(f"Registered risk rule: '{rule.rule_id}' ({rule.name})")

    def unregister(self, rule_id: str) -> bool:
        """Remove a rule from registry."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.debug(f"Unregistered risk rule: '{rule_id}'")
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[RiskRule]:
        """Retrieve rule instance by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[RiskRule]:
        """Return list of all registered rules."""
        return list(self._rules.values())

    def get_enabled_rules(self) -> List[RiskRule]:
        """Return list of currently enabled rules."""
        return [rule for rule in self._rules.values() if rule.enabled]

    def update_rule_config(
        self,
        rule_id: str,
        enabled: Optional[bool] = None,
        weight: Optional[float] = None,
        base_score: Optional[float] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Update existing registered rule settings."""
        rule = self._rules.get(rule_id)
        if not rule:
            return False
        if enabled is not None:
            rule.enabled = enabled
        if weight is not None:
            rule.weight = weight
        if base_score is not None:
            rule.base_score = base_score
        if config is not None:
            rule.config = {**getattr(rule, "config", {}), **config}
        return True

    def sync_from_db_records(self, db_rules: List[Any]) -> None:
        """
        Synchronize registered rules with configuration records loaded from DB (DetectionRule).
        """
        for record in db_rules:
            r_id = getattr(record, "rule_id", None) or getattr(record, "id", None)
            if not r_id:
                continue
            rule = self.get_rule(r_id)
            if rule:
                rule.enabled = getattr(record, "enabled", rule.enabled)
                rule.weight = getattr(record, "weight", rule.weight)
                rule.base_score = getattr(record, "base_score", getattr(rule, "base_score", 1.0))
                rule.category = getattr(record, "category", getattr(rule, "category", "os"))
                rec_cfg = getattr(record, "config", None)
                if rec_cfg and isinstance(rec_cfg, dict):
                    rule.config = rec_cfg
