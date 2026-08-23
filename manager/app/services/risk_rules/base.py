from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple


class RiskRule(ABC):
    """
    Abstract base class for all risk assessment rules.
    Follows Strategy Pattern & Chain of Responsibility for evaluating threat telemetry.
    """
    rule_id: str
    name: str
    description: str
    enabled: bool = True
    weight: float = 1.0
    config: Dict[str, Any] = {}

    @abstractmethod
    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        """
        Evaluate telemetry dictionary against rule criteria.
        
        Args:
            telemetry: Dictionary representation of RiskAssessmentDTO.
            context: Execution context containing services, DB session, dynamic settings.
            
        Returns:
            Tuple[float, str]: (score, reason)
        """
        pass
