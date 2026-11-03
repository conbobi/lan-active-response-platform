import json
import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

DEFAULT_KB_PATH = os.path.join(os.path.dirname(__file__), "mitre_techniques.json")


class MITREKnowledgeBase:
    """Grounding knowledge base for MITRE ATT&CK techniques in LARP EDR."""

    def __init__(self, path: str = DEFAULT_KB_PATH):
        self._path = path
        self._techs: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._techs = json.load(f)
                logger.info(f"Loaded {len(self._techs)} MITRE ATT&CK techniques from {self._path}")
            except Exception as e:
                logger.error(f"Failed to load MITRE techniques from {self._path}: {e}")
                self._techs = {}
        else:
            logger.warning(f"MITRE techniques file not found at {self._path}")
            self._techs = {}

    def validate_technique(self, tech_id: str) -> bool:
        """Validate if technique ID exists in KB (case-insensitive)."""
        if not tech_id or not isinstance(tech_id, str):
            return False
        clean_id = tech_id.strip().upper()
        return clean_id in self._techs

    def get_technique(self, tech_id: str) -> Dict[str, Any]:
        """Get technique details by ID."""
        if not tech_id or not isinstance(tech_id, str):
            return {}
        clean_id = tech_id.strip().upper()
        return self._techs.get(clean_id, {})

    def valid_ids(self) -> List[str]:
        """Return list of all recognized MITRE technique IDs."""
        return list(self._techs.keys())


mitre_kb = MITREKnowledgeBase()

