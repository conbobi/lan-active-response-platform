import time
import logging
from typing import Any, Dict, Tuple, List, Optional
from app.services.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)


class ProcessChainRule(RiskRule):
    rule_id = "process_chain"
    name = "Process Chain Anomaly"
    description = "Detects suspicious parent-child process chains based on dynamic database rules and process groups."
    enabled = True
    weight = 1.0
    base_score = 1.0
    category = "process"

    # Default fallback parents and children if DB is unavailable or empty
    DEFAULT_PARENTS = [
        "winword.exe", "word.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", "firefox.exe"
    ]
    DEFAULT_CHILDREN = [
        "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "bitsadmin.exe",
        "bash", "sh", "python", "python.exe", "curl", "wget", "certutil"
    ]

    # In-memory rule cache
    _cache_rules: Optional[List[Dict[str, Any]]] = None
    _cache_timestamp: float = 0.0
    CACHE_TTL_SECONDS: float = 30.0

    @classmethod
    def invalidate_cache(cls) -> None:
        """Invalidate in-memory cached process chain rules."""
        cls._cache_rules = None
        cls._cache_timestamp = 0.0
        logger.debug("ProcessChainRule in-memory cache invalidated.")

    @classmethod
    def _get_fallback_rules(cls) -> List[Dict[str, Any]]:
        """Construct fallback rules based on default hardcoded patterns."""
        return [
            {
                "id": "fallback_office_shell",
                "name": "Default Office Spawning Shell (Fallback)",
                "action": "alert",
                "parent_patterns": tuple(p.lower() for p in cls.DEFAULT_PARENTS),
                "child_patterns": tuple(p.lower() for p in cls.DEFAULT_CHILDREN),
            }
        ]

    async def _get_active_chain_rules(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fetch active process chain rules from DB with TTL caching.
        Falls back to hardcoded defaults on error or missing DB session.
        """
        now = time.time()
        if (
            self._cache_rules is not None
            and (now - self._cache_timestamp) < self.CACHE_TTL_SECONDS
        ):
            return self._cache_rules

        session = context.get("session")
        if not session:
            logger.warning(
                "[PROCESS_CHAIN] No database session provided in context. "
                "Using default fallback rules."
            )
            return self._get_fallback_rules()

        try:
            from app.repositories.process_chain_rule_repository import ProcessChainRuleRepository
            repo = ProcessChainRuleRepository(session)
            db_rules = await repo.list_active()

            if not db_rules:
                logger.warning(
                    "[PROCESS_CHAIN] No active process chain rules found in DB. "
                    "Using default fallback rules."
                )
                return self._get_fallback_rules()

            prepared: List[Dict[str, Any]] = []
            for r in db_rules:
                parent_pats = tuple(
                    p.strip().lower()
                    for p in (r.parent_group.patterns if r.parent_group else [])
                    if p.strip()
                )
                child_pats = tuple(
                    p.strip().lower()
                    for p in (r.child_group.patterns if r.child_group else [])
                    if p.strip()
                )
                prepared.append({
                    "id": r.id,
                    "name": r.name,
                    "action": r.action,
                    "parent_patterns": parent_pats,
                    "child_patterns": child_pats,
                })

            ProcessChainRule._cache_rules = prepared
            ProcessChainRule._cache_timestamp = now
            return prepared

        except Exception as exc:
            logger.warning(
                f"[PROCESS_CHAIN] Database query failed: {exc}. "
                "Falling back to default rules."
            )
            return self._get_fallback_rules()

    @staticmethod
    def _matches_pattern(proc_name: str, pattern: str) -> bool:
        """
        Fast case-insensitive match for process name against a pattern.
        Matches exact name, basename, or suffix.
        """
        if not proc_name or not pattern:
            return False
        # Exact match or suffix match
        if proc_name == pattern or proc_name.endswith(pattern):
            return True
        # Basename match
        base = proc_name.replace("\\", "/").split("/")[-1]
        return base == pattern or base.endswith(pattern) or pattern in base

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        process_tree = telemetry.get("process_tree", [])
        process_list = telemetry.get("process_list", [])
        agent_id = context.get("agent_id", "unknown")

        rules = await self._get_active_chain_rules(context)
        if not rules:
            return 0.0, ""

        # Collect and normalize all candidate parent-child pairs
        # Format: list of (raw_parent, raw_child, clean_parent, clean_child)
        pairs: List[Tuple[str, str, str, str]] = []

        # 1. From process_tree
        for item in process_tree:
            p_dict = (
                item if isinstance(item, dict)
                else item.model_dump() if hasattr(item, "model_dump")
                else getattr(item, "__dict__", {})
            )
            raw_p = str(p_dict.get("parent_name", "")).strip()
            raw_c = str(p_dict.get("child_name", "")).strip()
            if raw_p and raw_c:
                pairs.append((raw_p, raw_c, raw_p.lower(), raw_c.lower()))

        # 2. From process_list
        for proc in process_list:
            p_dict = (
                proc if isinstance(proc, dict)
                else proc.model_dump() if hasattr(proc, "model_dump")
                else getattr(proc, "__dict__", {})
            )
            raw_p = str(p_dict.get("parent_name", "")).strip()
            raw_c = str(p_dict.get("name", "")).strip()
            if raw_p and raw_c:
                pairs.append((raw_p, raw_c, raw_p.lower(), raw_c.lower()))

        if not pairs:
            return 0.0, ""

        anomalies: List[str] = []
        highest_action = "alert"
        action_priority = {"alert": 1, "block": 2, "isolate": 3}

        # Evaluate pairs against compiled active chain rules
        for raw_p, raw_c, clean_p, clean_c in pairs:
            for rule in rules:
                p_matched = any(self._matches_pattern(clean_p, pat) for pat in rule["parent_patterns"])
                if not p_matched:
                    continue

                c_matched = any(self._matches_pattern(clean_c, pat) for pat in rule["child_patterns"])
                if not c_matched:
                    continue

                rule_name = rule["name"]
                action = rule["action"]
                anomaly_desc = f"[Rule: {rule_name} ({action.upper()})] '{raw_p}' spawned '{raw_c}'"

                if anomaly_desc not in anomalies:
                    anomalies.append(anomaly_desc)
                    logger.info(
                        f"[PROCESS_CHAIN MATCH] Agent: {agent_id} | Rule: '{rule_name}' "
                        f"(action={action}) | Parent: '{raw_p}' -> Child: '{raw_c}'"
                    )

                if action_priority.get(action, 1) > action_priority.get(highest_action, 1):
                    highest_action = action

        if anomalies:
            # Score scaling: minimum 35, up to 60 * base_score
            score = min(60.0, max(35.0, len(anomalies) * 25.0)) * self.base_score
            return score, f"Process chain anomaly detected: {'; '.join(anomalies)}"

        return 0.0, ""
