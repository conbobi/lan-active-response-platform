import time
import logging
from typing import Any, Dict, Tuple, List, Optional
from app.services.risk_rules.base import RiskRule

logger = logging.getLogger(__name__)

ACTION_TO_SCORE = {
    "alert": 40.0,
    "block": 70.0,
    "isolate": 90.0,
}


class ProcessChainRule(RiskRule):
    rule_id = "process_chain"
    name = "Process Chain Anomaly"
    description = "Detects suspicious parent-child process chains based on dynamic database rules and process groups."
    enabled = True
    weight = 1.0
    base_score = 1.0
    category = "process"

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
        """Construct fallback rules when DB rules are empty or DB session is missing."""
        return [
            {
                "id": "fallback_office_shell",
                "name": "Default Office Spawning Shell (Fallback)",
                "action": "alert",
                "parent_patterns": ("winword.exe", "word.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe"),
                "child_patterns": ("cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe", "wscript.exe", "cscript.exe", "bash", "sh"),
            }
        ]

    async def _get_active_chain_rules(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fetch active process chain rules from DB via ProcessChainRuleService with TTL caching.
        Falls back to default rules on error or missing DB session.
        """
        session = context.get("session")
        if not session:
            return self._get_fallback_rules()

        now = time.time()
        if (
            self._cache_rules is not None
            and (now - self._cache_timestamp) < self.CACHE_TTL_SECONDS
        ):
            return self._cache_rules

        try:
            from app.services.process_chain_rule_service import ProcessChainRuleService
            service = ProcessChainRuleService(session)
            db_rules = await service.list_active_rules()

            if not db_rules:
                return self._get_fallback_rules()

            prepared: List[Dict[str, Any]] = []
            for r in db_rules:
                parent_pats = tuple(
                    p.strip(' \t\r\n"\'').lower()
                    for p in (r.parent_group.patterns if r.parent_group else [])
                    if p.strip(' \t\r\n"\'')
                )
                child_pats = tuple(
                    p.strip(' \t\r\n"\'').lower()
                    for p in (r.child_group.patterns if r.child_group else [])
                    if p.strip(' \t\r\n"\'')
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
        Exact case-insensitive match for process name against a pattern.
        Avoids substring matching ('pattern in base') to eliminate false positives.
        """
        if not proc_name or not pattern:
            return False
        p_clean = proc_name.strip(' \t\r\n"\'').lower()
        pat_clean = pattern.strip(' \t\r\n"\'').lower()
        if not p_clean or not pat_clean:
            return False
        # Extract basename
        base = p_clean.replace("\\", "/").split("/")[-1]
        if base == pat_clean or p_clean == pat_clean:
            return True
        # Windows .exe compatibility (e.g. cmd vs cmd.exe)
        if base.endswith(".exe") and base[:-4] == pat_clean:
            return True
        if pat_clean.endswith(".exe") and base == pat_clean[:-4]:
            return True
        return False

    @staticmethod
    def _extract_proc_names(p_dict: Dict[str, Any]) -> List[str]:
        names: List[str] = []
        name = str(p_dict.get("name", "")).strip()
        if name:
            names.append(name)

        cmdline = str(p_dict.get("cmdline", "")).strip()
        if cmdline:
            argv0 = cmdline.split()[0].replace("\\", "/").split("/")[-1]
            if argv0 and argv0 not in names:
                names.append(argv0)

        exe = str(p_dict.get("exe") or p_dict.get("path") or p_dict.get("exe_path") or "").strip()
        if exe:
            exe_base = exe.replace("\\", "/").split("/")[-1]
            if exe_base and exe_base not in names:
                names.append(exe_base)

        return names

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
            raw_c = str(p_dict.get("child_name") or p_dict.get("name", "")).strip()
            if raw_p and raw_c:
                pairs.append((raw_p, raw_c, raw_p.lower(), raw_c.lower()))

        # 2. From process_list (build pid_map to resolve parent_name from parent_pid)
        pid_map: Dict[Any, Dict[str, Any]] = {}
        for proc in process_list:
            p_dict = (
                proc if isinstance(proc, dict)
                else proc.model_dump() if hasattr(proc, "model_dump")
                else getattr(proc, "__dict__", {})
            )
            pid = p_dict.get("pid")
            if pid is not None:
                pid_map[pid] = p_dict

        for proc in process_list:
            p_dict = (
                proc if isinstance(proc, dict)
                else proc.model_dump() if hasattr(proc, "model_dump")
                else getattr(proc, "__dict__", {})
            )
            child_names = self._extract_proc_names(p_dict)
            if not child_names:
                continue

            parent_names: List[str] = []
            raw_p = str(p_dict.get("parent_name", "")).strip()
            if raw_p:
                parent_names.append(raw_p)

            if "parent_pid" in p_dict:
                parent_proc = pid_map.get(p_dict.get("parent_pid"))
                if parent_proc:
                    for p_n in self._extract_proc_names(parent_proc):
                        if p_n not in parent_names:
                            parent_names.append(p_n)

            for p_n in parent_names:
                for c_n in child_names:
                    pairs.append((p_n, c_n, p_n.lower(), c_n.lower()))

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
            score = ACTION_TO_SCORE.get(highest_action, 40.0) * self.base_score
            return score, f"Process chain anomaly detected: {'; '.join(anomalies)}"

        return 0.0, ""
