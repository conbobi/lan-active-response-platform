import re
import uuid
import logging
from typing import Dict, Any, Tuple, Union, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.risk_score import RiskScoreRecord
from app.models.command import Command
from app.schemas.risk import RiskAssessmentDTO
from app.schemas.enums import CommandStatus
from app.repositories.risk_score_repository import RiskScoreRepository
from app.repositories.agent_repository import AgentRepository
from app.repositories.command_repository import CommandRepository
from app.services.whitelist_service import WhitelistService
from app.services.notification_service import NotificationService
from app.services.threat_intelligence_service import ThreatIntelligenceService
from app.services.incident_service import IncidentService
from app.services.setting_service import SettingService
from app.services.detection_rule_service import DetectionRuleService
from app.services.risk_rules import create_default_registry, RiskRuleRegistry
from app.services.command_dispatcher import command_dispatcher

logger = logging.getLogger(__name__)


# ===== EMA (Exponential Moving Average) =====
EMA_ALPHA = 0.35             # Hệ số làm mượt
DEBOUNCE_MIN_CYCLES = 2      # Số chu kỳ liên tiếp tối thiểu
DEBOUNCE_PENALTY = 0.3       # Hệ số phạt nếu chưa đủ chu kỳ

# ===== Anomaly Category Cap =====
ANOMALY_RULES = {
    "ml_behavioral_anomaly",
    "cpu_spike",
    "ram_spike",
    "disk_spike",
    "network_volume_spike",
}
IOC_RULES = {
    "yara_match",
    "suspicious_process",
    "c2_communication",
    "credential_dumping",
    "threat_intel_match",
    "http_beaconing",
    "dns_tunneling",
}
ANOMALY_CAP = 35.0


def compute_ema(current: float, previous: Optional[float], alpha: float = EMA_ALPHA) -> float:
    """Tính EMA cho risk score.

    Args:
        current: Điểm raw vừa tính.
        previous: Điểm smoothed của chu kỳ trước (None nếu lần đầu).
        alpha: Hệ số làm mượt (0.35 = cân bằng giữa phản ứng và mượt).

    Returns:
        Điểm đã làm mượt.
    """
    if previous is None or not isinstance(previous, (int, float)):
        return round(float(current), 2)
    return round(alpha * current + (1 - alpha) * previous, 2)


def apply_debounce(
    raw_score: float,
    consecutive_hits: int,
    min_cycles: int = DEBOUNCE_MIN_CYCLES,
    penalty: float = DEBOUNCE_PENALTY,
) -> float:
    """Giảm điểm nếu rule chưa kích hoạt đủ số chu kỳ liên tiếp."""
    if consecutive_hits >= min_cycles:
        return raw_score
    return round(raw_score * penalty, 2)


def apply_category_cap(factors: Dict[str, Any]) -> float:
    """Tính tổng điểm sau khi áp dụng cap cho nhóm anomaly.

    - Nếu có bất kỳ IOC rule nào kích hoạt → KHÔNG cap.
    - Nếu chỉ có anomaly rules → cap tổng anomaly ở 35.
    """
    numeric_scores = {
        k: float(v) for k, v in factors.items()
        if k != "total_score" and isinstance(v, (int, float))
    }
    has_ioc = any(rule in numeric_scores and numeric_scores[rule] > 0 for rule in IOC_RULES)

    if has_ioc:
        return round(sum(numeric_scores.values()), 2)

    anomaly_sum = sum(v for k, v in numeric_scores.items() if k in ANOMALY_RULES)
    other_sum = sum(v for k, v in numeric_scores.items() if k not in ANOMALY_RULES)

    capped_anomaly = min(anomaly_sum, ANOMALY_CAP)
    return round(other_sum + capped_anomaly, 2)


class RiskAssessmentService:
    """
    Intelligent dynamic risk assessment service using Registry Pattern and Strategy Pattern.
    Evaluates composite telemetry risk scores across 13 security risk rules, whitelist rules,
    applies EMA smoothing and debounce, and executes automated network isolation, incident creation, and notifications.
    """

    # In-memory debounce counter across cycles: {agent_id: {rule_id: consecutive_count}}
    _rule_hit_counter: Dict[str, Dict[str, int]] = {}

    @classmethod
    def cleanup_agent(cls, agent_id: str) -> None:
        """Cleanup debounce counters when an agent disconnects."""
        cls._rule_hit_counter.pop(agent_id, None)

    def __init__(self, session: AsyncSession, registry: Optional[RiskRuleRegistry] = None):
        self.session = session
        self.risk_repo = RiskScoreRepository(session)
        self.agent_repo = AgentRepository(session)
        self.whitelist_service = WhitelistService(session)
        self.notification_service = NotificationService(session)
        self.threat_intel_service = ThreatIntelligenceService(session)
        self.setting_service = SettingService(session)
        self.detection_rule_service = DetectionRuleService(session)
        self.registry = registry if registry is not None else create_default_registry()

    async def evaluate(
        self, agent_id: str, data: Union[RiskAssessmentDTO, Dict[str, Any]]
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Evaluate composite risk score (0 - 100) using dynamic rules in RiskRuleRegistry,
        applying debounce to anomaly rules and category capping.
        """
        # Convert incoming data to standard telemetry dict
        if isinstance(data, RiskAssessmentDTO):
            telemetry = data.model_dump()
        elif isinstance(data, dict):
            try:
                dto = RiskAssessmentDTO.model_validate(data)
                telemetry = dto.model_dump()
            except Exception:
                telemetry = data
        else:
            telemetry = getattr(data, "__dict__", {})

        # Log telemetry trước khi evaluate
        logger.info(f"[EVALUATE] Agent {agent_id} - CPU: {telemetry.get('cpu_usage')}, "
                    f"RAM: {telemetry.get('ram_usage')}, "
                    f"processes: {len(telemetry.get('process_list', []))}, "
                    f"file_changes: {telemetry.get('file_changes_count', 0)}")

        # Try to sync rule configurations from database
        try:
            await self.detection_rule_service.sync_registry(self.registry)
        except Exception as e:
            logger.debug(f"Risk rule DB sync skipped/failed: {e}")

        context = {
            "threat_intel_service": self.threat_intel_service,
            "whitelist_service": self.whitelist_service,
            "setting_service": self.setting_service,
            "session": self.session,
            "agent_id": agent_id,
        }

        rule_scores: Dict[str, float] = {}
        factors: Dict[str, Any] = {}
        agent_counters = self._rule_hit_counter.setdefault(agent_id, {})

        # Evaluate each enabled rule in registry
        for rule in self.registry.get_enabled_rules():
            try:
                rule_score, reason = await rule.evaluate(telemetry, context)
                if rule_score > 0:
                    # Apply debounce if rule belongs to anomaly/behavioral category
                    if rule.rule_id in ANOMALY_RULES:
                        agent_counters[rule.rule_id] = agent_counters.get(rule.rule_id, 0) + 1
                        debounced_score = apply_debounce(rule_score, agent_counters[rule.rule_id])
                    else:
                        debounced_score = rule_score

                    weighted_score = debounced_score * getattr(rule, "weight", 1.0)
                    rule_scores[rule.rule_id] = weighted_score
                    factors[rule.rule_id] = reason
                    logger.info(f"[EVALUATE] Agent {agent_id} - Rule {rule.rule_id}: raw={rule_score}, debounced={debounced_score}, weighted={weighted_score}")
                else:
                    agent_counters.pop(rule.rule_id, None)
            except Exception as exc:
                logger.error(f"Error evaluating rule '{rule.rule_id}' for agent {agent_id}: {exc}", exc_info=True)

        final_score = min(100.0, apply_category_cap(rule_scores))
        factors["total_score"] = final_score
        logger.info(f"[EVALUATE] Agent {agent_id} - Final score: {final_score}")
        return final_score, factors

    async def determine_action(self, score: float) -> str:
        """
        Determine action strategy based on dynamic system risk thresholds:
        - < log: log
        - log - alert_with_buttons: alert
        - alert_with_buttons - auto_isolate: alert_with_buttons
        - >= auto_isolate: auto_isolate
        """
        thresholds = await self.setting_service.get_risk_thresholds()
        auto_isolate_th = thresholds.get("auto_isolate", 80.0)
        buttons_th = thresholds.get("alert_with_buttons", 60.0)
        alert_th = thresholds.get("alert", 30.0)

        if score >= auto_isolate_th:
            return "auto_isolate"
        elif score >= buttons_th:
            return "alert_with_buttons"
        elif score >= alert_th:
            return "alert"
        return "log"

    async def process_risk(
        self,
        agent_id: str,
        data: Union[RiskAssessmentDTO, Dict[str, Any]]
    ) -> RiskScoreRecord:
        """
        Process assessment, calculate raw + smoothed score via EMA, store record, check whitelist,
        and execute auto-isolation, incident creation, & alert based on smoothed score.
        """
        raw_score, factors = await self.evaluate(agent_id, data)

        # 2. Lấy smoothed_score gần nhất từ DB (hỗ trợ cả mock trong unit test)
        latest = None
        if hasattr(self.risk_repo, "get_latest_by_agent"):
            try:
                import inspect
                call_res = self.risk_repo.get_latest_by_agent(agent_id, limit=1)
                if inspect.isawaitable(call_res):
                    latest = await call_res
                elif isinstance(call_res, list):
                    latest = call_res
            except Exception as e:
                logger.debug(f"Could not fetch previous risk record: {e}")

        prev_record = latest[0] if (latest and isinstance(latest, list)) else latest
        prev_smoothed = getattr(prev_record, "smoothed_score", None) if prev_record else None
        if (prev_smoothed is None or not isinstance(prev_smoothed, (int, float))) and prev_record:
            prev_smoothed = getattr(prev_record, "score", None)
        if not isinstance(prev_smoothed, (int, float)):
            prev_smoothed = None

        # 3. Áp dụng EMA
        smoothed = compute_ema(raw_score, prev_smoothed)

        # 4. Lưu cả raw + smoothed + factors
        record = RiskScoreRecord(
            id=f"risk_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            score=raw_score,
            smoothed_score=smoothed,
            factors=factors
        )
        if hasattr(self.risk_repo, "add"):
            import inspect
            res_add = self.risk_repo.add(record)
            if inspect.isawaitable(res_add):
                await res_add

        # 5. Phản ứng tự động dựa trên smoothed score
        action = await self.determine_action(smoothed)

        agent = await self.agent_repo.get(agent_id)
        if not agent:
            logger.warning(f"Risk processed for non-existent agent '{agent_id}'.")
            return record

        # Check whitelist before taking aggressive actions
        is_whitelisted = False
        processes = data.process_list if isinstance(data, RiskAssessmentDTO) else data.get("process_list", [])
        for proc in processes:
            pname = proc.get("name") if isinstance(proc, dict) else getattr(proc, "name", None)
            ppath = proc.get("path") if isinstance(proc, dict) else getattr(proc, "path", None)
            if await self.whitelist_service.is_whitelisted(agent_id=agent_id, process_name=pname, path=ppath):
                is_whitelisted = True
                break

        if is_whitelisted:
            logger.info(f"Agent '{agent_id}' process matched Whitelist. Auto-isolation suppressed.")
            return record

        # Fetch thresholds
        thresholds = await self.setting_service.get_risk_thresholds()
        incident_creation_th = thresholds.get("incident_creation_threshold", 50.0)
        auto_kill_th = thresholds.get("auto_kill_threshold", 85.0)

        # 1. Automated Incident Creation if smoothed >= incident_creation_threshold
        if smoothed >= incident_creation_th:
            incident_service = IncidentService(self.session)
            inc = await incident_service.create_from_risk(agent_id, smoothed, factors)
            logger.info(f"Automated incident '{inc.id}' evaluated for agent '{agent_id}' (score: {smoothed} >= threshold: {incident_creation_th})")

        # 2. Automated Process Tree Termination if smoothed >= auto_kill_threshold
        if smoothed >= auto_kill_th and not is_whitelisted:
            logger.warning(
                f"High risk score ({smoothed} >= {auto_kill_th}) for agent '{agent_id}'. "
                f"Triggering Automated Process Tree Termination!"
            )
            cmd_repo = CommandRepository(self.session)
            suspicious_procs = []
            
            suspect_keywords = [
                "mimikatz", "nmap", "chisel", "psexec", "procdump",
                "ransomware_sim", "backdoor_sim", "credential_dump", "lazagne",
                "vssadmin", "meterpreter", "cobaltstrike"
            ]
            
            for proc in processes:
                p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
                is_susp = p_dict.get("is_suspicious", False)
                name = str(p_dict.get("name", "")).strip().lower()
                cmdline = str(p_dict.get("cmdline", "")).strip().lower()
                full_str = f"{name} {cmdline}"
                
                matches_suspect = any(k in full_str for k in suspect_keywords) or bool(re.search(r"(?:\A|[^a-zA-Z0-9_\-\.])(?:nc|ncat|netcat)(?:\.exe)?(?:\Z|[^a-zA-Z0-9_\-\.])", full_str))
                if is_susp or matches_suspect:
                    pid = p_dict.get("pid")
                    p_name = p_dict.get("name") or name or "suspicious_process"
                    if pid and not any(sp["pid"] == pid for sp in suspicious_procs):
                        suspicious_procs.append({"pid": pid, "name": p_name, "cmdline": cmdline})

            killed_details = []
            for sproc in suspicious_procs:
                kill_cmd = Command(
                    id=f"cmd_{uuid.uuid4().hex[:12]}",
                    agent_id=agent_id,
                    action="kill_process_tree",
                    payload={
                        "pid": sproc["pid"],
                        "process_name": sproc["name"],
                        "reason": f"Automated Process Tree Kill triggered by Risk Score {smoothed} (threshold: {auto_kill_th})"
                    },
                    status=CommandStatus.PENDING
                )
                await cmd_repo.add(kill_cmd)
                await command_dispatcher.push_command(kill_cmd.id, agent_id)
                killed_details.append(f"PID {sproc['pid']} ({sproc['name']})")
                logger.info(f"Dispatched kill_process_tree for PID {sproc['pid']} ({sproc['name']}) on agent '{agent_id}'")

            if killed_details:
                msg = (
                    f"⚔️ <b>AUTOMATED PROCESS TREE KILLED</b> ⚔️\n"
                    f"<b>Agent ID:</b> {agent_id}\n"
                    f"<b>Risk Score:</b> {smoothed}/100 (Threshold: {auto_kill_th})\n"
                    f"<b>Terminated Process Trees:</b> {', '.join(killed_details)}"
                )
                await self.notification_service.send_alert(msg)

        # 3. Policy-Based Automated Response (Policy Engine v1.4)
        policy_executed = False
        try:
            from app.services.policy_engine_service import PolicyEngineService
            policy_engine = PolicyEngineService(self.session)
            policy_res = await policy_engine.evaluate_and_execute(
                agent_id=agent_id,
                risk_score=smoothed,
                context=factors,
                dry_run=False
            )
            if policy_res and policy_res.matched_policy and policy_res.executed:
                policy_executed = True
                logger.info(
                    f"PolicyEngine successfully executed '{policy_res.action_type}' "
                    f"with scope '{policy_res.scope}' for agent '{agent_id}' (policy: {policy_res.matched_policy.name})"
                )
        except Exception as pe_exc:
            logger.error(f"Error in PolicyEngine execution for agent '{agent_id}': {pe_exc}", exc_info=True)

        # 4. Fallback legacy action trigger if no policy was executed
        if not policy_executed:
            if action == "auto_isolate":
                logger.warning(f"Critical risk score ({smoothed}) for agent '{agent_id}'. Triggering fallback auto-isolation!")
                agent.isolate()

                # Create isolate command
                cmd_repo = CommandRepository(self.session)
                cmd = Command(
                    id=f"cmd_{uuid.uuid4().hex[:12]}",
                    agent_id=agent_id,
                    action="isolate",
                    payload={"reason": f"Auto isolation triggered by Risk Assessment Score {smoothed}"},
                    status=CommandStatus.PENDING
                )
                await cmd_repo.add(cmd)
                await command_dispatcher.push_command(cmd.id, agent_id)

                # Send critical Telegram notification
                msg = (
                    f"🚨 <b>CRITICAL RISK ALERT</b> 🚨\n"
                    f"<b>Agent ID:</b> {agent_id}\n"
                    f"<b>Hostname:</b> {agent.hostname}\n"
                    f"<b>Risk Score:</b> {smoothed}/100\n"
                    f"<b>Action:</b> 🛡️ Automated Network Isolation Executed\n"
                    f"<b>Factors:</b> {factors}"
                )
                await self.notification_service.send_alert(msg)

            elif action == "alert_with_buttons":
                msg = (
                    f"⚠️ <b>HIGH RISK DETECTED</b> ⚠️\n"
                    f"<b>Agent ID:</b> {agent_id}\n"
                    f"<b>Hostname:</b> {agent.hostname}\n"
                    f"<b>Risk Score:</b> {smoothed}/100\n"
                    f"<b>Action Required:</b> Manual review or isolation recommended."
                )
                buttons = [
                    [
                        {"text": "🔒 Cô lập ngay", "callback_data": f"isolate:{agent_id}"},
                        {"text": "❌ Bỏ qua", "callback_data": f"ignore:{agent_id}"}
                    ]
                ]
                await self.notification_service.send_alert(msg, buttons=buttons)

            elif action == "alert":
                msg = (
                    f"⚡ <b>MODERATE RISK ALERT</b> ⚡\n"
                    f"<b>Agent ID:</b> {agent_id}\n"
                    f"<b>Risk Score:</b> {smoothed}/100"
                )
                await self.notification_service.send_alert(msg)

        await self.session.flush()
        return record
