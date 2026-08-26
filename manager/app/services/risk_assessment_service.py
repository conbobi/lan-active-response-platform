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


class RiskAssessmentService:
    """
    Intelligent dynamic risk assessment service using Registry Pattern and Strategy Pattern.
    Evaluates composite telemetry risk scores across 13 security risk rules, whitelist rules,
    and executes automated network isolation, incident creation, and notifications.
    """

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
        Evaluate composite risk score (0 - 100) using dynamic rules in RiskRuleRegistry.
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

        score = 0.0
        factors: Dict[str, Any] = {}

        # Evaluate each enabled rule in registry
        for rule in self.registry.get_enabled_rules():
            try:
                rule_score, reason = await rule.evaluate(telemetry, context)
                if rule_score > 0:
                    weighted_score = rule_score * getattr(rule, "weight", 1.0)
                    score += weighted_score
                    factors[rule.rule_id] = reason
                    logger.info(f"[EVALUATE] Agent {agent_id} - Rule {rule.rule_id}: score={rule_score}, weighted={weighted_score}")
            except Exception as exc:
                logger.error(f"Error evaluating rule '{rule.rule_id}' for agent {agent_id}: {exc}", exc_info=True)

        final_score = min(100.0, round(score, 2))
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
        Process assessment, store record, check whitelist, and execute auto-isolation, incident creation, & alert.
        """
        score, factors = await self.evaluate(agent_id, data)
        action = await self.determine_action(score)

        record = RiskScoreRecord(
            id=f"risk_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            score=score,
            factors=factors
        )
        await self.risk_repo.add(record)

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

        # 1. Automated Incident Creation if score >= incident_creation_threshold
        if score >= incident_creation_th:
            incident_service = IncidentService(self.session)
            inc = await incident_service.create_from_risk(agent_id, score, factors)
            logger.info(f"Automated incident '{inc.id}' evaluated for agent '{agent_id}' (score: {score} >= threshold: {incident_creation_th})")

        # 2. Automated Process Tree Termination if score >= auto_kill_threshold
        if score >= auto_kill_th and not is_whitelisted:
            logger.warning(
                f"High risk score ({score} >= {auto_kill_th}) for agent '{agent_id}'. "
                f"Triggering Automated Process Tree Termination!"
            )
            cmd_repo = CommandRepository(self.session)
            suspicious_procs = []
            
            suspect_keywords = [
                "nc", "netcat", "mimikatz", "nmap", "chisel", "psexec", "procdump",
                "ransomware_sim", "backdoor_sim", "credential_dump", "sleep", "shadow"
            ]
            
            for proc in processes:
                p_dict = proc if isinstance(proc, dict) else proc.model_dump() if hasattr(proc, "model_dump") else getattr(proc, "__dict__", {})
                is_susp = p_dict.get("is_suspicious", False)
                name = str(p_dict.get("name", "")).strip().lower()
                cmdline = str(p_dict.get("cmdline", "")).strip().lower()
                full_str = f"{name} {cmdline}"
                
                if is_susp or any(k in full_str for k in suspect_keywords):
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
                        "reason": f"Automated Process Tree Kill triggered by Risk Score {score} (threshold: {auto_kill_th})"
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
                    f"<b>Risk Score:</b> {score}/100 (Threshold: {auto_kill_th})\n"
                    f"<b>Terminated Process Trees:</b> {', '.join(killed_details)}"
                )
                await self.notification_service.send_alert(msg)

        # 3. Network Auto-Isolation
        if action == "auto_isolate":
            logger.warning(f"Critical risk score ({score}) for agent '{agent_id}'. Triggering auto-isolation!")
            agent.isolate()

            # Create isolate command
            cmd_repo = CommandRepository(self.session)
            cmd = Command(
                id=f"cmd_{uuid.uuid4().hex[:12]}",
                agent_id=agent_id,
                action="isolate",
                payload={"reason": f"Auto isolation triggered by Risk Assessment Score {score}"},
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)

            # Send critical Telegram notification
            msg = (
                f"🚨 <b>CRITICAL RISK ALERT</b> 🚨\n"
                f"<b>Agent ID:</b> {agent_id}\n"
                f"<b>Hostname:</b> {agent.hostname}\n"
                f"<b>Risk Score:</b> {score}/100\n"
                f"<b>Action:</b> 🛡️ Automated Network Isolation Executed\n"
                f"<b>Factors:</b> {factors}"
            )
            await self.notification_service.send_alert(msg)

        elif action == "alert_with_buttons":
            msg = (
                f"⚠️ <b>HIGH RISK DETECTED</b> ⚠️\n"
                f"<b>Agent ID:</b> {agent_id}\n"
                f"<b>Hostname:</b> {agent.hostname}\n"
                f"<b>Risk Score:</b> {score}/100\n"
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
                f"<b>Risk Score:</b> {score}/100"
            )
            await self.notification_service.send_alert(msg)

        await self.session.flush()
        return record
