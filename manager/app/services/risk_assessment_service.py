import uuid
import logging
from typing import Dict, Any, Tuple, Union
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
from app.services.command_dispatcher import command_dispatcher

logger = logging.getLogger(__name__)


class RiskAssessmentService:
    """
    Intelligent dynamic risk assessment service (Strategy Pattern).
    Evaluates multi-factor telemetry risk scores, threat intelligence indicators,
    whitelist rules, and executes automated isolation, incident creation, & notification workflows.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.risk_repo = RiskScoreRepository(session)
        self.agent_repo = AgentRepository(session)
        self.whitelist_service = WhitelistService(session)
        self.notification_service = NotificationService(session)
        self.threat_intel_service = ThreatIntelligenceService(session)
        self.setting_service = SettingService(session)

    async def evaluate(
        self, agent_id: str, data: Union[RiskAssessmentDTO, Dict[str, Any]]
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Evaluate composite risk score (0 - 100) based on telemetry factors:
        - CPU Spikes
        - Unlisted / Suspicious processes
        - Threat Intelligence Indicators (Hashes, malicious IPs)
        - High risk network connections
        - File system modification count
        """
        if isinstance(data, RiskAssessmentDTO):
            cpu = data.cpu_usage
            processes = data.process_list
            connections = data.network_connections
            file_changes = data.file_changes_count
        else:
            cpu = data.get("cpu_usage", 0.0)
            processes = data.get("process_list", [])
            connections = data.get("network_connections", [])
            file_changes = data.get("file_changes_count", 0)

        score = 0.0
        factors: Dict[str, Any] = {}

        # 1. CPU Usage Evaluation
        if cpu > 85.0:
            score += 30.0
            factors["cpu"] = f"Critical CPU spike ({cpu}%)"
        elif cpu > 70.0:
            score += 15.0
            factors["cpu"] = f"Elevated CPU usage ({cpu}%)"

        # 2. Suspicious Process & Threat Intel Hash Evaluation
        suspicious_proc_count = 0
        threat_hash_count = 0
        proc_names = []
        for proc in processes:
            name = proc.get("name", "") if isinstance(proc, dict) else getattr(proc, "name", "")
            p_hash = proc.get("hash") if isinstance(proc, dict) else getattr(proc, "hash", None)

            if proc.get("is_suspicious") or name.lower() in ["mimikatz.exe", "netcat", "nc.exe", "nmap", "chisel"]:
                suspicious_proc_count += 1
                proc_names.append(name)

            if p_hash:
                intel_res = await self.threat_intel_service.check_hash(p_hash)
                if intel_res.get("is_malicious"):
                    threat_hash_count += 1

        if suspicious_proc_count > 0:
            score += min(45.0, suspicious_proc_count * 25.0)
            factors["processes"] = f"Found {suspicious_proc_count} suspicious processes: {', '.join(proc_names)}"

        if threat_hash_count > 0:
            score += 40.0
            factors["threat_intel_hash"] = f"Matched {threat_hash_count} malicious file hashes with Threat Intelligence"

        # 3. Network Connections & Threat Intel IP Evaluation
        suspicious_ports = {4444, 1337, 31337, 6667, 23}
        suspicious_conns = 0
        threat_ip_count = 0

        for conn in connections:
            dst_port = conn.get("dst_port", 0) if isinstance(conn, dict) else getattr(conn, "dst_port", 0)
            dst_ip = conn.get("dst_ip") if isinstance(conn, dict) else getattr(conn, "dst_ip", None)

            if dst_port in suspicious_ports:
                suspicious_conns += 1

            if dst_ip:
                ip_intel = await self.threat_intel_service.check_ip(dst_ip)
                if ip_intel.get("is_malicious"):
                    threat_ip_count += 1

        if suspicious_conns > 0:
            score += min(35.0, suspicious_conns * 20.0)
            factors["network"] = f"Detected {suspicious_conns} connections to suspicious ports"

        if threat_ip_count > 0:
            score += 30.0
            factors["threat_intel_ip"] = f"Detected {threat_ip_count} connections to malicious IPs"

        # 4. File Changes Evaluation
        if file_changes > 100:
            score += 25.0
            factors["file_changes"] = f"Massive file modifications count ({file_changes})"
        elif file_changes > 30:
            score += 10.0
            factors["file_changes"] = f"Elevated file modifications count ({file_changes})"

        final_score = min(100.0, round(score, 2))
        factors["total_score"] = final_score
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

        if action == "auto_isolate":
            logger.warning(f"High risk score ({score}) for agent '{agent_id}'. Triggering auto-isolation!")
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

            # Automated Incident Creation
            incident_service = IncidentService(self.session)
            inc = await incident_service.create_from_risk(agent_id, score, factors)

            # Send critical Telegram notification
            msg = (
                f"🚨 <b>CRITICAL RISK ALERT</b> 🚨\n"
                f"<b>Agent ID:</b> {agent_id}\n"
                f"<b>Hostname:</b> {agent.hostname}\n"
                f"<b>Risk Score:</b> {score}/100\n"
                f"<b>Incident Created:</b> {inc.id}\n"
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
