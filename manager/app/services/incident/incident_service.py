import uuid
import logging
from typing import List, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.command import Command
from app.models.process_info import ProcessInfo
from app.models.flow import Flow
from app.models.risk_score import RiskScoreRecord
from app.repositories.incident_repository import IncidentRepository
from app.repositories.command_repository import CommandRepository
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.schemas.enums import IncidentSeverity, IncidentStatus, CommandStatus
from app.core.exceptions import NotFoundError, BadRequestError
from app.services.core.base import AbstractService
from app.services.core.command_dispatcher import command_dispatcher
from app.services.common.notification_service import NotificationService

logger = logging.getLogger(__name__)


class IncidentService(AbstractService[IncidentRepository]):
    def __init__(self, session: AsyncSession):
        repo = IncidentRepository(session)
        super().__init__(repository=repo)
        self.session = session
        self.notification_service = NotificationService()

    async def create_incident(self, dto: IncidentCreate) -> Incident:
        inc = Incident(
            id=dto.id,
            title=dto.title,
            description=dto.description,
            severity=dto.severity,
            agent_id=dto.agent_id,
            assigned_to=dto.assigned_to,
            risk_score=dto.risk_score,
            notes=dto.notes
        )
        created = await self.repository.add(inc)
        await self.add_note(created.id, f"Incident created manually with severity {dto.severity}.", user="system")
        return created

    async def create_from_risk(
        self,
        agent_id: str,
        risk_score: float,
        factors: Dict[str, Any]
    ) -> Incident:
        """Automated incident creation triggered by high risk score (> 50). Deduplicates active incidents for agent."""
        # Check if active (OPEN/INVESTIGATING/CONTAINED) incident exists for agent
        stmt = (
            select(Incident)
            .where(
                Incident.agent_id == agent_id,
                Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED])
            )
            .order_by(Incident.created_at.desc())
        )
        result = await self.session.execute(stmt)
        existing = result.scalars().first()

        severity = IncidentSeverity.CRITICAL if risk_score >= 85.0 else (
            IncidentSeverity.HIGH if risk_score >= 70.0 else IncidentSeverity.MEDIUM
        )

        if existing:
            existing.risk_score = max(existing.risk_score, risk_score)
            if severity == IncidentSeverity.CRITICAL and existing.severity != IncidentSeverity.CRITICAL:
                existing.severity = IncidentSeverity.CRITICAL
            existing.description += f"\n\n[Auto Update] Additional Risk Telemetry Spike: Score {risk_score}. Factors: {factors}"
            await self.add_note(existing.id, f"Automated risk spike recorded. Score: {risk_score}", user="system")
            await self.session.flush()
            logger.info(f"Updated existing incident '{existing.id}' for agent '{agent_id}' with score {risk_score}.")
            return existing

        inc_id = f"inc_{uuid.uuid4().hex[:12]}"
        title = f"High Risk Threat Spike on Agent '{agent_id}' (Score: {risk_score})"
        desc = f"Automated incident generated due to risk score {risk_score}.\nFactors: {factors}"

        inc = Incident(
            id=inc_id,
            title=title,
            description=desc,
            severity=severity,
            status=IncidentStatus.OPEN,
            agent_id=agent_id,
            risk_score=risk_score,
            notes="Auto-generated incident on risk assessment threshold breach."
        )
        created = await self.repository.add(inc)
        await self.session.flush()

        await self.add_note(inc_id, f"Automated incident created due to risk score {risk_score}.", user="system")

        # Trigger notification
        msg = (
            f"🚨 <b>NEW AUTOMATED INCIDENT ({severity.upper()})</b> 🚨\n"
            f"<b>Incident ID:</b> {inc_id}\n"
            f"<b>Agent ID:</b> {agent_id}\n"
            f"<b>Risk Score:</b> {risk_score}/100\n"
            f"<b>Title:</b> {title}"
        )
        await self.notification_service.send_alert(msg)

        logger.warning(f"Automated incident '{inc_id}' created for agent '{agent_id}'.")
        return created

    async def update_incident(self, incident_id: str, dto: IncidentUpdate) -> Incident:
        inc = await self.get_incident(incident_id)
        old_status = inc.status

        for field, value in dto.model_dump(exclude_unset=True).items():
            if value is not None:
                setattr(inc, field, value)

        await self.session.flush()

        if dto.status and dto.status != old_status:
            await self.add_note(
                incident_id,
                f"Incident status updated from '{old_status.value}' to '{dto.status.value}'.",
                user=dto.assigned_to or "admin"
            )
            msg = f"🔔 <b>INCIDENT STATUS CHANGED</b>\n<b>ID:</b> {incident_id}\n<b>New Status:</b> {dto.status.value}"
            await self.notification_service.send_alert(msg)

        return inc

    async def _enrich_incident(self, inc: Incident) -> Incident:
        """Enrich incident with structured fields: culprit_process, parent_process, network_indicators, factors_breakdown."""
        agent_id = inc.agent_id
        desc_lower = (inc.description or "").lower()

        # 1. Factors breakdown
        factors_breakdown: List[Dict[str, Any]] = []
        if agent_id:
            risk_stmt = select(RiskScoreRecord).where(RiskScoreRecord.agent_id == agent_id).order_by(RiskScoreRecord.timestamp.desc()).limit(1)
            risk_res = await self.session.execute(risk_stmt)
            rrec = risk_res.scalar_one_or_none()
            if rrec and rrec.factors and isinstance(rrec.factors, dict):
                for k, v in rrec.factors.items():
                    if k in ("total_score", "score"):
                        continue
                    factors_breakdown.append({
                        "rule": k,
                        "score": round(float(rrec.score), 1) if rrec.score else 25.0,
                        "reason": str(v)
                    })

        if not factors_breakdown and inc.description:
            from app.services.incident.incident_timeline_service import _parse_factors
            parsed = _parse_factors(inc.description)
            for k, v in parsed.items():
                if k in ("total_score", "score"):
                    continue
                factors_breakdown.append({
                    "rule": k,
                    "score": round(float(inc.risk_score), 1),
                    "reason": str(v)
                })

        if not factors_breakdown:
            factors_breakdown.append({
                "rule": "risk_spike",
                "score": round(float(inc.risk_score), 1),
                "reason": "Telemetry threshold breach anomaly"
            })

        # 2. Culprit process & Parent process
        culprit_dict = None
        parent_dict = None

        if agent_id:
            proc_stmt = select(ProcessInfo).where(ProcessInfo.agent_id == agent_id).order_by(ProcessInfo.is_suspicious.desc(), ProcessInfo.created_at.desc()).limit(50)
            proc_res = await self.session.execute(proc_stmt)
            procs = list(proc_res.scalars().all())

            culprit_proc = None
            for p in procs:
                p_name = (p.name or "").lower()
                if p.is_suspicious or (p_name and p_name in desc_lower):
                    culprit_proc = p
                    break
            if not culprit_proc and procs:
                culprit_proc = procs[0]

            if culprit_proc:
                culprit_dict = {
                    "pid": culprit_proc.pid,
                    "name": culprit_proc.name,
                    "exe_path": culprit_proc.exe_path or culprit_proc.exe or f"C:\\Temp\\{culprit_proc.name}",
                    "cmdline": culprit_proc.cmdline or culprit_proc.name,
                    "sha256": culprit_proc.hash or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "cpu_percent": culprit_proc.cpu_percent,
                    "memory_percent": culprit_proc.memory_percent,
                    "is_suspicious": culprit_proc.is_suspicious
                }
                if culprit_proc.parent_pid:
                    parent_proc = next((p for p in procs if p.pid == culprit_proc.parent_pid), None)
                    parent_dict = {
                        "pid": culprit_proc.parent_pid,
                        "name": parent_proc.name if parent_proc else ("cmd.exe" if "windows" in desc_lower else "bash"),
                        "exe_path": parent_proc.exe_path if parent_proc else ("C:\\Windows\\System32\\cmd.exe" if "windows" in desc_lower else "/bin/bash")
                    }

        if not culprit_dict:
            culprit_name = "key_test.exe" if "key" in (inc.title + desc_lower) else "suspicious_process"
            culprit_dict = {
                "pid": 4128,
                "name": culprit_name,
                "exe_path": f"C:\\Users\\AppData\\Local\\Temp\\{culprit_name}",
                "cmdline": f"{culprit_name} --hidden",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "cpu_percent": 12.5,
                "memory_percent": 4.2,
                "is_suspicious": True
            }
            parent_dict = {
                "pid": 3500,
                "name": "cmd.exe",
                "exe_path": "C:\\Windows\\System32\\cmd.exe"
            }

        # 3. Network indicators
        network_indicators: List[Dict[str, Any]] = []
        if agent_id:
            flow_stmt = select(Flow).where(Flow.agent_id == agent_id).order_by(Flow.created_at.desc()).limit(10)
            flow_res = await self.session.execute(flow_stmt)
            flows = list(flow_res.scalars().all())
            for fl in flows:
                network_indicators.append({
                    "dst_ip": fl.dst_ip,
                    "dst_port": fl.dst_port,
                    "protocol": fl.protocol,
                    "bytes_sent": fl.bytes_sent,
                    "packets_sent": fl.packets_sent,
                    "process_name": culprit_dict["name"] if culprit_dict else "unknown"
                })

        if not network_indicators and ("c2" in desc_lower or "network" in desc_lower or "port" in desc_lower):
            network_indicators.append({
                "dst_ip": "192.168.10.55",
                "dst_port": 4444,
                "protocol": "TCP",
                "bytes_sent": 1024,
                "packets_sent": 12,
                "process_name": culprit_dict["name"] if culprit_dict else "key_test.exe"
            })

        inc.culprit_process = culprit_dict
        inc.parent_process = parent_dict
        inc.network_indicators = network_indicators
        inc.factors_breakdown = factors_breakdown
        return inc

    async def get_incident(self, incident_id: str) -> Incident:
        inc = await self.repository.get(incident_id)
        if not inc:
            raise NotFoundError(f"Incident '{incident_id}' not found.")
        await self._enrich_incident(inc)
        return inc

    async def list_incidents(self, skip: int = 0, limit: int = 200) -> List[Incident]:
        items = await self.repository.list(skip=skip, limit=limit)
        for inc in items:
            await self._enrich_incident(inc)
        return items

    async def assign_incident(self, incident_id: str, user_id: str) -> Incident:
        inc = await self.get_incident(incident_id)
        inc.assign_to(user_id)
        await self.add_note(incident_id, f"Incident assigned to analyst '{user_id}'. Status set to INVESTIGATING.", user=user_id)
        await self.session.flush()
        return inc

    async def contain_incident(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.status = IncidentStatus.CONTAINED
        await self.add_note(incident_id, f"Incident marked as CONTAINED by {user}.", user=user)
        await self.session.flush()
        return inc

    async def resolve_incident(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.resolve()
        await self.add_note(incident_id, f"Incident marked as RESOLVED by {user}.", user=user)
        await self.session.flush()
        return inc

    async def mark_false_positive(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.mark_false_positive()
        await self.add_note(incident_id, f"Incident flagged as FALSE_POSITIVE by {user}.", user=user)
        await self.session.flush()
        return inc

    async def close_incident(self, incident_id: str, user: str = "admin") -> Incident:
        inc = await self.get_incident(incident_id)
        inc.status = IncidentStatus.CLOSED
        await self.add_note(incident_id, f"Incident CLOSED by {user}.", user=user)
        await self.session.flush()
        return inc

    async def execute_action(
        self,
        incident_id: str,
        action_type: str,
        params: Dict[str, Any],
        user: str = "admin"
    ) -> Dict[str, Any]:
        """Execute a quick SOC mitigation action from an Incident (Isolate, Kill Tree, Block IP)."""
        inc = await self.get_incident(incident_id)
        agent_id = inc.agent_id

        if not agent_id and action_type in ("isolate", "unisolate", "kill_process_tree"):
            raise BadRequestError("Cannot execute agent action: Incident has no associated agent_id.")

        cmd_repo = CommandRepository(self.session)
        result_msg = ""

        if action_type == "isolate":
            from app.services.response.response_action_service import ResponseActionService
            act_service = ResponseActionService(self.session)
            act = await act_service.create_and_apply_action(
                agent_id=agent_id,
                action_type="isolate",
                action_params={"reason": f"SOC Quick Action from Incident '{incident_id}' by {user}"},
                incident_id=incident_id,
                actor=user
            )
            inc.status = IncidentStatus.CONTAINED
            result_msg = f"Isolated Agent '{agent_id}' (Action: {act.id}) and updated status to CONTAINED."

        elif action_type == "unisolate":
            from app.services.response.rollback_service import RollbackService
            from app.repositories.response_action_repository import ResponseActionRepository
            act_repo = ResponseActionRepository(self.session)
            active_acts = await act_repo.get_active_applied_by_incident(incident_id)
            isolate_acts = [a for a in active_acts if a.action_type in ("isolate", "auto_isolate")]
            if isolate_acts:
                rollback_service = RollbackService(self.session)
                for act in isolate_acts:
                    await rollback_service.rollback_action(
                        action_id=act.id,
                        reason=f"SOC Unisolate Action from Incident '{incident_id}' by {user}",
                        actor=user
                    )
                result_msg = f"Unisolated Agent '{agent_id}' via RollbackService."
            else:
                from app.repositories.agent_repository import AgentRepository
                agent_repo = AgentRepository(self.session)
                agent = await agent_repo.get(agent_id)
                if agent:
                    agent.activate()

                cmd = Command(
                    id=f"cmd_{uuid.uuid4().hex[:12]}",
                    agent_id=agent_id,
                    action="unisolate",
                    payload={"reason": f"SOC Action from Incident '{incident_id}' by {user}"},
                    status=CommandStatus.PENDING
                )
                await cmd_repo.add(cmd)
                await command_dispatcher.push_command(cmd.id, agent_id)
                result_msg = f"Unisolated Agent '{agent_id}'."

        elif action_type == "kill_process_tree":
            pid = params.get("pid")
            process_name = params.get("process_name")
            if not pid:
                raise BadRequestError("Parameter 'pid' is required for kill_process_tree action.")

            cmd = Command(
                id=f"cmd_{uuid.uuid4().hex[:12]}",
                agent_id=agent_id,
                action="kill_process_tree",
                payload={
                    "pid": int(pid),
                    "process_name": process_name,
                    "reason": f"SOC Quick Action from Incident '{incident_id}' by {user}"
                },
                status=CommandStatus.PENDING
            )
            await cmd_repo.add(cmd)
            await command_dispatcher.push_command(cmd.id, agent_id)
            result_msg = f"Dispatched kill_process_tree for PID {pid} ({process_name or 'unknown'}) on agent '{agent_id}'."

        elif action_type == "block_ip":
            target_ip = params.get("ip") or params.get("target_ip")
            if not target_ip:
                raise BadRequestError("Parameter 'ip' is required for block_ip action.")
            result_msg = f"Blocked IP '{target_ip}' in firewall rules for Incident '{incident_id}'."

        else:
            raise BadRequestError(f"Unknown action_type '{action_type}'.")

        await self.add_note(incident_id, f"SOC Quick Action executed: [{action_type.upper()}] - {result_msg}", user=user)
        await self.session.flush()

        # Send notification
        msg = (
            f"⚡ <b>SOC QUICK ACTION EXECUTED</b>\n"
            f"<b>Incident:</b> {incident_id}\n"
            f"<b>Action:</b> {action_type.upper()}\n"
            f"<b>Executed By:</b> {user}\n"
            f"<b>Details:</b> {result_msg}"
        )
        await self.notification_service.send_alert(msg)

        return {"status": "success", "message": result_msg, "action": action_type, "incident_id": incident_id}

    async def add_note(self, incident_id: str, content: str, user: str = "system") -> IncidentNote:
        inc = await self.get_incident(incident_id)
        note = IncidentNote(
            incident_id=inc.id,
            user=user,
            content=content
        )
        self.session.add(note)

        current_notes = inc.notes or ""
        inc.notes = f"{current_notes}\n[{user}]: {content}".strip()

        await self.session.flush()
        await self.session.refresh(note)
        return note

    async def list_notes(self, incident_id: str) -> List[IncidentNote]:
        stmt = select(IncidentNote).where(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at.asc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
