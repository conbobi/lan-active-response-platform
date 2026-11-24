import uuid
import hashlib
import json
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.agent import Agent
from app.services.agent.activity import attach_incident_activity
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
from app.services.detection.network_reputation_service import NetworkReputationService

logger = logging.getLogger(__name__)


SYSTEM_AND_KERNEL_EXCLUSIONS = {
    "kthreadd", "kworker", "rcu", "swapper",
    "migration", "ksoftirqd", "psimon", "cpuhp", "kdevtmpfs", "kauditd",
    "khungtaskd", "oom_reaper", "kblockd", "scsi_eh", "scsi_tmf",
    "jbd2", "irq/", "card1-crtc", "watchdog",
    # Desktop environment daemons (tránh attribution sai và DoS desktop)
    "lightdm", "xorg", "xfce4-session", "xfce4-panel", "thunar", "systemd",
    "dbus-daemon", "xfwm4", "pulseaudio"
}


def is_eligible_culprit(proc: Optional[ProcessInfo]) -> bool:
    """Xác thực process có đủ điều kiện làm culprit không — loại trừ tuyệt đối kernel threads và system desktop daemons."""
    if not proc or proc.pid is None:
        return False
    if proc.pid in (0, 1, 2):
        return False
    # Trong Linux, bất kỳ tiến trình nào có parent là kthreadd (PID 2) đều là kernel thread
    if getattr(proc, "parent_pid", None) == 2:
        return False

    exe = (getattr(proc, "exe_path", None) or getattr(proc, "exe", None) or "").strip()
    cmd = (getattr(proc, "cmdline", None) or "").strip()
    p_name = (proc.name or "").lower()

    # Kernel thread không có file thực thi (exe) và không có cmdline người dùng
    if not exe and (not cmd or cmd == f"[{p_name}]" or cmd == p_name):
        return False

    # Các tiền tố thread nhân Linux phổ biến
    if p_name.startswith(("scsi_", "kworker", "rcu", "migration", "cpuhp", "jbd2", "ext4", "watchdog", "card", "irq/")):
        return False

    if any(k in p_name for k in SYSTEM_AND_KERNEL_EXCLUSIONS):
        return False

    return True


async def _safe_trigger_ai_triage(incident_id: str):
    """Background task: Chạy AI triage an toàn với sleep 0.8s và retry loop để đảm bảo transaction đã commit."""
    import asyncio
    from app.core.database import AsyncSessionLocal
    from app.services.ai.ai_triage_service import AITriageService

    logger.info(f"Triggering AI Triage for incident {incident_id}")
    await asyncio.sleep(0.8)

    for attempt in range(1, 4):
        try:
            async with AsyncSessionLocal() as session:
                inc = await session.get(Incident, incident_id)
                if not inc:
                    if attempt < 3:
                        logger.warning(
                            f"Incident {incident_id} not found in DB yet (attempt {attempt}/3), retrying in 1.0s..."
                        )
                        await asyncio.sleep(1.0)
                        continue
                    else:
                        logger.error(
                            f"Incident {incident_id} not found after 3 attempts. Aborting AI triage."
                        )
                        return

            # Connection released back to pool before AI triage LLM call
            service = AITriageService()
            analysis = await service.analyze_incident(incident_id)
            if analysis:
                logger.info(f"AI triage completed successfully for incident {incident_id}")
            else:
                logger.warning(f"AI triage returned no analysis for incident {incident_id}")
            return
        except Exception as e:
            logger.error(f"AI triage attempt {attempt} failed for incident {incident_id}: {e}", exc_info=True)
            if attempt < 3:
                await asyncio.sleep(1.0)


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

        # Fire-and-forget AI triage (không block incident creation)
        try:
            context = getattr(self.session, "info", {})
            if context.get("defer_incident_events") is True:
                context.setdefault("new_incident_ids", []).append(created.id)
            else:
                import asyncio
                asyncio.create_task(_safe_trigger_ai_triage(created.id))
        except Exception as e:
            logger.error(f"Failed to trigger AI triage for incident {created.id}: {e}")

        return created

    async def create_from_risk(
        self,
        agent_id: str,
        risk_score: float,
        factors: Dict[str, Any]
    ) -> Incident:
        """Deduplicate active risk incidents by agent and detection source."""
        auth_alert = factors.get("brute_force")
        notes = (
            "risk_source:brute_force"
            if auth_alert else "Auto-generated incident on risk assessment threshold breach."
        )
        now = datetime.now(timezone.utc)
        source = "brute_force" if auth_alert else "risk_assessment"
        rule_ids = sorted(key for key in factors if key not in {"total_score", "score", "_scores"})
        fingerprint = hashlib.sha256(json.dumps([source, rule_ids]).encode()).hexdigest()
        await self.session.execute(select(Agent.id).where(Agent.id == agent_id).with_for_update())
        stmt = select(Incident).where(
            Incident.agent_id == agent_id, Incident.fingerprint == fingerprint,
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED]),
            or_(Incident.label.is_(None), Incident.label != "false_positive"),
            Incident.updated_at >= now - timedelta(minutes=5),
        ).order_by(Incident.updated_at.desc())
        existing = (await self.session.execute(stmt)).scalars().first()

        severity = IncidentSeverity.CRITICAL if risk_score >= 85.0 else (
            IncidentSeverity.HIGH if risk_score >= 70.0 else IncidentSeverity.MEDIUM
        )
        scores = factors.get("_scores", {})
        evidence = {"rule_id": source, "rule_version": "risk:1", "risk_calculated_at": now.isoformat(),
                    "first_seen": now.isoformat(), "last_received_at": now.isoformat(), "observations": 1, "factors": [
            {"rule": key, "score": scores.get(key), "reason": str(value)}
            for key, value in factors.items() if key not in {"_scores", "total_score", "score"}
        ]}

        if existing:
            previous = existing.detection_evidence or {}
            best = evidence if not previous or risk_score > existing.risk_score else previous
            existing.detection_evidence = {
                **best, "first_seen": previous.get("first_seen", now.isoformat()),
                "last_received_at": now.isoformat(), "observations": previous.get("observations", 1) + 1,
            }
            existing.updated_at = now
            if risk_score > existing.risk_score:
                existing.risk_score = risk_score
                existing.severity = severity
            await self.session.flush()
            logger.info(f"Updated existing incident '{existing.id}' for agent '{agent_id}' with score {risk_score}.")
            return existing

        inc_id = f"inc_{uuid.uuid4().hex[:12]}"
        title = (
            f"Authentication Risk on Agent '{agent_id}' (Score: {risk_score})"
            if auth_alert else f"High Risk Threat Spike on Agent '{agent_id}' (Score: {risk_score})"
        )
        desc = f"Automated incident generated due to risk score {risk_score}.\nFactors: {factors}"

        inc = Incident(
            id=inc_id,
            title=title,
            description=desc,
            severity=severity,
            status=IncidentStatus.OPEN,
            agent_id=agent_id,
            risk_score=risk_score,
            notes=notes,
            detection_evidence=evidence,
            fingerprint=fingerprint,
        )
        created = await self.repository.add(inc)
        await self.session.flush()

        await self.add_note(inc_id, f"Automated incident created due to risk score {risk_score}.", user="system")

        context = getattr(self.session, "info", {})
        if context.get("defer_incident_events") is True:
            context.setdefault("new_incident_ids", []).append(created.id)
        else:
            import asyncio
            asyncio.create_task(_safe_trigger_ai_triage(created.id))

        # Trigger notification
        msg = (
            f"🚨 <b>NEW AUTOMATED INCIDENT ({severity.upper()})</b> 🚨\n"
            f"<b>Incident ID:</b> {inc_id}\n"
            f"<b>Agent ID:</b> {agent_id}\n"
            f"<b>Risk Score:</b> {risk_score}/100\n"
            f"<b>Title:</b> {title}"
        )
        if context.get("defer_incident_events") is True:
            context.setdefault("incident_alerts", []).append(msg)
        else:
            await self.notification_service.send_alert(msg)

        logger.warning(f"Automated incident '{inc_id}' created for agent '{agent_id}'.")
        return created

    async def update_incident(self, incident_id: str, dto: IncidentUpdate) -> Incident:
        await self.session.execute(select(Incident.id).where(Incident.id == incident_id).with_for_update())
        inc = await self.get_incident(incident_id)
        old_status = inc.status
        requested_status = dto.status
        if requested_status == IncidentStatus.FALSE_POSITIVE:
            dto = dto.model_copy(update={"status": None, "label": "false_positive"})
        if dto.status and dto.status != old_status:
            allowed = {
                IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
                IncidentStatus.INVESTIGATING: {IncidentStatus.OPEN, IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
                IncidentStatus.CONTAINED: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
                IncidentStatus.RESOLVED: {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
                IncidentStatus.CLOSED: {IncidentStatus.OPEN},
                IncidentStatus.FALSE_POSITIVE: {IncidentStatus.OPEN, IncidentStatus.CLOSED},
            }
            if dto.status not in allowed[old_status]:
                raise BadRequestError("Invalid incident lifecycle transition")
            if dto.status in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED}:
                inc.resolved_at = inc.resolved_at or datetime.now(timezone.utc)
            else:
                inc.resolved_at = None

        # If label is provided, set labeled_at = now()
        if dto.label is not None:
            inc.label = dto.label
            inc.label_reason = dto.label_reason
            inc.labeled_by = dto.labeled_by or "current_user"
            inc.labeled_at = datetime.now(timezone.utc)

        # Log warning if closing without label
        new_status = dto.status
        is_closing = False
        if new_status:
            status_val = new_status.value if hasattr(new_status, "value") else str(new_status).lower()
            if status_val == "closed":
                is_closing = True

        if is_closing and not dto.label and not inc.label:
            logger.warning(f"Closing incident {incident_id} without label — AI feedback unavailable")

        for field, value in dto.model_dump(exclude_unset=True).items():
            if field in ("label", "label_reason", "labeled_by", "labeled_at"):
                continue
            if value is not None:
                setattr(inc, field, value)

        await self.session.flush()

        if (dto.status and dto.status != old_status) or requested_status == IncidentStatus.FALSE_POSITIVE:
            status_val = (dto.status or requested_status).value
            old_status_val = old_status.value if hasattr(old_status, "value") else str(old_status)
            await self.add_note(
                incident_id,
                f"Incident status updated from '{old_status_val}' to '{status_val}'.",
                user=dto.assigned_to or (dto.labeled_by or "admin")
            )
            await self.session.commit()
            msg = f"🔔 <b>INCIDENT STATUS CHANGED</b>\n<b>ID:</b> {incident_id}\n<b>New Status:</b> {status_val}"
            await self.notification_service.send_alert(msg)

            # Broadcast to dashboard websocket
            try:
                from app.websocket.dashboard_connection_manager import dashboard_manager
                evt_type = "INCIDENT_RESOLVED" if status_val in ("resolved", "closed", "false_positive") else "INCIDENT_STATUS_CHANGED"
                await dashboard_manager.broadcast({
                    "type": evt_type,
                    "event": evt_type,
                    "incident_id": incident_id,
                    "agent_id": inc.agent_id,
                    "status": status_val,
                })
            except Exception as e:
                logger.warning(f"Failed to broadcast incident status update to dashboard: {e}")

        await attach_incident_activity(self.session, [inc])
        return inc

    async def _enrich_incident(self, inc: Incident, *, stored_only=False) -> Incident:
        """Enrich incident with structured fields: culprit_process, parent_process, network_indicators, factors_breakdown."""
        if inc.detection_evidence:
            evidence = inc.detection_evidence
            inc.culprit_process = evidence.get("process")
            inc.parent_process = next(iter(evidence.get("ancestry", [])), None)
            inc.network_indicators = [evidence["network"]] if "network" in evidence else []
            inc.factors_breakdown = evidence.get("factors") or [
                {"rule": evidence["rule_id"], "score": signal["score"], "reason": signal["reason"]}
                for signal in evidence.get("signals", [])
            ]
            inc.story = evidence.get("story") or (inc.description or "").split("\n", 1)[0]
            return inc
        notes = inc.notes or ""
        if (notes.startswith("rule_id:builtin_linux_network_shell")
                or "Direct connection to C2 port" in (inc.description or "")):
            inc.culprit_process = None
            inc.parent_process = None
            inc.network_indicators = []
            inc.factors_breakdown = []
            inc.story = "Legacy network alert. Socket-to-process evidence was unavailable."
            return inc
        if stored_only:
            inc.culprit_process = None
            inc.parent_process = None
            inc.network_indicators = []
            inc.factors_breakdown = []
            inc.story = (inc.description or "").split("\n", 1)[0]
            return inc
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
                    if k in ("total_score", "score", "_scores"):
                        continue
                    factors_breakdown.append({
                        "rule": k,
                        "score": rrec.factors.get("_scores", {}).get(k),
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
            # 1. First priority: suspicious non-kernel process
            for p in procs:
                if p.is_suspicious and is_eligible_culprit(p):
                    culprit_proc = p
                    break

            # 2. Second priority: process specifically identified in incident description as suspicious or culprit
            if not culprit_proc:
                for p in procs:
                    p_name = (p.name or "").lower()
                    if p_name and len(p_name) >= 3 and is_eligible_culprit(p):
                        pattern = r'\b' + re.escape(p_name) + r'\b'
                        if re.search(pattern, desc_lower) and (p.is_suspicious or "process:" in desc_lower or "culprit" in desc_lower):
                            culprit_proc = p
                            break

            # 3. Third priority: common attack / shell binaries ONLY IF suspicious or running network reverse shell
            if not culprit_proc:
                common_attack_names = {
                    "nc", "ncat", "netcat", "socat"
                }
                for p in procs:
                    p_name = (p.name or "").lower()
                    if p_name in common_attack_names and is_eligible_culprit(p):
                        cmd = (p.cmdline or "").lower()
                        if p.is_suspicious or any(pat in cmd for pat in ("/dev/tcp/", "-e /bin", "-e /bin/sh", "-e /bin/bash")):
                            culprit_proc = p
                            break

            # KHÔNG CÓ BLIND FALLBACK: Nếu không có tiến trình nào thỏa mãn các điều kiện trên,
            # giữ culprit_proc = None. Đây là sự cố cấp độ Host/Network Telemetry, không được gán ép bừa bãi!

            if culprit_proc:
                culprit_dict = {
                    "pid": culprit_proc.pid,
                    "name": culprit_proc.name,
                    "exe_path": culprit_proc.exe_path or culprit_proc.exe or "",
                    "cmdline": culprit_proc.cmdline or "",
                    "sha256": culprit_proc.hash or "",
                    "cpu_percent": culprit_proc.cpu_percent,
                    "memory_percent": culprit_proc.memory_percent,
                    "is_suspicious": culprit_proc.is_suspicious
                }
                if culprit_proc.parent_pid and culprit_proc.parent_pid != culprit_proc.pid and culprit_proc.parent_pid > 2:
                    parent_proc = next((p for p in procs if p.pid == culprit_proc.parent_pid), None)
                    if parent_proc:
                        parent_dict = {
                            "pid": parent_proc.pid,
                            "name": parent_proc.name,
                            "exe_path": parent_proc.exe_path or parent_proc.exe or ""
                        }
                    else:
                        parent_dict = {
                            "pid": culprit_proc.parent_pid,
                            "name": None,
                            "exe_path": None
                        }

        # 3. Network indicators
        network_indicators: List[Dict[str, Any]] = []
        if agent_id:
            flow_stmt = select(Flow).where(Flow.agent_id == agent_id).order_by(Flow.created_at.desc()).limit(20)
            flow_res = await self.session.execute(flow_stmt)
            flows = list(flow_res.scalars().all())
            for fl in flows:
                if fl.dst_ip in ("0.0.0.0", "127.0.0.1", "::1", "localhost"):
                    continue
                p_name = fl.process_name
                # Strictly only attribute to culprit if PID matches
                if not p_name and culprit_dict and fl.pid and fl.pid == culprit_dict.get("pid"):
                    p_name = culprit_dict.get("name")
                
                rep = NetworkReputationService.get_reputation(fl.dst_ip)

                network_indicators.append({
                    "dst_ip": fl.dst_ip,
                    "dst_port": fl.dst_port,
                    "protocol": fl.protocol,
                    "bytes_sent": fl.bytes_sent,
                    "packets_sent": fl.packets_sent,
                    "process_name": p_name or "unknown",
                    "pid": fl.pid,
                    "asn": rep.get("asn", "UNKNOWN"),
                    "org": rep.get("org", "Unknown"),
                    "category": rep.get("category", "public_internet")
                })
                if len(network_indicators) >= 10:
                    break

        inc.culprit_process = culprit_dict
        inc.parent_process = parent_dict
        inc.network_indicators = network_indicators
        inc.factors_breakdown = factors_breakdown
        inc.story = self.generate_story(inc, culprit_dict, parent_dict)
        return inc

    def generate_story(
        self,
        incident: Incident,
        culprit: Optional[Dict[str, Any]],
        parent: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate factual narrative story for an incident without hallucinating missing fields."""
        score_val = int(incident.risk_score) if incident.risk_score is not None else 0
        if not culprit:
            context_bits = []
            desc = incident.description or ""
            if "http_beaconing" in desc or "beacon" in desc.lower():
                context_bits.append("chuỗi kết nối mạng định kỳ ra ngoài (Network Beaconing)")
            if "ml_behavioral_anomaly" in desc or "anomaly" in desc.lower():
                context_bits.append("đột biến tài nguyên hệ thống (ML Behavioral Anomaly)")
            reason_str = f" do {' và '.join(context_bits)}" if context_bits else ""
            return f"Hệ thống phân tích rủi ro ghi nhận điểm đe dọa {score_val}/100 trên máy trạm `{incident.agent_id}`{reason_str}. Chưa ghi nhận tiến trình độc hại cụ thể trực tiếp gắn với lưu lượng này."

        c_name = culprit.get("name") or "tiến trình không xác định"
        c_pid = culprit.get("pid")
        pid_str = f" (PID {c_pid})" if c_pid is not None else ""
        parts = [f"Tiến trình `{c_name}`{pid_str}"]

        parent_name = parent.get("name") if parent else None
        parent_pid = parent.get("pid") if parent else None
        if parent_pid == 0 or (c_pid is not None and parent_pid == c_pid):
            parent_pid = None
            if parent_name == c_name:
                parent_name = None

        if parent_name and parent_pid:
            parts.append(f"được khởi chạy bởi `{parent_name}` (PID {parent_pid})")
        elif parent_name:
            parts.append(f"được khởi chạy bởi `{parent_name}`")
        elif parent_pid:
            parts.append(f"có parent PID {parent_pid} (không xác định tên)")

        c_exe = culprit.get("exe_path") or culprit.get("exe")
        if c_exe:
            parts.append(f"hoạt động từ `{c_exe}`")

        parts.append(f"Hệ thống phân tích rủi ro kích hoạt điểm đe dọa {score_val}/100.")
        return " ".join(parts)

    async def get_incident(self, incident_id: str) -> Incident:
        inc = await self.repository.get(incident_id)
        if not inc:
            raise NotFoundError(f"Incident '{incident_id}' not found.")
        await self._enrich_incident(inc, stored_only=True)
        await attach_incident_activity(self.session, [inc])
        return inc

    async def list_incidents(
        self,
        skip: int = 0,
        limit: int = 200,
        active_only: bool = False,
        hours: Optional[int] = None,
        finding: Optional[str] = None,
    ) -> List[Incident]:
        items = await self.repository.list(skip=skip, limit=limit, active_only=active_only, hours=hours, finding=finding)
        for inc in items:
            await self._enrich_incident(inc, stored_only=True)
        return await attach_incident_activity(self.session, items)

    async def assign_incident(self, incident_id: str, user_id: str) -> Incident:
        return await self.update_incident(incident_id, IncidentUpdate(
            assigned_to=user_id, status=IncidentStatus.INVESTIGATING,
        ))

    async def contain_incident(self, incident_id: str, user: str = "admin") -> Incident:
        return await self.update_incident(incident_id, IncidentUpdate(status=IncidentStatus.CONTAINED))

    async def resolve_incident(self, incident_id: str, user: str = "admin") -> Incident:
        return await self.update_incident(incident_id, IncidentUpdate(status=IncidentStatus.RESOLVED))

    async def mark_false_positive(self, incident_id: str, user: str = "admin") -> Incident:
        return await self.update_incident(incident_id, IncidentUpdate(
            status=IncidentStatus.FALSE_POSITIVE, labeled_by=user,
        ))

    async def close_incident(self, incident_id: str, user: str = "admin") -> Incident:
        return await self.update_incident(incident_id, IncidentUpdate(status=IncidentStatus.CLOSED))

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
                action_params={"confirmed": params.get("confirmed"), "reason": f"SOC Quick Action from Incident '{incident_id}' by {user}"},
                incident_id=incident_id,
                actor=user
            )
            result_msg = f"Queued isolation for Agent '{agent_id}' (Action: {act.id})."

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
                result_msg = f"Requested isolation rollback for Agent '{agent_id}'."
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
            process = (inc.detection_evidence or {}).get("process")
            if inc.process_activity != "running" or not process or params.get("pid") != process["pid"]:
                raise BadRequestError("The incident has no verified process identity for this PID")
            from app.services.response.response_action_service import ResponseActionService
            act = await ResponseActionService(self.session).create_and_apply_action(
                agent_id=agent_id, action_type=action_type, incident_id=incident_id, actor=user,
                action_params={
                    "pid": process["pid"], "process_start_time": process["process_start_time"],
                    "parent_pid": process["parent_pid"], "exe_path": process["exe_path"],
                    "confirmed": params.get("confirmed"), "reason": f"SOC action for incident {incident_id}",
                },
            )
            result_msg = f"Queued process termination for PID {process['pid']} (Action: {act.id})."

        elif action_type == "block_ip":
            raise BadRequestError("Use the Agent firewall controls to apply an IP rule.")

        else:
            raise BadRequestError(f"Unknown action_type '{action_type}'.")

        await self.add_note(incident_id, f"SOC action requested: [{action_type.upper()}] - {result_msg}", user=user)
        await self.session.flush()

        # Send notification
        msg = (
            f"⚡ <b>SOC ACTION REQUESTED</b>\n"
            f"<b>Incident:</b> {incident_id}\n"
            f"<b>Action:</b> {action_type.upper()}\n"
            f"<b>Executed By:</b> {user}\n"
            f"<b>Details:</b> {result_msg}"
        )
        await self.notification_service.send_alert(msg)

        return {"status": "pending", "message": result_msg, "action": action_type, "incident_id": incident_id}

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

    async def delete_incident(self, incident_id: str) -> bool:
        """Xóa vĩnh viễn một incident và dữ liệu quan hệ liên quan khỏi PostgreSQL."""
        inc = await self.repository.get(incident_id)
        if not inc:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        from app.models.incident_note import IncidentNote
        from app.models.ai_analysis import AIAnalysis
        from app.models.response_action import ResponseAction
        from sqlalchemy import delete, update

        # 1. Xóa incident_notes
        await self.session.execute(delete(IncidentNote).where(IncidentNote.incident_id == incident_id))

        # 2. Xóa ai_analysis
        await self.session.execute(delete(AIAnalysis).where(AIAnalysis.incident_id == incident_id))

        # 3. Gỡ liên kết response_actions
        await self.session.execute(
            update(ResponseAction).where(ResponseAction.incident_id == incident_id).values(incident_id=None)
        )

        # 4. Xóa incident
        await self.session.delete(inc)
        await self.session.commit()
        return True

    async def bulk_resolve(self, incident_ids: List[str]) -> int:
        """Đánh dấu đã giải quyết (resolved) cho nhiều incidents cùng lúc."""
        if not incident_ids:
            return 0
        from sqlalchemy import update
        now = datetime.now(timezone.utc)
        stmt = (
            update(Incident)
            .where(Incident.id.in_(incident_ids))
            .values(status=IncidentStatus.RESOLVED, resolved_at=now)
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount or 0

    async def bulk_delete(self, incident_ids: List[str]) -> int:
        """Xóa vĩnh viễn nhiều incidents khỏi PostgreSQL."""
        if not incident_ids:
            return 0
        from app.models.incident_note import IncidentNote
        from app.models.ai_analysis import AIAnalysis
        from app.models.response_action import ResponseAction
        from sqlalchemy import delete, update

        # 1. Xóa notes liên quan
        await self.session.execute(
            delete(IncidentNote).where(IncidentNote.incident_id.in_(incident_ids))
        )

        # 2. Xóa ai_analysis liên quan
        await self.session.execute(
            delete(AIAnalysis).where(AIAnalysis.incident_id.in_(incident_ids))
        )

        # 3. Gỡ liên kết response_actions
        await self.session.execute(
            update(ResponseAction).where(ResponseAction.incident_id.in_(incident_ids)).values(incident_id=None)
        )

        # 4. Xóa incidents
        result = await self.session.execute(
            delete(Incident).where(Incident.id.in_(incident_ids))
        )
        await self.session.commit()
        return result.rowcount or 0

