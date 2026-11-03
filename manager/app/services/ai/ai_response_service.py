import re
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.flow import Flow
from app.models.ai_analysis import AIAnalysis
from app.models.response_action import ResponseAction
from app.services.ai.ai_client import ai_client
from app.services.response.response_action_service import ResponseActionService
from app.core.exceptions import NotFoundError, BadRequestError

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS: Set[str] = {
    "kill_process",
    "kill_process_tree",
    "isolate",
    "suspend_process",
    "block_ip",
    "no_action",
}


class AIResponseService:
    """
    Response AI Assist Service (Layer 2 AI).
    Recommends response actions based on triage analysis, endpoint context, and historical effective mitigations.
    Analyst must explicitly approve and apply all recommendations — zero automated dispatch.
    """

    async def suggest_response(self, incident_id: str, session: AsyncSession) -> Optional[AIAnalysis]:
        """Suggest response action based on existing triage analysis. Read-only."""
        try:
            # 1. Lấy latest AIAnalysis (triage) — nếu chưa có → return None
            stmt = (
                select(AIAnalysis)
                .where(AIAnalysis.incident_id == incident_id, AIAnalysis.analysis_type == "triage")
                .order_by(AIAnalysis.created_at.desc())
                .limit(1)
            )
            res = await session.execute(stmt)
            analysis = res.scalar_one_or_none()
            if not analysis:
                logger.warning(f"No triage analysis found for incident {incident_id} to suggest response")
                return None

            incident = await session.get(Incident, incident_id)
            if not incident:
                logger.warning(f"Incident {incident_id} not found")
                return None

            agent_id = incident.agent_id

            # 2. Pull context: process tree + suspicious processes + network
            suspicious_procs, all_procs = await self._get_processes(session, agent_id)
            recent_flows = await self._get_flows(session, agent_id)

            # 3. Pull similar incidents: label=true_positive and response_action.outcome=effective
            similar_cases = await self._get_similar_incidents(session)

            # 4. Build prompt
            prompt = self._build_prompt(
                incident=incident,
                triage=analysis,
                processes=suspicious_procs,
                flows=recent_flows,
                similar_incidents=similar_cases,
            )

            # 5. Call ai_client
            logger.info(f"Calling Foundation-Sec AI response suggestion for incident {incident_id}...")
            result = await ai_client.generate(
                prompt=prompt,
                system=self._system_prompt(),
            )

            # 6. Parse JSON from answer or raw text
            text_to_parse = result.get("answer") or result.get("raw") or ""
            parsed = self._parse_json_answer(text_to_parse)

            raw_action = str(parsed.get("suggested_action", "no_action")).strip().lower()
            raw_params = parsed.get("params", {}) or {}
            confidence = float(parsed.get("confidence", 0.7))
            reasoning = str(parsed.get("reasoning", "")).strip()
            risk_if_not_act = str(parsed.get("risk_if_not_act", "")).strip()

            if risk_if_not_act and not reasoning.endswith(risk_if_not_act):
                reasoning = f"{reasoning} Nguy cơ nếu không hành động: {risk_if_not_act}"

            # 7. Validate action & params
            validated_action, validated_params, final_reasoning = await self._validate_suggestion(
                action=raw_action,
                params=raw_params,
                reasoning=reasoning,
                confidence=confidence,
                all_procs=all_procs,
                recent_flows=recent_flows,
            )

            # 8. Calculate real blast radius from endpoint data (OVERRIDE AI value)
            real_blast = await self._calculate_real_blast_radius(
                session=session,
                agent_id=incident.agent_id,
                action_type=validated_action,
                params=validated_params,
            )

            # 9. Update AIAnalysis row with suggestion_* fields
            analysis.suggested_action = validated_action
            analysis.suggestion_params = validated_params
            analysis.suggestion_reasoning = final_reasoning
            analysis.blast_radius = real_blast
            # Reset analyst review fields if re-suggesting
            analysis.applied_by_analyst = None
            analysis.applied_at = None
            analysis.dismissed_by_analyst = None
            analysis.dismissed_at = None
            analysis.dismiss_reason = None
            analysis.updated_at = datetime.now(timezone.utc)

            await session.commit()
            await session.refresh(analysis)
            logger.info(
                f"AI response suggestion generated for incident {incident_id}: "
                f"action={validated_action}, params={validated_params}, confidence={confidence:.2f}"
            )
            return analysis

        except Exception as e:
            logger.error(f"Failed to generate response suggestion for incident {incident_id}: {e}", exc_info=True)
            return None

    async def apply_suggestion(self, incident_id: str, analyst: str, session: AsyncSession) -> ResponseAction:
        """Apply AI response suggestion — delegate strictly to existing ResponseActionService."""
        # 1. Lấy AIAnalysis có suggested_action
        stmt = (
            select(AIAnalysis)
            .where(AIAnalysis.incident_id == incident_id, AIAnalysis.analysis_type == "triage")
            .order_by(AIAnalysis.created_at.desc())
            .limit(1)
        )
        res = await session.execute(stmt)
        suggestion = res.scalar_one_or_none()
        if not suggestion or not suggestion.suggested_action:
            raise NotFoundError(f"No response suggestion found for incident '{incident_id}'")

        # === IDEMPOTENCY CHECK ===
        if suggestion.applied_by_analyst:
            raise ValueError(
                f"Suggestion already applied by '{suggestion.applied_by_analyst}' "
                f"at {suggestion.applied_at.isoformat() if suggestion.applied_at else 'N/A'}. "
                f"To re-apply, analyst must regenerate AI suggestion first."
            )

        if suggestion.dismissed_by_analyst:
            raise ValueError(
                f"Suggestion was dismissed by '{suggestion.dismissed_by_analyst}' "
                f"(reason: {suggestion.dismiss_reason or 'none'}). "
                f"Cannot apply a dismissed suggestion — regenerate first."
            )
        # === END IDEMPOTENCY ===

        incident = await session.get(Incident, incident_id)
        if not incident or not incident.agent_id:
            raise NotFoundError(f"Incident '{incident_id}' or associated agent ID was not found")

        # === VALIDATION BLOCK (thêm trước khi dispatch) ===
        suggested = suggestion.suggested_action
        params = suggestion.suggestion_params or {}

        if suggested in ("kill_process", "kill_process_tree", "suspend_process"):
            pid = params.get("pid")
            if not pid:
                raise ValueError(f"Missing 'pid' param for {suggested}")
            try:
                pid_int = int(pid)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid 'pid' param: {pid} (must be integer)")

            # Verify PID exists in process_info for this agent
            stmt = (
                select(ProcessInfo)
                .where(ProcessInfo.agent_id == incident.agent_id)
                .where(ProcessInfo.pid == pid_int)
                .limit(1)
            )
            result = await session.execute(stmt)
            proc = result.scalar_one_or_none()
            if not proc:
                raise ValueError(
                    f"PID {pid_int} not found in process_info for agent {incident.agent_id}. "
                    f"AI suggestion is stale or hallucinated — refusing to dispatch."
                )

        elif suggested == "block_ip":
            ip = params.get("ip")
            if not ip:
                raise ValueError("Missing 'ip' param for block_ip")

            # Verify IP exists in recent flows (last 1h)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            stmt = (
                select(Flow)
                .where(Flow.agent_id == incident.agent_id)
                .where(Flow.dst_ip == ip)
                .where(Flow.start_time >= cutoff)
                .limit(1)
            )
            result = await session.execute(stmt)
            if not result.scalar_one_or_none():
                raise ValueError(
                    f"IP {ip} not found in recent flows (1h) for agent {incident.agent_id}. "
                    f"Refusing to dispatch block_ip."
                )

        elif suggested in ("isolate", "unisolate"):
            # Không cần params — agent-level action
            pass

        elif suggested == "no_action":
            raise ValueError(
                "Cannot apply 'no_action' — analyst should simply not act. "
                "Dismiss the suggestion instead."
            )
        else:
            raise ValueError(f"Unsupported suggested action '{suggested}'")

        # === END VALIDATION ===

        # 2. Gọi ResponseActionService.create_and_apply_action
        response_service = ResponseActionService(session)
        action_params = dict(suggestion.suggestion_params or {})
        reason_text = f"Applied AI suggestion: {(suggestion.suggestion_reasoning or '')[:200]}"
        action_params["reason"] = reason_text

        action = await response_service.create_and_apply_action(
            agent_id=incident.agent_id,
            action_type=suggestion.suggested_action,
            action_params=action_params,
            incident_id=incident_id,
            actor=analyst,
        )

        # 3. Update ai_analysis: applied_by_analyst, applied_at (within same transaction)
        now = datetime.now(timezone.utc)
        suggestion.applied_by_analyst = analyst
        suggestion.applied_at = now

        # 4. Ghi feedback signal vào response_action
        action.feedback_signal = {
            "source": "ai_suggestion",
            "confidence": suggestion.confidence,
            "analyst": analyst,
            "suggested_action": suggestion.suggested_action,
        }

        await session.commit()
        await session.refresh(action)
        await session.refresh(suggestion)
        logger.info(f"Successfully applied AI suggestion {suggestion.suggested_action} for incident {incident_id} by {analyst}")
        return action

    async def dismiss_suggestion(
        self,
        incident_id: str,
        analyst: str,
        reason: str,
        session: AsyncSession
    ) -> AIAnalysis:
        """Analyst dismisses AI suggestion — records negative/dismissal feedback signal."""
        stmt = (
            select(AIAnalysis)
            .where(AIAnalysis.incident_id == incident_id, AIAnalysis.analysis_type == "triage")
            .order_by(AIAnalysis.created_at.desc())
            .limit(1)
        )
        res = await session.execute(stmt)
        suggestion = res.scalar_one_or_none()
        if not suggestion:
            raise NotFoundError(f"No AI analysis found for incident '{incident_id}'")

        now = datetime.now(timezone.utc)
        suggestion.dismissed_by_analyst = analyst
        suggestion.dismissed_at = now
        suggestion.dismiss_reason = reason or "No reason provided"

        await session.commit()
        await session.refresh(suggestion)
        logger.info(f"AI suggestion for incident {incident_id} dismissed by {analyst}. Reason: {reason}")
        return suggestion

    # =========================================================================
    # Context, Prompt & Validation Helpers
    # =========================================================================

    def _system_prompt(self) -> str:
        return (
            "Bạn là SOC Analyst Tier 2 chuyên phản ứng sự cố an ninh EDR. "
            "Nhiệm vụ của bạn là đề xuất DUY NHẤT 1 hành động phản ứng tối ưu dựa trên phân tích triage. "
            "Trả về JSON hợp lệ theo đúng cấu trúc yêu cầu. Không thêm markdown ngoài JSON."
        )

    def _build_prompt(
        self,
        incident: Incident,
        triage: AIAnalysis,
        processes: List[ProcessInfo],
        flows: List[Flow],
        similar_incidents: List[str],
    ) -> str:
        mitre_list = []
        if triage.mitre_techniques and isinstance(triage.mitre_techniques, list):
            for t in triage.mitre_techniques[:3]:
                if isinstance(t, dict):
                    mitre_list.append(f"• {t.get('id', '')} - {t.get('name', '')}")
        mitre_str = "\n".join(mitre_list) if mitre_list else "None identified"

        procs_str = "\n".join(
            f"PID {p.pid} (Name: {p.name}, PPID: {p.parent_pid}, Cmd: {p.cmdline[:80]}) {'[SUSPICIOUS]' if p.is_suspicious else ''}"
            for p in processes[:6]
        ) or "None recorded"

        flows_str = "\n".join(
            f"Process: {f.process_name or 'unknown'} (PID {f.pid or 0}) -> {f.dst_ip}:{f.dst_port}"
            for f in flows[:3]
        ) or "None recorded"

        sim_str = "\n".join(similar_incidents[:2]) if similar_incidents else "Chưa có incident tương tự."
        triage_summary_short = (triage.summary or "")[:250].replace("\n", " ").strip()

        json_example = """{
  "suggested_action": "kill_process_tree",
  "params": {"pid": 3748},
  "confidence": 0.90,
  "reasoning": "Lý do ngắn gọn 1-2 câu tham chiếu PID hoặc IP.",
  "blast_radius": {
    "processes_affected": 2,
    "sessions_affected": 1,
    "reversible": false
  },
  "risk_if_not_act": "Nguy cơ nếu không hành động."
}"""

        return f"""Bạn là SOC Analyst Tier 2. Dựa trên dữ liệu dưới đây, đề xuất DUY NHẤT 1 HÀNH ĐỘNG PHẢN ỨNG tối ưu.

INCIDENT: {incident.title} (Score: {incident.risk_score}/100) trên Agent {incident.agent_id}
TRIAGE: {triage_summary_short}
MITRE:
{mitre_str}
SUSPICIOUS PROCESSES:
{procs_str}
NETWORK FLOWS:
{flows_str}
HISTORICAL CASES:
{sim_str}

ALLOWED ACTIONS:
- kill_process: Kill 1 process (param: pid)
- kill_process_tree: Kill process và con cháu (param: pid)
- isolate: Cô lập host khỏi mạng
- suspend_process: Tạm dừng process (param: pid)
- block_ip: Block IP C2 (param: ip)
- no_action: Chỉ giám sát

Trả về DUY NHẤT 1 JSON (không markdown ngoài JSON):
{json_example}
"""

    def _parse_json_answer(self, answer: str) -> dict:
        """Extract JSON from model response, handling think tags, markdown fences, and boundary markers."""
        if not answer:
            raise ValueError("AI returned an empty response")

        if "</think>" in answer:
            answer = answer.split("</think>", 1)[1].strip()

        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", answer, re.DOTALL)
        if match:
            clean_text = match.group(1).strip()
            try:
                return json.loads(clean_text)
            except Exception:
                pass

        end = answer.rfind("}")
        if end >= 0:
            for start in range(len(answer[:end])):
                if answer[start] == "{":
                    candidate = answer[start:end+1].strip()
                    try:
                        data = json.loads(candidate)
                        if isinstance(data, dict) and "suggested_action" in data:
                            return data
                    except Exception:
                        continue

        for m in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", answer, re.DOTALL):
            try:
                data = json.loads(m.group(0))
                if isinstance(data, dict) and "suggested_action" in data:
                    return data
            except Exception:
                continue

        try:
            return json.loads(answer)
        except json.JSONDecodeError as e:
            raise ValueError(f"AI did not return valid JSON: {e}. Raw: {answer[:300]}")

    async def _validate_suggestion(
        self,
        action: str,
        params: Dict[str, Any],
        reasoning: str,
        confidence: float,
        all_procs: List[ProcessInfo],
        recent_flows: List[Flow],
    ) -> tuple[str, Dict[str, Any], str]:
        """Validate AI suggestion against strict constraints and live endpoint telemetry."""
        # Rule 1: Action must be in ALLOWED list
        if action not in ALLOWED_ACTIONS:
            return (
                "no_action",
                {},
                f"Hành động đề xuất '{action}' không nằm trong danh mục cho phép. Chuyển sang theo dõi (no_action). Ban đầu: {reasoning}",
            )

        # Rule 2: Low confidence fallback
        if confidence < 0.6:
            return (
                "no_action",
                {},
                f"Độ tin cậy của mô hình ({confidence:.2f}) dưới ngưỡng an toàn 0.60. Đề xuất quan sát (no_action). Lý do: {reasoning}",
            )

        # Rule 3: Process actions require real existing PID
        if action in {"kill_process", "kill_process_tree", "suspend_process"}:
            if not all_procs:
                return (
                    "isolate",
                    {},
                    f"Không có dữ liệu tiến trình để thực hiện {action}. Đề xuất cô lập host (isolate) để ngăn chặn rủi ro. Lý do: {reasoning}",
                )

            pid = params.get("pid")
            if pid is None:
                return (
                    "no_action",
                    {},
                    f"Đề xuất {action} nhưng thiếu tham số 'pid'. Chuyển sang no_action. Lý do: {reasoning}",
                )

            try:
                pid_int = int(pid)
            except (ValueError, TypeError):
                return (
                    "no_action",
                    {},
                    f"Tham số PID '{pid}' không hợp lệ. Chuyển sang no_action.",
                )

            existing_proc = next((p for p in all_procs if p.pid == pid_int), None)
            if not existing_proc:
                return (
                    "no_action",
                    {},
                    f"PID {pid_int} được đề xuất không tồn tại trên máy trạm (hallucinated PID). Đã chặn và chuyển sang no_action. Lý do: {reasoning}",
                )

            params["pid"] = pid_int
            if existing_proc.name:
                params["process_name"] = existing_proc.name

        # Rule 4: Block IP requires real IP present in flows
        if action == "block_ip":
            ip = params.get("ip")
            if not ip or not isinstance(ip, str):
                return (
                    "no_action",
                    {},
                    f"Đề xuất block_ip nhưng thiếu tham số IP. Chuyển sang no_action. Lý do: {reasoning}",
                )

            ip_clean = ip.strip()
            existing_ip = any(f.dst_ip == ip_clean or f.src_ip == ip_clean for f in recent_flows)
            if not existing_ip:
                return (
                    "no_action",
                    {},
                    f"Địa chỉ IP '{ip_clean}' không xuất hiện trong các kết nối mạng của máy trạm. Đã chặn đề xuất.",
                )

            params["ip"] = ip_clean

        return action, params, reasoning

    async def _calculate_real_blast_radius(
        self, session: AsyncSession, agent_id: str, action_type: str, params: dict
    ) -> dict:
        """Calculate actual blast radius from DB — không dùng AI value."""
        if action_type in ("kill_process", "kill_process_tree", "suspend_process"):
            pid = params.get("pid")
            if not pid:
                return {"processes_affected": 0, "sessions_affected": 0, "reversible": False}

            try:
                pid_int = int(pid)
            except (ValueError, TypeError):
                return {"processes_affected": 0, "sessions_affected": 0, "reversible": False}

            # Load ALL processes for this agent (1 query)
            stmt = select(ProcessInfo).where(ProcessInfo.agent_id == agent_id)
            result = await session.execute(stmt)
            all_procs = list(result.scalars().all())

            if not all_procs:
                return {"processes_affected": 0, "sessions_affected": 0, "reversible": False}

            # Verify target PID exists
            by_pid = {p.pid: p for p in all_procs}
            if pid_int not in by_pid:
                return {"processes_affected": 0, "sessions_affected": 0, "reversible": False}

            # Recursive descend from target PID
            if action_type == "kill_process":
                descendants = [pid_int]
            else:  # kill_process_tree or suspend_process
                descendants = [pid_int]
                frontier = [pid_int]
                while frontier:
                    parent = frontier.pop()
                    children = [p.pid for p in all_procs if p.parent_pid == parent]
                    descendants.extend(children)
                    frontier.extend(children)

            # Count unique sessions in affected processes
            session_ids = {
                by_pid[p].session_id
                for p in descendants
                if p in by_pid and by_pid[p].session_id
            }

            return {
                "processes_affected": len(descendants),
                "sessions_affected": len(session_ids),
                "reversible": action_type == "suspend_process",
            }

        elif action_type == "isolate":
            # Count active network connections
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            stmt = (
                select(Flow)
                .where(Flow.agent_id == agent_id)
                .where(Flow.start_time >= cutoff)
                .where(Flow.end_time.is_(None))  # active
            )
            result = await session.execute(stmt)
            active_flows = len(list(result.scalars().all()))
            return {
                "processes_affected": 0,
                "sessions_affected": active_flows,  # active connections ≈ sessions
                "reversible": True,
            }

        elif action_type == "block_ip":
            # Count flows to that IP
            ip = params.get("ip")
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            stmt = (
                select(Flow)
                .where(Flow.agent_id == agent_id)
                .where(Flow.dst_ip == ip)
                .where(Flow.start_time >= cutoff)
            )
            result = await session.execute(stmt)
            affected = len(list(result.scalars().all()))
            return {
                "processes_affected": 0,
                "sessions_affected": affected,
                "reversible": True,
            }

        return {"processes_affected": 0, "sessions_affected": 0, "reversible": False}

    async def _get_processes(self, session: AsyncSession, agent_id: Optional[str]) -> tuple[List[ProcessInfo], List[ProcessInfo]]:
        if not agent_id:
            return [], []

        stmt = select(ProcessInfo).where(ProcessInfo.agent_id == agent_id).order_by(ProcessInfo.created_at.desc()).limit(100)
        res = await session.execute(stmt)
        all_procs = list(res.scalars().all())

        suspicious_names = {"msbuild.exe", "powershell.exe", "cmd.exe", "certutil.exe", "rundll32.exe", "mshta.exe", "cscript.exe", "wscript.exe"}
        suspicious = [
            p for p in all_procs
            if p.is_suspicious or (p.name and p.name.lower() in suspicious_names)
        ]

        if not suspicious:
            suspicious = all_procs[:10]

        return suspicious[:10], all_procs

    async def _get_flows(self, session: AsyncSession, agent_id: Optional[str]) -> List[Flow]:
        if not agent_id:
            return []

        stmt = select(Flow).where(Flow.agent_id == agent_id).order_by(Flow.start_time.desc()).limit(20)
        res = await session.execute(stmt)
        flows = list(res.scalars().all())
        return flows[:10]

    async def _get_similar_incidents(self, session: AsyncSession) -> List[str]:
        """Find historical incidents where label=true_positive and response_action outcome=effective."""
        stmt = (
            select(Incident, ResponseAction)
            .join(ResponseAction, ResponseAction.incident_id == Incident.id)
            .where(Incident.label == "true_positive", ResponseAction.outcome == "effective")
            .order_by(ResponseAction.created_at.desc())
            .limit(3)
        )
        res = await session.execute(stmt)
        rows = res.all()
        cases = []
        for inc, act in rows:
            cases.append(f"{inc.id} ({act.action_type}, effective): {inc.title}")
        return cases

