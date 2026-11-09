import re
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.process_info import ProcessInfo
from app.models.flow import Flow
from app.models.risk_score import RiskScoreRecord
from app.models.ai_analysis import AIAnalysis
from app.services.ai.ai_client import ai_client
from app.services.ai.knowledge.mitre_kb import mitre_kb
from app.services.incident.incident_timeline_service import _parse_factors

logger = logging.getLogger(__name__)


class AITriageService:
    """
    Automated Incident Triage Service (Layer 1 AI).
    Generates structured Vietnamese summaries, MITRE ATT&CK technique mapping,
    and root cause analysis grounded in endpoint telemetry.
    """

    async def analyze_incident(self, incident_id: str, session: AsyncSession) -> Optional[AIAnalysis]:
        """Run AI triage on an incident and persist results into ai_analysis table."""
        result = None
        try:
            # 1. Pull incident
            incident = await session.get(Incident, incident_id)
            if not incident:
                logger.warning(f"Incident {incident_id} not found for AI triage")
                return None

            # 2. Pull context
            process_tree = await self._get_process_tree(session, incident.agent_id)
            process_tree = process_tree[:20]
            flows = await self._get_recent_flows(session, incident.agent_id, incident.created_at, minutes=15)
            flows = flows[:10]
            factors = await self._get_risk_factors(
            session, incident.agent_id, incident.created_at, incident.description,)

            # 3. Build prompt
            prompt = self._build_prompt(
                incident=incident,
                process_tree=process_tree,
                flows=flows,
                factors=factors,
                mitre_kb_ids=list(mitre_kb.valid_ids()),
            )

            # 4. Call AI
            logger.info(f"Calling Foundation-Sec AI triage for incident {incident_id}...")
            result = await ai_client.generate(
                prompt=prompt,
                system=self._system_prompt(),
            )

            # 5. Parse JSON from answer
            parsed = self._parse_json_answer(result.get("answer", ""))

            # 6. Validate MITRE IDs (reject hallucinated)
            raw_techs = parsed.get("mitre_techniques", [])
            if not isinstance(raw_techs, list):
                raw_techs = []

            validated_techs = []
            rejected_techs = []
            for t in raw_techs:
                if isinstance(t, dict):
                    tech_id = str(t.get("id", "")).strip().upper()
                    if mitre_kb.validate_technique(tech_id):
                        kb_meta = mitre_kb.get_technique(tech_id)
                        validated_techs.append({
                            "id": tech_id,
                            "name": t.get("name") or kb_meta.get("name", "Unknown Technique"),
                            "tactic": kb_meta.get("tactic", "unknown"),
                            "evidence": str(t.get("evidence", "")).strip(),
                        })
                    else:
                        rejected_techs.append(t)

            if rejected_techs:
                logger.warning(
                    f"AI hallucinated {len(rejected_techs)} MITRE IDs for incident {incident_id}, rejected: {[t.get('id') for t in rejected_techs]}"
                )

            # 7. Check confidence calibration
            confidence = float(parsed.get("confidence", 0.75))
            if confidence > 1.0:
                confidence = 1.0
            elif confidence < 0.0:
                confidence = 0.0

            # Guard against overconfidence without strong supporting factors
            has_strong_evidence = bool(validated_techs and any(t.get("evidence") for t in validated_techs))
            if confidence >= 0.9 and not has_strong_evidence:
                confidence = 0.70

            summary = str(parsed.get("summary", "")).strip()[:4000]
            if not summary:
                summary = "AI đã phân tích dữ liệu nhưng không tạo được tóm tắt phù hợp."

            root_cause = str(parsed.get("root_cause", "")).strip()[:2000]

            # 8. Save AI Analysis
            ai_analysis = AIAnalysis(
                incident_id=incident_id,
                analysis_type="triage",
                summary=summary,
                mitre_techniques=validated_techs,
                root_cause=root_cause,
                model_name="foundation-sec",
                confidence=round(confidence, 2),
                raw_response=result.get("answer", "")[:8000],
            )
            session.add(ai_analysis)
            await session.commit()
            await session.refresh(ai_analysis)
            logger.info(f"AI triage completed successfully for incident {incident_id} (confidence={confidence:.2f})")
            return ai_analysis

        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}".strip(": ")
            logger.error(f"AI triage failed for incident {incident_id}: {err_msg}", exc_info=True)
            # Save error record so analysts know triage failed rather than hanging indefinitely
            try:
                ai_analysis = AIAnalysis(
                    incident_id=incident_id,
                    analysis_type="triage",
                    summary="[AI analysis failed]",
                    error_message=err_msg[:500],
                    model_name="foundation-sec",
                    confidence=0.0,
                    raw_response=result.get("answer", "")[:8000] if result else None,
                )
                session.add(ai_analysis)
                await session.commit()
                return ai_analysis
            except Exception as commit_err:
                logger.error(f"Failed to save AI error record for incident {incident_id}: {commit_err}")
                return None

    def _system_prompt(self) -> str:
        return (
            "You are a senior SOC analyst triaging EDR incidents. Respond ONLY with valid JSON matching the schema. "
            "Summary and root_cause must be in Vietnamese. MITRE names in English. Do not include markdown code fences."
        )

    def _build_prompt(
        self,
        incident: Incident,
        process_tree: List[ProcessInfo],
        flows: List[Flow],
        factors: Dict[str, Any],
        mitre_kb_ids: List[str],
    ) -> str:
        first_desc_line = (incident.description or '').split('\n')[0][:200]
        # Select top 20 candidate MITRE IDs to keep prompt lean
        priority_ids = [
            # LOLBin / Process execution
            "T1218.007", "T1218", "T1059", "T1059.001", "T1059.003", "T1059.004",
            "T1106", "T1204", "T1204.002",
            # Injection / Credential
            "T1055", "T1055.012", "T1003", "T1003.001",
            # Lateral movement
            "T1021", "T1021.001", "T1021.002", "T1047", "T1046", "T1018", "T1570",
            # Network / C2
            "T1071", "T1071.001", "T1071.004", "T1105", "T1095", "T1571", "T1572",
            # Persistence
            "T1547.001", "T1543.003", "T1053.005", "T1136.001",
            # Impact
            "T1486", "T1490", "T1489", "T1485",
            # Discovery
            "T1049", "T1087", "T1082", "T1016", "T1033",
            # Defense evasion
            "T1562.001", "T1070", "T1112",
            # Brute force
            "T1110", "T1110.001", "T1110.003",
        ]
        allowed_subset = [mid for mid in priority_ids if mid in mitre_kb_ids] or mitre_kb_ids[:40]

        return f"""Analyze this EDR alert and return JSON.

INCIDENT: {incident.title} (Score: {incident.risk_score}/100)
Alert: {first_desc_line}

SUSPICIOUS/KEY PROCESSES:
{self._format_process_tree(process_tree[:8])}

NETWORK ACTIVITY:
{self._format_flows(flows[:5])}

FACTORS:
{json.dumps(factors, ensure_ascii=False) if factors else "None"}

ALLOWED MITRE IDs:
{', '.join(allowed_subset)}

INSTRUCTIONS:
- Analyze what attack happened using the processes and alert above.
- STRICT RULES:
  * ONLY use data from the PROVIDED FIELDS above.
  * If a field is empty, missing, or unknown, state "không xác định" or omit it. DO NOT invent or hallucinate.
  * DO NOT mention file paths not present in the data (e.g. do NOT invent /tmp/, C:\Temp).
  * DO NOT mention parent process names not in the data (e.g. do NOT invent bash, cmd.exe).
- "summary": write 2-4 sentences in Vietnamese describing the actual incident grounded strictly in the evidence.
- "mitre_techniques": list mapped techniques chosen strictly from the allowed MITRE IDs above with evidence.
- "root_cause": 1-2 sentences in Vietnamese identifying the root cause.
- "confidence": float 0.0 to 1.0.

JSON FORMAT:
{{
  "summary": "...",
  "mitre_techniques": [
    {{"id": "...", "name": "...", "evidence": "..."}}
  ],
  "root_cause": "...",
  "confidence": 0.85
}}
"""

    def _format_process_tree(self, procs: List[ProcessInfo]) -> str:
        if not procs:
            return "No suspicious processes recorded."
        lines = []
        for p in procs[:8]:
            tag = " [SUSPICIOUS]" if p.is_suspicious else ""
            cmd = p.cmdline.strip() if p.cmdline else "(none)"
            if len(cmd) > 70:
                cmd = cmd[:67] + "..."
            exe = p.exe_path or p.exe or "(none/kernel)"
            parent = f"parent PID: {p.parent_pid}" if p.parent_pid is not None else "parent: unknown"
            lines.append(f"PID {p.pid} ({p.name}, exe: {exe}, cmd: {cmd}, {parent}){tag}")
        return "\n".join(lines)

    def _format_flows(self, flows: List[Flow]) -> str:
        if not flows:
            return "No network activity recorded."
        lines = []
        for f in flows[:5]:
            pname = f.process_name or "unknown"
            lines.append(f"{pname} -> {f.dst_ip}:{f.dst_port} ({f.protocol})")
        return "\n".join(lines)

    def _parse_json_answer(self, answer: str) -> dict:
        """Extract JSON from model response, handling thinking tags, markdown fences, and boundary markers."""
        if not answer:
            raise ValueError("AI returned an empty response")

        # 1. Strip reasoning before </think> tag if present
        if "</think>" in answer:
            answer = answer.split("</think>", 1)[1].strip()

        # 2. Strip markdown ```json ... ``` if present
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", answer, re.DOTALL)
        if match:
            clean_text = match.group(1).strip()
            try:
                return json.loads(clean_text)
            except Exception:
                pass

        # 3. Find candidate JSON object containing "summary"
        end = answer.rfind("}")
        if end >= 0:
            for start in range(len(answer[:end])):
                if answer[start] == "{":
                    candidate = answer[start:end+1].strip()
                    try:
                        data = json.loads(candidate)
                        if isinstance(data, dict) and "summary" in data:
                            return data
                    except Exception:
                        continue

        # 4. Fallback search for any balanced JSON block
        for match in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", answer, re.DOTALL):
            try:
                data = json.loads(match.group(0))
                if isinstance(data, dict) and "summary" in data:
                    return data
            except Exception:
                continue

        # 5. Final fallback
        try:
            return json.loads(answer)
        except json.JSONDecodeError as e:
            raise ValueError(f"AI did not return valid JSON: {e}. Raw snippet: {answer[:300]}")

    async def _get_process_tree(self, session: AsyncSession, agent_id: Optional[str]) -> List[ProcessInfo]:
        """Fetch top 30 key processes prioritizing suspicious nodes, ancestors, and network bindings."""
        if not agent_id:
            return []

        # Pull suspicious processes first, then recent ones
        stmt = (
            select(ProcessInfo)
            .where(ProcessInfo.agent_id == agent_id)
            .order_by(ProcessInfo.is_suspicious.desc(), ProcessInfo.created_at.desc())
            .limit(60)
        )
        res = await session.execute(stmt)
        all_procs = list(res.scalars().all())

        if not all_procs:
            return []

        # Build dictionary by PID for ancestor tracing
        by_pid = {p.pid: p for p in all_procs}
        selected_pids: Set[int] = set()

        # Prioritize suspicious processes and trace their parent lineage
        for p in all_procs:
            if p.is_suspicious:
                selected_pids.add(p.pid)
                curr_parent = p.parent_pid
                for _ in range(3):
                    if curr_parent and curr_parent in by_pid:
                        selected_pids.add(curr_parent)
                        curr_parent = by_pid[curr_parent].parent_pid
                    else:
                        break

        # Fill up to 30 processes with remaining most recent processes
        final_list: List[ProcessInfo] = [p for p in all_procs if p.pid in selected_pids]
        for p in all_procs:
            if len(final_list) >= 30:
                break
            if p.pid not in selected_pids:
                final_list.append(p)
                selected_pids.add(p.pid)

        return final_list[:30]

    async def _get_recent_flows(
        self,
        session: AsyncSession,
        agent_id: Optional[str],
        ref_time: Optional[datetime],
        minutes: int = 15,
    ) -> List[Flow]:
        """Fetch up to 20 network flows within time window of the incident."""
        if not agent_id:
            return []

        target_time = ref_time or datetime.now(timezone.utc)
        stmt = (
            select(Flow)
            .where(Flow.agent_id == agent_id)
            .where(Flow.start_time <= target_time + timedelta(minutes=minutes))
            .where(Flow.start_time >= target_time - timedelta(minutes=minutes))
            .order_by(Flow.start_time.desc())
            .limit(20)
        )
        res = await session.execute(stmt)
        flows = list(res.scalars().all())

        # Fallback to latest 20 flows if none within window
        if not flows:
            fallback_stmt = (
                select(Flow)
                .where(Flow.agent_id == agent_id)
                .order_by(Flow.start_time.desc())
                .limit(20)
            )
            res = await session.execute(fallback_stmt)
            flows = list(res.scalars().all())

        return flows

    async def _get_risk_factors(
        self,
        session: AsyncSession,
        agent_id: Optional[str],
        ref_time: Optional[datetime],
        description: Optional[str],
    ) -> Dict[str, Any]:
        """Retrieve risk assessment factors from risk_score_records or fallback description."""
        factors = {}
        if agent_id:
            target_time = ref_time or datetime.now(timezone.utc)
            stmt = (
                select(RiskScoreRecord)
                .where(RiskScoreRecord.agent_id == agent_id)
                .where(RiskScoreRecord.timestamp <= target_time + timedelta(minutes=15))
                .where(RiskScoreRecord.timestamp >= target_time - timedelta(minutes=15))
                .order_by(RiskScoreRecord.timestamp.desc())
                .limit(1)
            )
            res = await session.execute(stmt)
            rrec = res.scalar_one_or_none()
            if rrec and rrec.factors and isinstance(rrec.factors, dict):
                factors = {k: v for k, v in rrec.factors.items() if k not in ("total_score", "score")}

        if not factors and description:
            parsed = _parse_factors(description)
            if parsed and isinstance(parsed, dict):
                factors = {k: v for k, v in parsed.items() if k not in ("total_score", "score")}

        return factors
