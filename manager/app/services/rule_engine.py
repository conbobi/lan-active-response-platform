import asyncio
import logging
import re
import time
import uuid
import yaml
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule_candidate import RuleCandidate
from app.models.incident import Incident
from app.schemas.enums import IncidentSeverity, IncidentStatus

logger = logging.getLogger("larp.services.rule_engine")


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: str
    mitre_techniques: List[str]
    matched_event: Dict[str, Any]
    detail: str


SAFE_PROCESSES = ['python3', 'python', 'node', 'bash', 'sh', 'xfwm4', 'systemd', 'dbus-daemon', 'xfce4-panel']
SUSPICIOUS_DIRS = ('/tmp', '/dev/shm', '/var/tmp')


def is_safe_process(event: Dict[str, Any]) -> bool:
    """
    Kiểm tra nếu tiến trình nằm trong SAFE_PROCESSES và không nằm trong thư mục tạm.
    Nếu đúng, trả về True để bỏ qua hoàn toàn, không tạo Incident, không chấm điểm.
    """
    if not isinstance(event, dict):
        return False

    proc_name = str(
        event.get("process_name")
        or event.get("name")
        or event.get("process")
        or event.get("Image")
        or ""
    ).strip().lower()
    base_name = proc_name.replace("\\", "/").split("/")[-1]

    safe_set = {p.lower() for p in SAFE_PROCESSES}
    if base_name in safe_set or proc_name in safe_set:
        exe_path = str(
            event.get("exe")
            or event.get("exe_path")
            or event.get("path")
            or event.get("Image")
            or ""
        ).strip().lower()
        # Nếu nằm trong thư mục tạm /tmp, /dev/shm, /var/tmp -> không an toàn (có thể là mã độc mạo danh)
        in_temp = any(exe_path.startswith(d) or f"{d}/" in exe_path for d in SUSPICIOUS_DIRS)
        if not in_temp:
            return True

    return False


def is_reverse_shell_match(m: RuleMatch) -> bool:
    """Kiểm tra match có phải là Reverse Shell / Command Interpreter không (T1059)."""
    shell_techniques = {"T1059", "T1059.004", "T1059.001", "T1059.003"}
    if any(t in shell_techniques for t in m.mitre_techniques):
        return True
    r_name = m.rule_name.lower()
    return any(k in r_name for k in ("reverse shell", "unix shell", "command execution", "shell spawned", "interactive shell"))


def is_generic_network_match(m: RuleMatch) -> bool:
    """Kiểm tra match có phải là generic network abnormal / beaconing (T1071) không."""
    if any(str(t).startswith("T1071") for t in m.mitre_techniques):
        return True
    r_name = m.rule_name.lower()
    return any(k in r_name for k in ("beaconing", "application layer", "network abnormal"))


def is_suspicious_for_t1071(event: Dict[str, Any]) -> bool:
    """
    Chỉ gán nhãn T1071 (Application Layer Protocol) nếu tiến trình ĐÃ BỊ COI LÀ ĐÁNG NGỜ:
    - is_suspicious == True
    - hoặc exe nằm trong thư mục nguy hiểm (/tmp, /dev/shm, /var/tmp)
    - hoặc CommandLine chứa /dev/tcp, nc -e, ncat, pty.spawn, socket.socket, curl | sh, wget | sh
    - Không được tự động gán T1071 chỉ vì tiến trình hệ thống / bình thường có kết nối mạng.
    """
    if not isinstance(event, dict):
        return False
    if event.get("is_suspicious"):
        return True
    cmdline = str(event.get("cmdline") or "").lower()
    if any(p in cmdline for p in ("/dev/tcp/", "nc -e", "ncat -e", "pty.spawn", "socket.socket", "curl |", "wget |")):
        return True
    exe_path = str(event.get("exe") or event.get("exe_path") or event.get("path") or event.get("Image") or "").lower()
    if any(exe_path.startswith(d) or f"{d}/" in exe_path for d in SUSPICIOUS_DIRS):
        return True
    return False


class RuleEngine:
    """
    Evaluate active Sigma rules against telemetry from agent.
    Cache active rules 60s, hot-reload after activate/disable.
    """

    CACHE_TTL_SEC = 60
    SUPPORTED_SEVERITIES = {"low", "medium", "high", "critical"}

    def __init__(self):
        self._cached_rules: List[Dict[str, Any]] = []
        self._cache_loaded_at: float = 0.0
        self._lock = asyncio.Lock()

    async def evaluate(
        self,
        telemetry: Dict[str, Any],
        session: AsyncSession,
    ) -> List[Incident]:
        """Evaluate all active rules against telemetry, create Incidents for matches."""
        rules = await self._get_active_rules(session)
        if not rules:
            return []

        agent_id = telemetry.get("agent_id")
        if not agent_id:
            logger.warning("rule_engine.evaluate: missing agent_id in telemetry")
            return []

        matches: List[RuleMatch] = []
        for rule in rules:
            try:
                rule_matches = self._evaluate_rule(rule, telemetry)
                matches.extend(rule_matches)
            except Exception as e:
                logger.error(f"rule_engine: rule '{rule.get('rule_name')}' eval failed: {e}")
                continue

        if not matches:
            return []

        # Lọc bỏ matches nếu process_name hoặc Image nằm trong SAFE_PROCESSES và không ở /tmp, /dev/shm, /var/tmp
        filtered_matches = []
        for m in matches:
            event = m.matched_event
            if is_safe_process(event):
                # Ngoại lệ: chỉ giữ lại nếu match là reverse shell thực sự với payload độc hại trên cmdline
                if is_reverse_shell_match(m) and any(
                    re.search(pat, str(event.get("cmdline") or ""), re.IGNORECASE)
                    for pat in (r"/dev/tcp/", r"\bbash\s+-[a-zA-Z]*i", r"\bsh\s+-[a-zA-Z]*i", r"\bpty\.spawn", r"\bsocket\.socket")
                ):
                    filtered_matches.append(m)
                    continue

                logger.info(
                    f"rule_engine: suppressed safe process '{event.get('name') or event.get('process_name') or event.get('Image')}' "
                    f"(rule '{m.rule_name}') - not in suspicious dirs (/tmp, /dev/shm, /var/tmp)"
                )
                continue
            filtered_matches.append(m)
        matches = filtered_matches

        if not matches:
            return []

        # Lọc bỏ generic network match (T1071) nếu tiến trình không bị coi là đáng ngờ
        # (Chỉ gán T1071 nếu tiến trình đáng ngờ / reverse shell / path độc hại)
        filtered_matches = []
        for m in matches:
            event = m.matched_event
            if is_generic_network_match(m) and not is_suspicious_for_t1071(event):
                logger.info(
                    f"rule_engine: suppressed T1071 rule '{m.rule_name}' for non-suspicious process "
                    f"'{event.get('name') or event.get('process_name') or event.get('Image')}'"
                )
                continue
            # Nếu match có chứa tag T1071 nhưng tiến trình không đáng ngờ, loại bỏ tag T1071 khỏi mitre_techniques
            if not is_suspicious_for_t1071(event):
                m.mitre_techniques = [t for t in m.mitre_techniques if not str(t).startswith("T1071")]
            filtered_matches.append(m)
        matches = filtered_matches

        if not matches:
            return []

        # Ưu tiên Reverse Shell (T1059 / T1059.004) lên đầu
        matches.sort(
            key=lambda m: (
                1 if is_reverse_shell_match(m) else 0,
                self._severity_to_score(m.severity)
            ),
            reverse=True
        )

        # Nếu trong batch đã có Reverse Shell match, loại bỏ các generic network match (T1071)
        has_reverse_shell = any(is_reverse_shell_match(m) for m in matches)
        if has_reverse_shell:
            filtered_matches = []
            for m in matches:
                if is_generic_network_match(m):
                    logger.info(
                        f"rule_engine: suppressed T1071 generic network match '{m.rule_name}' "
                        f"in favor of T1059 Reverse Shell for agent={agent_id}"
                    )
                    continue
                filtered_matches.append(m)
            matches = filtered_matches

        incidents = await self._create_incidents(matches, telemetry, agent_id, session)
        if incidents:
            logger.info(
                f"rule_engine: {len(incidents)} incident(s) created for agent={agent_id} "
                f"from {len(matches)} match(es)"
            )
        return incidents

    async def _get_active_rules(self, session: AsyncSession) -> List[Dict[str, Any]]:
        """Load active rules từ DB, cache 60s."""
        async with self._lock:
            now = time.time()
            if now - self._cache_loaded_at < self.CACHE_TTL_SEC and self._cached_rules:
                return self._cached_rules

            stmt = select(RuleCandidate).where(RuleCandidate.status == "active")
            result = await session.execute(stmt)
            rules_db = result.scalars().all()

            parsed_rules = []
            for r in rules_db:
                try:
                    rule_dict = yaml.safe_load(r.rule_yaml or "")
                    if not isinstance(rule_dict, dict):
                        continue

                    # Parse mitre_techniques safely
                    mitre = r.mitre_techniques
                    if isinstance(mitre, list):
                        mitre_list = mitre
                    elif isinstance(mitre, str):
                        mitre_list = [mitre]
                    elif isinstance(mitre, dict):
                        mitre_list = list(mitre.values())
                    else:
                        mitre_list = rule_dict.get("tags") or []

                    parsed_rules.append({
                        "id": str(r.id),
                        "rule_name": r.rule_name or rule_dict.get("title", "Unnamed Rule"),
                        "severity": (r.severity or rule_dict.get("level", "medium")).lower(),
                        "mitre_techniques": mitre_list,
                        "detection": rule_dict.get("detection", {}),
                        "logsource": rule_dict.get("logsource", {}),
                    })
                except yaml.YAMLError as e:
                    logger.warning(f"rule_engine: invalid YAML for rule {r.id}: {e}")
                    continue

            self._cached_rules = parsed_rules
            self._cache_loaded_at = now
            logger.debug(f"rule_engine: reloaded {len(parsed_rules)} active rules")
            return parsed_rules

    def _evaluate_rule(self, rule: Dict[str, Any], telemetry: Dict[str, Any]) -> List[RuleMatch]:
        """
        Evaluate 1 Sigma rule against telemetry.
        Support các kiểu match cơ bản của Sigma:
          - Process: process_list[].name, cmdline, exe, parent_pid
          - Network: network_connections[].dst_port, dst_ip
          - File: FIM alerts (nếu telemetry có file_changes)
        """
        detection = rule.get("detection") or {}
        if not detection:
            return []

        selection = detection.get("selection")
        if not selection or not isinstance(selection, dict):
            return []

        matches: List[RuleMatch] = []

        logsource = rule.get("logsource") or {}
        category = str(logsource.get("category") or logsource.get("product") or "process_creation").lower()

        candidates = self._get_candidates(telemetry, category)

        for event in candidates:
            # Bỏ qua nếu là tiến trình trong SAFE_PROCESSES và không ở thư mục tạm
            if is_safe_process(event):
                cmdline = str(event.get("cmdline") or "")
                if not any(pat in cmdline for pat in ("/dev/tcp/", "-i", "pty.spawn", "socket.socket")):
                    continue
            try:
                if self._match_selection(selection, event):
                    matches.append(RuleMatch(
                        rule_id=rule["id"],
                        rule_name=rule["rule_name"],
                        severity=rule["severity"],
                        mitre_techniques=rule["mitre_techniques"],
                        matched_event=event,
                        detail=self._build_detail(selection, event),
                    ))
            except Exception as e:
                logger.debug(f"_match_selection error: {e}")
                continue

        return matches

    def _get_candidates(self, telemetry: Dict[str, Any], category: str) -> List[Dict[str, Any]]:
        """Trả về list event cần match, dựa vào loại logsource."""
        if "process" in category or "endpoint" in category:
            return telemetry.get("process_list") or telemetry.get("processes") or []
        if "network" in category:
            return telemetry.get("network_connections") or telemetry.get("conns") or []
        if "file" in category:
            return telemetry.get("file_changes") or telemetry.get("fim_alerts") or []

        # Fallback: gộp process + network
        procs = telemetry.get("process_list") or telemetry.get("processes") or []
        conns = telemetry.get("network_connections") or telemetry.get("conns") or []
        return procs + conns

    def _match_selection(self, selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """
        Match 1 selection dict lên 1 event.
        Hỗ trợ các modifier: |contains, |endswith, |startswith, |re, |in
        """
        for key, expected in selection.items():
            if isinstance(expected, list):
                # OR logic cho list các giá trị
                if not any(self._match_field(key, v, event) for v in expected):
                    return False
            elif isinstance(expected, dict):
                # Nested criteria (nếu có)
                continue
            else:
                if not self._match_field(key, expected, event):
                    return False
        return True

    def _match_field(self, key_spec: str, expected: Any, event: Dict[str, Any]) -> bool:
        """
        Match 1 field với modifier. Ví dụ:
          - "CommandLine|contains" → check 'contains' trên field 'cmdline'
          - "Image|endswith" → check 'endswith' trên field 'exe'
        """
        parts = key_spec.split("|")
        field_name = parts[0].strip()
        modifiers = [m.strip().lower() for m in parts[1:]]

        # Alias mapping (Sigma field → telemetry key)
        field_aliases = {
            "commandline": "cmdline",
            "cmdline": "cmdline",
            "image": "exe",
            "exe": "exe",
            "process": "exe",
            "processname": "name",
            "name": "name",
            "processid": "pid",
            "pid": "pid",
            "parentprocessid": "parent_pid",
            "parent_pid": "parent_pid",
            "parentimage": "parent_exe",
            "parent_exe": "parent_exe",
            "destinationport": "dst_port",
            "dst_port": "dst_port",
            "destinationip": "dst_ip",
            "dst_ip": "dst_ip",
            "sourceport": "src_port",
            "src_port": "src_port",
            "sourceip": "src_ip",
            "src_ip": "src_ip",
            "targetfilename": "file_path",
            "file_path": "file_path",
        }
        actual_key = field_aliases.get(field_name.lower(), field_name.lower())
        actual_value = event.get(actual_key)

        # Fallback cho process/image: nếu exe rỗng, thử name
        if actual_value is None and actual_key in ("exe", "name"):
            actual_value = event.get("name") or event.get("exe") or event.get("process")

        # Fallback cho parent: nếu parent_exe rỗng, thử parent_name hoặc parent
        if actual_value is None and actual_key == "parent_exe":
            actual_value = event.get("parent_exe") or event.get("parent_name") or event.get("parent")

        # Logic trace parent: nếu không tìm thấy parent (None, 0, rỗng, unknown), không được tự động match hay cộng rủi ro
        # Không trace process nếu parent_pid < 100 (ngoại trừ nếu rule tìm đích danh PID 1 hoặc systemd)
        if actual_key in ("parent_pid", "parent_exe"):
            if actual_value is None or str(actual_value).strip().lower() in ("", "0", "none", "null", "unknown", "-1"):
                return False
            if actual_key == "parent_pid":
                try:
                    val_int = int(actual_value)
                    if val_int < 100 and val_int != 1 and str(expected).strip() not in (str(val_int), "systemd"):
                        return False
                except (ValueError, TypeError):
                    pass

        if actual_value is None:
            return False

        actual_str = str(actual_value).lower()
        expected_str = str(expected).lower()

        for mod in modifiers:
            if mod == "contains":
                if expected_str not in actual_str:
                    return False
            elif mod == "endswith":
                if not actual_str.endswith(expected_str):
                    return False
            elif mod == "startswith":
                if not actual_str.startswith(expected_str):
                    return False
            elif mod in ("re", "regex"):
                try:
                    if not re.search(str(expected), str(actual_value), re.IGNORECASE):
                        return False
                except re.error:
                    return False
            elif mod == "in":
                if isinstance(actual_value, list):
                    if expected_str not in [str(x).lower() for x in actual_value]:
                        return False
                else:
                    if expected_str not in actual_str:
                        return False
            else:
                # Modifiers khác hoặc exact match
                if actual_str != expected_str:
                    return False

        # Nếu không có modifier: so sánh exact (hoặc number)
        if not modifiers:
            if isinstance(actual_value, (int, float)) and isinstance(expected, (int, float)):
                if actual_value != expected:
                    return False
            elif actual_str != expected_str:
                return False

        return True

    def _build_detail(self, selection: Dict[str, Any], event: Dict[str, Any]) -> str:
        """Human-readable detail để show cho analyst."""
        parts = []
        for k in selection.keys():
            field_name = k.split("|")[0].strip()
            val = event.get(field_name.lower()) or event.get(field_name)
            if val:
                parts.append(f"{field_name}={val}")
        return ", ".join(parts[:3]) or "Matched Sigma pattern"

    async def _create_incidents(
        self,
        matches: List[RuleMatch],
        telemetry: Dict[str, Any],
        agent_id: str,
        session: AsyncSession,
    ) -> List[Incident]:
        """
        Tạo Incident cho mỗi match.
        DEDUP: nếu cùng (rule_name, agent_id) đã có incident mở trong 5 phút → bỏ qua.
        """
        cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=300)
        recent_stmt = select(Incident).where(
            Incident.agent_id == agent_id,
            Incident.created_at >= cutoff_dt,
        )
        recent = (await session.execute(recent_stmt)).scalars().all()

        sev_map = {
            "low": IncidentSeverity.LOW,
            "medium": IncidentSeverity.MEDIUM,
            "high": IncidentSeverity.HIGH,
            "critical": IncidentSeverity.CRITICAL,
        }

        # Kiểm tra xem agent đã có incident Reverse Shell (T1059) nào trong 5 phút qua không
        has_recent_shell_incident = any(
            (
                "T1059" in (inc.description or "")
                or "reverse shell" in (inc.title or "").lower()
                or "shell" in (inc.title or "").lower()
            )
            for inc in recent
        )

        created = []
        for m in matches:
            # Dedup check
            if any(self._is_same_rule_incident(inc, m) for inc in recent):
                logger.debug(f"rule_engine: dedup skip rule={m.rule_name} agent={agent_id}")
                continue

            # Nếu đã có Reverse Shell incident gần đây, không sinh thêm generic network incident (T1071)
            if has_recent_shell_incident and is_generic_network_match(m):
                logger.info(
                    f"rule_engine: suppressed T1071 rule '{m.rule_name}' for agent={agent_id} "
                    f"due to active T1059 reverse shell in last 5m"
                )
                continue

            inc_id = f"inc_{uuid.uuid4().hex[:12]}"
            incident = Incident(
                id=inc_id,
                agent_id=agent_id,
                title=f"[{m.severity.upper()}] {m.rule_name}",
                description=(
                    f"Rule: {m.rule_name}\n"
                    f"Rule ID: {m.rule_id}\n"
                    f"Severity: {m.severity}\n"
                    f"MITRE: {', '.join(m.mitre_techniques) if m.mitre_techniques else 'N/A'}\n"
                    f"Detail: {m.detail}\n"
                    f"Agent: {agent_id}"
                ),
                severity=sev_map.get(m.severity.lower(), IncidentSeverity.MEDIUM),
                status=IncidentStatus.OPEN,
                risk_score=float(self._severity_to_score(m.severity)),
                notes=f"rule_id:{m.rule_id} | Auto-generated by LARP AI Rule Engine",
            )
            session.add(incident)
            created.append(incident)
            # Add to local recent list for deduplicating multiple matches in the same batch
            recent.append(incident)

        if created:
            await session.commit()
            for inc in created:
                await session.refresh(inc)
        return created

    def _is_same_rule_incident(self, incident: Incident, match: RuleMatch) -> bool:
        """Kiểm tra incident trùng lặp theo rule_id hoặc rule_name."""
        if incident.notes and f"rule_id:{match.rule_id}" in incident.notes:
            return True
        if incident.description and f"Rule ID: {match.rule_id}" in incident.description:
            return True
        return match.rule_name in (incident.title or "")

    def _severity_to_score(self, severity: str) -> int:
        return {"low": 30, "medium": 50, "high": 75, "critical": 95}.get(severity.lower(), 50)

    def invalidate_cache(self) -> None:
        """Call sau khi activate/disable rule để reload lần evaluate tiếp theo."""
        self._cache_loaded_at = 0.0
        self._cached_rules = []


# Singleton instance
rule_engine = RuleEngine()

