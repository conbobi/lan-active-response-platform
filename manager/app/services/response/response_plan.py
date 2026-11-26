"""Readable analysis and multi-action response plan for an incident (P5/P6).

The plan is derived from the deterministic pattern assessment and its playbook. Executable items are
only available when ``investigate()`` produced a matching evidence-scoped candidate, so the plan can
never offer an action the Response Assist routes would refuse. Knowledge references and similar cases
are reference material and are kept apart from incident evidence.
"""
from __future__ import annotations

import hashlib
import logging
import re

from app.core import response_outcome as oc
from app.core.config import settings
from app.schemas.enums import IncidentStatus
from app.services.ai.analysis_cache import cached_search, find_similar, fingerprint
from app.services.ai.knowledge import pattern_engine
from app.services.response import lab_waf
from app.services.response.assist_policy import decision
from app.services.response.http_investigation import ASSIST_TYPES, BLOCK, COLLECT, GUIDE, RATE, REVOKE, WATCH, http_behavior

logger = logging.getLogger(__name__)

HISTORICAL = {IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE}
ENFORCEMENT = {BLOCK, RATE, REVOKE, WATCH}
HOST_ACTIONS = {"kill_process_tree", "isolate"}
LIFECYCLE_ONLY = {"release_ip_block", "verify_block_enforcement"}
POST_EXPLOITATION_PLAYBOOK = "web_post_exploitation"
PARAMETERIZATION_REFS = ("owasp-sqli-prevention:primary-defenses:0", "owasp-sqli-prevention:parameterized-queries:0",
                         "owasp-sqli-prevention:manually-escaping-strongly-discouraged:0", "owasp-sqli-prevention:input-validation:0")
SEVERITY_BY_LEVEL = {0: "low", 1: "low", 2: "medium", 3: "high", 4: "critical"}
IMPACT_BY_LEVEL = {
    0: "Chưa xác định được tác động từ bằng chứng hiện có.",
    1: "Chỉ có chỉ báo công cụ; chưa thấy payload hay kết quả phía ứng dụng. Tác động thực tế chưa xác định.",
    2: "Ứng dụng đang bị dò SQL injection. Nếu truy vấn không được tham số hóa, kẻ tấn công có thể vượt qua đăng nhập hoặc đọc dữ liệu.",
    3: "Có phản hồi bất thường của ứng dụng tương quan với request độc hại; khả năng đã khai thác cần xác minh gấp.",
    4: "Ứng dụng đã cấp phiên dù thông tin đăng nhập sai: truy cập trái phép đã xảy ra.",
}
# Non-SQLi ladders: (severity, impact) by level name. SQLi uses the numeric ladder above.
DANGER_BY_LEVEL_NAME = {
    "automation_indicator": ("low", "Chỉ là chỉ báo client tự động (User-Agent tự khai báo); chưa có bằng chứng tấn công."),
    "repeated_auth_failures": ("low", "Nhiều lần đăng nhập thất bại nhưng chưa đạt tiêu chí brute force."),
    "authentication_brute_force": ("medium", "Đang có tấn công đoán mật khẩu. Nếu mật khẩu yếu, tài khoản mục tiêu có thể bị chiếm."),
    "brute_force_success": ("critical", "Một lần đăng nhập thành công theo sau chuỗi thất bại: tài khoản có thể đã bị chiếm."),
    "inbound_port_contacts": ("low", "Có kết nối tới nhiều cổng; có thể là dò quét, chưa xác định mục đích."),
    "service_scanning": ("medium", "Dịch vụ đang bị dò quét; đây thường là bước trinh sát trước khai thác."),
    "suspicious_shell_socket": ("high", "Shell có socket mạng nhưng chưa liên kết đủ process, socket và FD để kết luận."),
    "reverse_shell_confirmed": ("critical", "Shell được điều khiển qua kết nối mạng: máy chủ có thể đã bị chiếm quyền."),
    "related_host_activity": ("medium", "Có hoạt động host liên quan theo thời gian nhưng chưa xác minh tương quan."),
    "web_server_spawned_shell": ("critical", "Ứng dụng web đã sinh shell: thực thi lệnh từ xa đã xảy ra."),
}
RESULT_GROUPS = {
    "applied": {"succeeded", "partial", "monitoring", "verifying", "dispatched", "executing"},
    "blocked": {"rejected", "not_recommended", "expired"},
    "failed": {"failed", "rollback_failed"},
    "awaiting_approval": {"pending_approval", "approved"},
    "rolled_back": {"rolled_back"},
    "mock": {"mock_succeeded"},
}
EVIDENCE_TAG = re.compile(r"\s*\[evidence:\s*([^\]]+)\]")
LAB_LOGIN_DIFF = """--- agent/vulnerable_web/app.py (login, LAB — cố ý có lỗ hổng)
+++ hardened mode (đề xuất, cần phê duyệt, không tự áp dụng)
-        query = (
-            f"SELECT * FROM users "
-            f"WHERE username='{username}' "
-            f"AND password="
-            f"'{hashlib.md5(password.encode()).hexdigest()}'"
-        )
-        c.execute(query)
+        # Tham số hóa: dữ liệu người dùng không bao giờ trở thành cú pháp SQL.
+        c.execute(
+            "SELECT id, username, password FROM users WHERE username = ?",
+            (username,),
+        )
+        user = c.fetchone()
+        # So sánh băm ngoài SQL; chuyển sang bcrypt/argon2 thay cho MD5 ở bước tiếp theo.
+        if user and hmac.compare_digest(user[2], hashlib.md5(password.encode()).hexdigest()):
+            ...
"""


def is_historical(incident) -> bool:
    return incident.status in HISTORICAL


def _short(value, limit=400):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _split_refs(statement: str) -> dict:
    refs = [ref.strip() for match in EVIDENCE_TAG.findall(statement) for ref in match.split(",") if ref.strip()]
    return {"text": EVIDENCE_TAG.sub("", statement).strip(), "evidence_refs": refs}


def _kb():
    try:
        from app.services.ai.knowledge.kb_store import knowledge_base
        return knowledge_base
    except Exception:  # pragma: no cover - the plan degrades to no knowledge refs
        logger.exception("Knowledge base unavailable")
        return None


def _knowledge_refs(kb, spec) -> list[str]:
    if kb is None or not isinstance(spec, dict) or not spec.get("terms"):
        return []
    try:
        chunks = cached_search(kb, spec["terms"], categories=spec.get("categories") or None,
                               attack_ids=spec.get("attack_ids") or None, limit=2)
    except Exception:
        logger.exception("Knowledge lookup failed")
        return []
    return [chunk.chunk_id for chunk in chunks]


def _knowledge_view(kb, refs) -> list[dict]:
    items = []
    for ref in dict.fromkeys(refs):
        chunk = kb.get(ref) if kb is not None else None
        if chunk is None:
            continue
        items.append({**chunk.citation(), "excerpt": _short(chunk.text)})
        if len(items) == 5:
            break
    return items


def _unavailable_reason(kind, incident, investigation):
    """Explain why investigate() produced no candidate of this type."""
    if investigation is None:
        return "Chưa có bằng chứng HTTP tương quan cho sự cố này.", oc.INSUFFICIENT_EVIDENCE
    if kind in (BLOCK, RATE):
        if not settings.HTTP_RESPONSE_LAB_WAFS.get(incident.agent_id):
            return ("Chưa cấu hình điểm thực thi HTTP (lab WAF) cho Agent này; không thể chặn hoặc giới hạn tốc độ.",
                    oc.EXECUTOR_UNAVAILABLE)
        peers = {fact.get("source_ip") for fact in investigation.get("observed_facts", [])}
        if not any(lab_waf.eligible(incident.agent_id, peer) for peer in peers if peer):
            return ("Nguồn không thuộc danh sách peer thử nghiệm được phép chặn (hoặc là peer được bảo vệ).",
                    oc.POLICY_DENIED)
        if not any(fact.get("payload_indicators") for fact in investigation.get("observed_facts", [])):
            return "Chưa có payload SQL trong request; chỉ báo công cụ không đủ để chặn.", oc.INSUFFICIENT_EVIDENCE
        return ("Nguồn chưa được xác minh kết nối trực tiếp (qua proxy/forwarded, hoặc quan sát đã quá 5 phút).",
                oc.INSUFFICIENT_EVIDENCE)
    if kind == REVOKE:
        return ("Chưa có phiên được cấp tương quan với xác minh sai thông tin đăng nhập phía ứng dụng.",
                oc.INSUFFICIENT_EVIDENCE)
    return "Chưa có bằng chứng HTTP tương quan cho hành động này.", oc.INSUFFICIENT_EVIDENCE


def _plan_item(incident, playbook_id, spec, *, investigation, candidates, actions_by_type, kb, verified_host, historical):
    kind = spec["action_type"]
    item = {
        "plan_id": hashlib.sha256(f"{incident.id}|{playbook_id}|{kind}".encode()).hexdigest()[:16],
        "action_type": kind, "title": spec.get("description", kind), "category": spec.get("category", "investigation"),
        "priority": int(spec.get("priority", 99)), "execution": spec.get("execution", "advisory"),
        "why": spec.get("description", ""), "evidence_ids": [], "expected_effect": spec.get("description", ""),
        "operational_risk": spec.get("operational_risk", "unknown"), "rollback": spec.get("rollback", ""),
        "verification_method": spec.get("verification_method", ""),
        "depends_on": list(spec.get("depends_on") or []), "conflicts_with": list(spec.get("conflicts_with") or []),
        "requires_approval": True, "policy_decision": "ADVISORY_ONLY", "available": False,
        "disabled_reason": None, "outcome_code": None, "proposal_action_id": None, "action": None,
        "knowledge_refs": _knowledge_refs(kb, spec.get("knowledge")), "related_incident_id": None, "remediation": None,
    }
    if kind in ASSIST_TYPES:
        candidate = candidates.get(kind)
        existing = actions_by_type.get(kind)
        item["action"] = existing
        if candidate:
            item.update(proposal_action_id=candidate["action_id"], evidence_ids=list(candidate["evidence_ids"]),
                        expected_effect=candidate.get("expected_effect") or item["expected_effect"],
                        why=f"{spec.get('description', '')} Căn cứ: {candidate.get('rationale', '')}".strip(),
                        requires_approval=bool(candidate.get("requires_approval", True)),
                        policy_decision="ALLOW_AUTOMATIC" if kind == GUIDE else "REQUIRE_APPROVAL", available=True)
        else:
            reason, code = _unavailable_reason(kind, incident, investigation)
            item.update(disabled_reason=reason, outcome_code=code,
                        policy_decision="DENY" if code == oc.POLICY_DENIED else "REQUIRE_MORE_EVIDENCE")
        if historical and kind in ENFORCEMENT:
            item.update(available=False, policy_decision="DENY", outcome_code=oc.POLICY_DENIED,
                        disabled_reason="Sự cố đã đóng: chỉ cho phép phân tích và thu thập chỉ đọc, không áp dụng chặn/giám sát mới.")
        return item
    if kind in HOST_ACTIONS:
        if not verified_host:
            return None
        source = verified_host[0]
        item.update(available=not historical, related_incident_id=source.get("source_incident_id"),
                    evidence_ids=list(source.get("evidence_refs") or []), policy_decision="REQUIRE_APPROVAL",
                    why=f"{spec.get('description', '')} Căn cứ: {source.get('reason', '')}".strip())
        if historical:
            item.update(policy_decision="DENY", outcome_code=oc.POLICY_DENIED,
                        disabled_reason="Sự cố đã đóng: không đề xuất ngăn chặn trên host.")
        return item
    item["execution"] = "advisory"
    if kind in LIFECYCLE_ONLY:
        item["disabled_reason"] = "Thực hiện trong vòng đời của hành động chặn (xác minh hoặc rollback), không chạy riêng."
    else:
        item["disabled_reason"] = "Khuyến nghị cho quản trị viên/nhà phát triển, không thực thi tự động."
    item["requires_approval"] = False
    if kind == "recommend_parameterized_queries":
        # Pinned to the OWASP primary-defense prose: free-text search ranks per-language code samples
        # (Perl, Ruby INSERTs) above the guidance the analyst actually needs.
        refs = [ref for ref in PARAMETERIZATION_REFS if kb is not None and kb.get(ref)] or item["knowledge_refs"]
        item["knowledge_refs"] = refs
        guidance = [_short(kb.get(ref).text, 300) for ref in refs if kb is not None and kb.get(ref)
                    and not kb.get(ref).text.lstrip().startswith("```")]
        item["remediation"] = {
            "guidance": guidance or ["Dùng truy vấn tham số hóa (prepared statements); lọc đầu vào không thay thế tham số hóa."],
            "secure_code_diff": LAB_LOGIN_DIFF,
            "applies_to": "agent/vulnerable_web/app.py login() — ứng dụng LAB cố ý có lỗ hổng; bản vá thuộc chế độ hardened riêng.",
            "requires_approval": True,
        }
    return item


def _evidence_rows(incident, investigation):
    behavior = http_behavior(incident)
    rows = []
    for fact in (investigation or {}).get("observed_facts", []):
        parts = []
        if fact.get("method"):
            parts.append(f"{fact['method']} {behavior.get('request_path') or ''}".strip())
        if fact.get("http_status"):
            parts.append(f"HTTP {fact['http_status']}")
        if fact.get("automation_hint"):
            parts.append(f"User-Agent tự khai báo: {fact['automation_hint']}")
        if fact.get("payload_indicators"):
            parts.append("Chỉ báo payload: " + ", ".join(fact["payload_indicators"]))
        if fact.get("outcome"):
            parts.append(f"Kết quả ứng dụng: {fact['outcome']}")
        rows.append({"evidence_id": ", ".join(fact.get("evidence_ids") or []), "source": fact.get("source_ip"),
                     "target": f"{incident.agent_id} ({behavior.get('service') or fact.get('provenance')})",
                     "time": fact.get("observed_at"), "behavior": "; ".join(parts) or fact.get("provenance")})
    return rows


def _what_happened(incident, assessment, investigation):
    sentences = [assessment.conclusion] if assessment and assessment.level else []
    facts = (investigation or {}).get("observed_facts", [])
    if facts:
        sources = sorted({f.get("source_ip") for f in facts if f.get("source_ip")})
        sentences.insert(0, f"Agent {incident.agent_id} ghi nhận {len(facts)} quan sát HTTP từ "
                            f"{', '.join(sources) or 'nguồn chưa xác định'} (lần cuối {facts[-1].get('observed_at')}).")
    if not sentences:
        sentences.append("Chưa có bằng chứng HTTP tương quan để mô tả sự cố này.")
    return " ".join(sentences[:3])


def _results(actions):
    grouped = {key: [] for key in RESULT_GROUPS}
    for action in actions:
        for key, states in RESULT_GROUPS.items():
            if action.get("status") in states:
                grouped[key].append(action.get("action_id"))
    return grouped


async def _similar(db, incident, investigation):
    if not investigation:
        return []
    try:
        matches = await find_similar(db, fingerprint(investigation), tenant=incident.agent_id,
                                     exclude_incident_id=incident.id, threshold=0.8, limit=3)
    except Exception:
        logger.exception("Similar-case lookup failed for %s", incident.id)
        return []
    return [{"incident_id": m.incident_id, "similarity": round(m.similarity, 3), "classification": m.classification,
             "analyst_label": m.analyst_label, "playbook_id": getattr(m, "playbook_id", None)} for m in matches]


async def build(db, incident, investigation, actions, *, kb=None):
    """Return (analysis, plan) following the Response Assist API contract."""
    kb = kb if kb is not None else _kb()
    historical = is_historical(incident)
    try:
        host = await pattern_engine.related_host_evidence(db, incident)
    except Exception:
        logger.exception("Host evidence correlation failed for %s", incident.id)
        host = []
    source = investigation or http_behavior(incident) or (incident.detection_evidence or {})
    try:
        assessment = pattern_engine.assess(source, host_evidence=host, kb=kb)
    except Exception:
        logger.exception("Pattern assessment failed for %s", incident.id)
        assessment = None
    behavior = (incident.detection_evidence or {}).get("behavior") if isinstance(incident.detection_evidence, dict) else None
    if (assessment is None or not assessment.level) and isinstance(behavior, dict) and behavior is not source:
        # investigate() summarises some evidence types under its own labels (e.g. observed_login_failures);
        # the stored detection behavior carries the classification the pattern ladders are defined on.
        try:
            fallback = pattern_engine.assess(behavior, host_evidence=host, kb=kb)
            if fallback.level:
                assessment = fallback
        except Exception:
            logger.exception("Behavior assessment failed for %s", incident.id)
    verified_host = [item for item in (assessment.post_exploitation if assessment else ())
                     if item.get("correlation") == "verified" and item.get("status") == "correlated"]
    candidates = {}
    for candidate in (investigation or {}).get("recommended_responses", []):
        candidates.setdefault(candidate["action_type"], candidate)
    actions_by_type = {}
    for action in actions:
        actions_by_type.setdefault(action.get("action_type"), action)

    plan = []
    books = [assessment.playbook_id] if assessment and assessment.playbook_id else []
    if verified_host:
        # Verified post-exploitation adds the host playbook (process termination, containment) to the
        # incident's own playbook; unverified related activity never does.
        books.append(POST_EXPLOITATION_PLAYBOOK)
    for book_id in books:
        for spec in (pattern_engine.playbook(book_id) or {}).get("actions", []):
            item = _plan_item(incident, book_id, spec, investigation=investigation, candidates=candidates,
                              actions_by_type=actions_by_type, kb=kb, verified_host=verified_host, historical=historical)
            if item and all(existing["action_type"] != item["action_type"] for existing in plan):
                plan.append(item)
    plan.sort(key=lambda item: (item["priority"], item["action_type"]))

    level = assessment.level if assessment else 0
    if assessment is not None and assessment.pattern_id != "sqli" and assessment.level_name in DANGER_BY_LEVEL_NAME:
        severity, impact = DANGER_BY_LEVEL_NAME[assessment.level_name]
    else:
        severity, impact = SEVERITY_BY_LEVEL.get(level, "medium"), IMPACT_BY_LEVEL.get(level, IMPACT_BY_LEVEL[0])
    if verified_host:
        severity = "critical"
        impact = "Ứng dụng web đã sinh shell có kết nối mạng đã xác minh: máy chủ có thể đã bị chiếm quyền điều khiển."
    analysis = {
        "what_happened": _what_happened(incident, assessment, investigation),
        "evidence": _evidence_rows(incident, investigation),
        "assessment": {
            "level": {"pattern_id": assessment.pattern_id if assessment else None, "level": level,
                      "level_name": assessment.level_name if assessment else "unmatched",
                      "conclusion": assessment.conclusion if assessment else ""},
            "confirmed": [_split_refs(text) for text in (assessment.confirmed_facts if assessment else ())],
            "suspected": list(assessment.suspected if assessment else ()),
            "missing": list(dict.fromkeys([*(assessment.missing_evidence if assessment else ()),
                                           *((investigation or {}).get("missing_evidence") or [])])),
            "alternative_explanations": list(assessment.alternative_explanations if assessment else ()),
        },
        "attack_mapping": [{"technique_id": m.technique_id, "name": m.name, "evidence_refs": list(m.evidence_refs),
                            "knowledge_refs": list(m.knowledge_refs)} for m in (assessment.attack_mapping if assessment else ())],
        "danger": {"severity": severity, "impact": impact},
        "response_results": _results(actions),
        "knowledge": _knowledge_view(kb, assessment.knowledge_refs if assessment else ()),
        "similar_cases": await _similar(db, incident, investigation),
        "post_exploitation": [dict(item) for item in (assessment.post_exploitation if assessment else ())],
        "historical": historical,
    }
    return analysis, plan


def conflicting_types(action_type: str) -> set[str]:
    """Union of playbook conflicts for this action type, plus block vs rate limit on one peer."""
    conflicts = set()
    try:
        _, playbooks = pattern_engine.catalog()
    except Exception:
        logger.exception("Playbook catalog unavailable")
        playbooks = {}
    for book in playbooks.values():
        for spec in book.get("actions", []):
            if spec.get("action_type") == action_type:
                conflicts.update(spec.get("conflicts_with") or [])
            elif action_type in (spec.get("conflicts_with") or []):
                conflicts.add(spec.get("action_type"))
    if action_type in (BLOCK, RATE):
        conflicts.add(RATE if action_type == BLOCK else BLOCK)
    conflicts.discard(action_type)
    return conflicts
