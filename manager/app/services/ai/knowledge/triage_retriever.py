"""Select rule-specific references, separate from observed incident evidence."""
import hashlib
from uuid import UUID

import yaml
from sqlalchemy import select

from app.models.rule_candidate import RuleCandidate
from app.models.rule_version import RuleVersion
from app.services.ai.alert_context_projector import AUTH_RULE, FIM_RULE, AlertContext
from app.services.ai.knowledge.mitre_kb import mitre_kb
from app.services.ai.triage_tokens import serialize_data
from app.services.detection.network_shell import RULE_ID

SOPS = {
    (RULE_ID, "builtin:1"): (
        "network-shell", "T1059.004",
        "Đối chiếu process identity, socket inode và FD trên cùng mẫu. "
        "Phân biệt socket holder với bên khởi tạo. Nếu các holder ngang bằng, ghi rõ chưa xác định tiến trình chính.",
    ),
    (FIM_RULE, "builtin:1"): (
        "sensitive-file-change", None,
        "Đối chiếu path và chuyển đổi SHA-256. Xác minh thay đổi hợp lệ qua lịch bảo trì hoặc nhật ký quản lý cấu hình.",
    ),
    (AUTH_RULE, "risk:1"): (
        "authentication", "T1110",
        "Đối chiếu service, tài khoản, nguồn và khung quan sát. "
        "Xem xét tác vụ lặp lại với thông tin đăng nhập đã hết hạn.",
    ),
}
RISK_TECHNIQUES = {"http_beaconing": "T1071", AUTH_RULE: "T1110"}


def _validated_ids(tags) -> tuple[str, ...]:
    if not isinstance(tags, (list, tuple)):
        return ()
    normalized = (tag.removeprefix("attack.").upper() for tag in tags if isinstance(tag, str))
    return tuple(dict.fromkeys(tag for tag in normalized if mitre_kb.validate_technique(tag)))[:8]


def _rule_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _risk_mapping(context: AlertContext) -> list[str]:
    if context.metadata["rule_version"] != "risk:1":
        return []
    return [RISK_TECHNIQUES[item["rule"]] for item in context.facts
            if item.get("rule") in RISK_TECHNIQUES]


async def enrich_rule_mapping(session, context: AlertContext) -> None:
    rule = context.metadata["rule_id"], context.metadata["rule_version"]
    sop = SOPS.get(rule)
    tags = [sop[1]] if sop else []
    tags.extend(_risk_mapping(context))
    try:
        rule_id = UUID(rule[0])
    except ValueError:
        context.mapped_techniques = _validated_ids(tags)
        return
    record = await session.get(RuleCandidate, rule_id)
    if record is not None:
        current_yaml = record.rule_yaml or ""
        if _rule_hash(current_yaml) == rule[1]:
            tags.extend(_validated_ids(record.mitre_techniques))
        else:
            versions = await session.scalars(
                select(RuleVersion.yaml_content).where(RuleVersion.rule_candidate_id == rule_id)
                .order_by(RuleVersion.version_number.desc()).limit(20)
            )
            current_yaml = next((text for text in versions if _rule_hash(text) == rule[1]), "")
        if current_yaml:
            try:
                document = yaml.safe_load(current_yaml)
            except yaml.YAMLError:
                document = None
            if isinstance(document, dict):
                tags.extend(_validated_ids(document.get("tags")))
    context.mapped_techniques = _validated_ids(tags)


def retrieve_references(context: AlertContext, tokenizer) -> list[dict]:
    documents = []
    rule = context.metadata["rule_id"], context.metadata["rule_version"]
    sop = SOPS.get(rule)
    if sop is None and "T1110" in _risk_mapping(context):
        sop = SOPS[(AUTH_RULE, "risk:1")]
    candidates = []
    if sop:
        candidates.append({"id": sop[0], "source": "larp_sop", "version": "1", "excerpt": sop[2]})
    for technique in context.mapped_techniques[:2]:
        entry = mitre_kb.get_technique(technique)
        candidates.append({
            "id": technique, "source": "mitre_kb", "name": entry.get("name", technique),
            "tactic": entry.get("tactic", "N/A"),
        })
    for candidate in candidates:
        if len(documents) == 2:
            break
        if tokenizer.count_text(serialize_data([*documents, candidate])) <= 400:
            documents.append(candidate)
    return documents
