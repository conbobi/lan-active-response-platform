"""AI Rule Generator turn, instrumented as Decision Trace stages.

One code path serves the plain ``POST /rules/assistant`` endpoint and the streamed
``POST /rules/assistant/runs`` endpoint; with a recorder, each real step emits its stage:

REQUEST_UNDERSTANDING   deterministic requirement check, then (only for a new message) the model's intent extraction
PLATFORM_LOGSOURCE      platform and Sigma logsource from the grounded intent (never guessed by the model)
TELEMETRY_FIELDS        fields the Agent reports and the processes/platforms it reported in the last 24 h
CLARIFICATION           terminal when a slot is missing: the questions are stored with the conversation
SIGMA_GENERATION        fixed compiler: confirmed intent → Sigma
SCHEMA_RUNTIME_CHECK    YAML/schema, Detection Engine support, quality lint, platform and safe-process checks
HISTORICAL_VALIDATION   Agent B on the labelled dataset + dry-run on 24 h of real telemetry
RESULT_EXPLANATION      what the validator concluded; a rule is "passed" only when the validator says PASSED
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

import yaml
from sqlalchemy import select, update

from app.models.rule_conversation import RuleConversation
from app.services.ai import rule_assistant
from app.services.detection import sigma_runtime

AGENT_FIELDS = ("Image", "ParentImage", "CommandLine", "ParentCommandLine", "ProcessName", "ParentProcessName")


class TurnError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class _NoTrace:
    """Recorder stand-in for the untraced endpoint."""

    def __getattr__(self, name):
        async def noop(*args, **kwargs):
            return None
        return noop


async def owned_conversation(db, key, actor):
    row = await db.scalar(select(RuleConversation).where(RuleConversation.id == key.hex,
                                                         RuleConversation.owner == actor))
    if row is None:
        raise TurnError(404, "Conversation unavailable")
    return row


async def precheck(db, actor, body) -> Tuple[Optional[RuleConversation], Dict[str, Any]]:
    """Request errors that need no work: unknown/foreign conversation, stale revision, unasked answer."""
    row = await owned_conversation(db, body.conversation_id, actor) if body.conversation_id else None
    state = row.state if row else {}
    if body.resume:
        return row, state
    if row and body.revision != row.revision:
        raise TurnError(409, "Conversation changed; reload the latest turn")
    if body.answer is not None and row and body.answer.slot not in {q["slot"] for q in state["questions"]}:
        raise TurnError(422, "Answer does not correspond to an open question")
    context = state.get("context", body.context or "")
    if len(context) + len((body.message or "").strip()) > 8000:
        raise TurnError(422, "Start a new conversation for this request")
    return row, state


def _logsource(intent: Dict[str, Any]) -> Optional[Dict[str, str]]:
    return {"category": "process_creation", "product": intent["platform"]} if intent.get("platform") else None


def rule_checks(sigma_yaml: str, intent: Dict[str, Any]) -> List[Dict[str, Any]]:
    from app.services.ai.validation_service import quality_problems
    checks: List[Dict[str, Any]] = []

    def add(check_id, label, passed, detail):
        checks.append({"check_id": check_id, "label": label, "passed": bool(passed), "detail": detail})

    try:
        rule = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as exc:
        add("yaml_schema", "YAML/Sigma schema", False, f"YAML không hợp lệ: {exc.__class__.__name__}")
        return checks
    missing = [k for k in ("title", "logsource", "detection") if not (isinstance(rule, dict) and rule.get(k))]
    add("yaml_schema", "YAML/Sigma schema", not missing,
        f"Thiếu trường: {', '.join(missing)}" if missing else "Có title, logsource, detection.")
    if missing:
        return checks
    supported, reason = sigma_runtime.check_support(rule)
    add("engine_support", "Detection Engine hỗ trợ", supported, reason)
    problems = quality_problems(rule)
    add("quality_lint", "Kiểm tra chất lượng rule", not problems, "; ".join(problems) or "Không có lỗi chất lượng.")
    product = (rule.get("logsource") or {}).get("product")
    foreign = rule_assistant._foreign_children(intent)
    add("platform_match", "Đúng nền tảng", product == intent.get("platform") and not foreign,
        f"Tiến trình {', '.join(foreign)} không thuộc {product}." if foreign else
        f"logsource.product={product}, nền tảng đã xác nhận={intent.get('platform')}.")
    ignored = rule_assistant._runtime_ignored(intent)
    add("runtime_safe_process", "Không bị runtime safe-process bỏ qua", not ignored,
        "Shell/interpreter không có tiến trình cha sẽ bị runtime bỏ qua." if ignored else
        "Điều kiện đủ cụ thể để runtime đánh giá.")
    return checks


def validation_view(result: Dict[str, Any]) -> Dict[str, Any]:
    keep = ("verdict", "passed", "reason", "fpr", "precision", "recall", "f1", "confusion", "thresholds", "dataset",
            "engine_supported")
    view = {k: result.get(k) for k in keep if k in result}
    view["fp_samples"] = [{k: s.get(k) for k in ("name", "cmdline", "parent_cmdline", "source") if k in s}
                          for s in (result.get("fp_samples") or [])[:5]]
    return view


def explanation(validation: Dict[str, Any], preview: Dict[str, Any], intent: Dict[str, Any]) -> str:
    verdict = validation.get("verdict")
    head = {"PASSED": "Validator xác nhận rule ĐẠT trên dữ liệu có nhãn.",
            "FAILED": "Validator kết luận rule KHÔNG ĐẠT.",
            "INCONCLUSIVE": "Validator CHƯA KẾT LUẬN được (không phải là đạt).",
            "UNSUPPORTED_BY_ENGINE": "Detection Engine không chạy được rule này."}.get(verdict, "Chưa có kết quả kiểm định.")
    return (f"{head} {validation.get('reason') or ''} Dry-run 24 giờ trên telemetry thật: "
            f"{preview.get('matches', 0)} lần khớp / {preview.get('processes_scanned', 0)} tiến trình (không có nhãn). "
            f"Rule cho {intent.get('platform')} chưa được kích hoạt; bấm 'Tạo rule' để đưa vào chế độ giám sát.").strip()


async def run_turn(db, actor: str, body, rec=None, *, validate: bool = False) -> Dict[str, Any]:
    trace = rec or _NoTrace()
    row, state = await precheck(db, actor, body)
    if body.resume and row:
        return state
    editing = not body.answer and not body.message and body.intent is not None
    intent, _ = rule_assistant.sanitize(body.intent if editing else state.get("intent", body.intent or {}))
    message = (body.message or "").strip()
    context = state.get("context", body.context or "")
    error, error_code, model_used = None, None, False

    calls_model = False
    restriction, notices = rule_assistant.request_constraints(message)
    if row and not message and state.get("classification") in {"UNSUPPORTED_REQUIREMENT", "INSUFFICIENT_TELEMETRY"}:
        restriction, notices = state["classification"], list(state["notices"])
    calls_model = body.answer is None and bool(message) and restriction in (None, "NEEDS_CLARIFICATION")
    await trace.start_run(summary="Bắt đầu lượt AI Rule Generator", stage="RUN", mode="fresh",
                          model_name=rule_assistant.DEFAULT_MODEL, safe_result={"task_type": "rule_generation"})
    await trace.start_stage("REQUEST_UNDERSTANDING", summary="Đang hiểu yêu cầu.",
                            source_type="AI_INFERENCE" if calls_model else "DETERMINISTIC")
    if body.answer is not None:
        try:
            if body.answer.slot == "scenario":
                intent, restriction, extra = rule_assistant.apply_scenario(intent, str(body.answer.value))
                notices.extend(extra)
            else:
                intent = rule_assistant.apply_answer(intent, body.answer.slot, body.answer.value, body.answer.replace)
        except ValueError as exc:
            await trace.fail_stage("REQUEST_UNDERSTANDING", error_code="INVALID_ANSWER", summary=str(exc))
            raise TurnError(422, str(exc)) from exc
        context = (context + "\n" + str(body.answer.value))[-8000:]
        understood = f"Áp dụng câu trả lời cho '{body.answer.slot}' (không gọi mô hình)."
    elif calls_model:
        try:
            if row:  # release the read transaction before waiting for inference
                await db.commit()
            intent, extracted = await rule_assistant.extract(message, intent, context=context)
            notices.extend(extracted)
            model_used = True
            understood = (f"Mô hình {rule_assistant.DEFAULT_MODEL} trích ý định; "
                          f"{sum(n.startswith('AI đoán') for n in extracted)} giá trị không có trong lời người dùng "
                          "đã bị loại.")
        except rule_assistant.GenerationError as exc:
            error = f"AI không phản hồi được ({exc}). Bạn có thể điền trực tiếp các ô bên dưới."
            error_code = "OLLAMA_TIMEOUT" if "timed out" in str(exc) else "MODEL_ERROR"
            understood = None
            await trace.fail_stage("REQUEST_UNDERSTANDING", status="TIMEOUT" if error_code == "OLLAMA_TIMEOUT" else "FAILED",
                                   error_code=error_code, source_type="AI_INFERENCE",
                                   summary=f"Mô hình không trả lời được: {exc}")
    elif restriction:
        understood = f"Kiểm tra yêu cầu bằng luật cố định: {restriction} (không gọi mô hình)."
    else:
        understood = "Áp dụng chỉnh sửa trực tiếp của người dùng (không gọi mô hình)."
    if understood:
        await trace.complete_stage("REQUEST_UNDERSTANDING", source_type="AI_INFERENCE" if model_used else "DETERMINISTIC",
                                   summary=understood, safe_result={
                                       "classification": restriction, "model_used": model_used,
                                       "intent": {k: intent.get(k) for k in ("platform", "parent", "parent_hint",
                                                                              "child", "command", "chaining")},
                                       "notices": notices[:6]})
    if restriction == "NEEDS_CLARIFICATION":
        intent["platform"] = None
    context = (context + "\n" + message).strip()

    await trace.start_stage("PLATFORM_LOGSOURCE", summary="Đang xác định nền tảng và logsource.")
    logsource = _logsource(intent)
    foreign = rule_assistant._foreign_children(intent)
    await trace.complete_stage("PLATFORM_LOGSOURCE", safe_result={"platform": intent.get("platform"),
                                                                  "logsource": logsource, "foreign_children": foreign},
                               summary=(f"Nền tảng {intent['platform']}, logsource process_creation/{intent['platform']}."
                                        + (f" {', '.join(foreign)} không thuộc nền tảng này." if foreign else "")
                                        if logsource else "Chưa xác định được nền tảng từ lời người dùng — cần hỏi lại."))

    await trace.start_stage("TELEMETRY_FIELDS", summary="Đang kiểm tra Agent telemetry fields.", source_type="ENDPOINT_AGENT")
    observed = await rule_assistant.observed_options(db)
    await trace.complete_stage("TELEMETRY_FIELDS", source_type="ENDPOINT_AGENT", safe_result={
        "fields": list(AGENT_FIELDS), "observed_platforms": observed.get("platforms", []),
        "observed_parents": observed.get("parents", [])[:8], "observed_scripts": observed.get("scripts", [])[:8]},
        summary=(f"Agent gửi {', '.join(AGENT_FIELDS[:4])}; 24 giờ qua thấy nền tảng "
                 f"{', '.join(observed.get('platforms') or ['(chưa có)'])}."))

    asks = rule_assistant.questions(intent, observed)
    scenario = rule_assistant.scenario_question(message, intent) if message and not restriction else None
    if scenario:
        asks.insert(0, scenario)
        notices.append("Yêu cầu chưa nêu hành vi cụ thể. Chọn một hành vi bên dưới thay vì tạo một rule bao quát "
                       "mọi tiến trình.")
    if restriction in {"INSUFFICIENT_TELEMETRY", "UNSUPPORTED_REQUIREMENT"}:
        asks = []
    if message and re.search(r"\bhttp\b", message, re.I):
        notices.append("Sigma process_creation chỉ thấy tiến trình, không thấy request HTTP. Việc nối request với "
                       "tiến trình do Web Compromise Chain làm (theo request ID và thời gian).")
    sigma_yaml, checks, validation, preview = None, [], None, None
    if not asks and not restriction and not error:
        await trace.start_stage("SIGMA_GENERATION", summary="Đang tạo Sigma bằng bộ biên dịch cố định.")
        try:
            sigma_yaml, _ = rule_assistant.compile_rule(intent, context)
            await trace.complete_stage("SIGMA_GENERATION", summary="Đã biên dịch Sigma từ ý định đã xác nhận.",
                                       safe_result={"logsource": logsource, "lines": sigma_yaml.count("\n") + 1})
        except ValueError as exc:
            asks = [{"slot": "child", "text": f"Chưa tạo được rule: {exc}", "options": [], "allow_text": True}]
            await trace.fail_stage("SIGMA_GENERATION", error_code="COMPILE_REJECTED", summary=str(exc))
    if sigma_yaml:
        await trace.start_stage("SCHEMA_RUNTIME_CHECK", summary="Đang kiểm tra schema/runtime support.")
        checks = rule_checks(sigma_yaml, intent)
        failed = [c for c in checks if not c["passed"]]
        if failed:
            await trace.fail_stage("SCHEMA_RUNTIME_CHECK", error_code="RULE_CHECK_FAILED", safe_result={"checks": checks},
                                   summary="Không đạt: " + "; ".join(f"{c['label']} ({c['detail']})" for c in failed))
            error, error_code, sigma_yaml = "Rule không qua kiểm tra schema/runtime nên không được đề xuất.", \
                "RULE_CHECK_FAILED", None
        else:
            await trace.complete_stage("SCHEMA_RUNTIME_CHECK", safe_result={"checks": checks},
                                       summary=f"Đạt {len(checks)}/{len(checks)} kiểm tra schema và runtime.")
    if sigma_yaml and validate:
        from app.services.ai.validation_service import validation_service
        await trace.start_stage("HISTORICAL_VALIDATION", summary="Đang chạy historical validation (Agent B).")
        raw = await validation_service.validate_rule(rule_yaml=sigma_yaml, db_session=db)
        validation = validation_view(raw)
        preview = await rule_assistant.preview_recent(yaml.safe_load(sigma_yaml), db)
        payload = {"validation": validation, "recent_telemetry": preview}
        source = "HYBRID" if raw.get("llm_explanation") else "DETERMINISTIC"
        summary = f"Validator: {validation.get('verdict')} — {validation.get('reason')}"
        if validation.get("verdict") in {"FAILED", "UNSUPPORTED_BY_ENGINE"}:
            await trace.fail_stage("HISTORICAL_VALIDATION", error_code="VALIDATION_FAILED", source_type=source,
                                   summary=summary, safe_result=payload)
        else:
            await trace.complete_stage("HISTORICAL_VALIDATION", source_type=source, summary=summary, safe_result=payload)
    if sigma_yaml:
        notices.append("Rule khớp khi mọi điều kiện trong detection.selection cùng đúng. Tác vụ quản trị hợp lệ vẫn "
                       "có thể khớp; xem mẫu benign và false positive trong kết quả kiểm định Agent B.")
    revision = row.revision + 1 if row else 1
    key = row.id if row else uuid.uuid4().hex
    result = {"conversation_id": key, "revision": revision, "context": context, "intent": intent,
              "classification": restriction or ("READY_TO_GENERATE" if sigma_yaml else "NEEDS_CLARIFICATION"),
              "questions": asks, "ready": bool(sigma_yaml), "sigma_yaml": sigma_yaml, "notices": notices,
              "model_used": model_used, "has_model_input": model_used or state.get("has_model_input", False),
              "model": rule_assistant.DEFAULT_MODEL, "error": error}
    if rec is not None:
        result["checks"] = checks
        result["validation"] = validation
        result["recent_telemetry"] = preview
    if row:
        changed = await db.execute(update(RuleConversation).where(
            RuleConversation.id == key, RuleConversation.owner == actor, RuleConversation.revision == body.revision
        ).values(state=result, revision=revision))
        if not changed.rowcount:
            raise TurnError(409, "Conversation changed; reload the latest turn")
    else:
        db.add(RuleConversation(id=key, owner=actor, revision=revision, state=result))
    await db.flush()

    if rec is not None:
        await db.commit()  # the reply is durable before the run is reported finished
        await finish(rec, result, error_code)
    return result


async def finish(rec, result: Dict[str, Any], error_code: Optional[str]) -> None:
    run_result = {"conversation_id": result["conversation_id"], "revision": result["revision"],
                  "classification": result["classification"], "ready": result["ready"]}
    if error_code in {"OLLAMA_TIMEOUT", "MODEL_ERROR"}:
        await rec.fail_run(status="TIMEOUT" if error_code == "OLLAMA_TIMEOUT" else "FAILED", stage="RUN",
                           error_code=error_code, result=run_result, error_message=result["error"] or "",
                           summary="Mô hình không trả lời được; không có rule nào được tạo.")
        return
    if error_code:
        await rec.fail_run(stage="RUN", error_code=error_code, result=run_result, error_message=result["error"] or "",
                           summary="Rule không qua kiểm tra nên không được đề xuất.")
        return
    if result["questions"]:
        await rec.require_clarification(questions=result["questions"], result=run_result,
                                        summary=f"Cần làm rõ {len(result['questions'])} thông tin trước khi tạo rule.")
        return
    await rec.start_stage("RESULT_EXPLANATION", summary="Đang giải thích kết quả.")
    validation = result.get("validation") or {}
    if result["sigma_yaml"]:
        text = explanation(validation, result.get("recent_telemetry") or {}, result["intent"])
    else:
        text = f"Không tạo Sigma ({result['classification']}): " + " ".join(result["notices"][-2:])
    await rec.complete_stage("RESULT_EXPLANATION", summary=text, safe_result={
        "classification": result["classification"], "verdict": validation.get("verdict"),
        "passed": bool(validation.get("passed"))})
    await rec.emit_answer_delta(text, stage="RESULT_EXPLANATION", source_type="DETERMINISTIC")
    await rec.complete_run(final_stage="RUN", result=run_result, model_name=result["model"],
                           summary=("Hoàn tất: rule đã qua Validator." if validation.get("passed") else
                                    "Hoàn tất: rule chưa được Validator xác nhận đạt." if result["sigma_yaml"] else
                                    f"Hoàn tất: {result['classification']}."))
