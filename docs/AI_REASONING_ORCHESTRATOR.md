# LARP EDR — Reasoning Orchestrator và Decision Trace "Quá trình phân tích"

Ngày: 28/11/2026. Phạm vi: AI Rule Generator và AI Risk Analyst. Tài liệu này mô tả kiến trúc đã triển khai,
thuật toán từng workflow, schema sự kiện, cách kiểm thử và những gì chưa kiểm thử live.

## 1. Kiểm tra runtime (audit)

| Thành phần | Trạng thái trước | Sau thay đổi |
|---|---|---|
| Ollama `sec-q5:latest` | Foundation-Sec-8B-**Reasoning** (Cisco Foundation AI, "Metis"), GGUF Q5_K_M, 8.03 B tham số, context 131072 (đang nạp với 4096). Ollama báo `capabilities: ["thinking","completion"]`. Chạy **CPU** (`size_vram = 0`): ~3 token/giây khi sinh, ~13 token/giây khi đọc prompt. | Không đổi |
| Chat/Generate API | Rule Assistant/Harvest dùng `/api/generate` chế độ `raw` với khối `<think></think>` rỗng (model không tốn token suy nghĩ). Triage dùng `/api/chat` với `think` theo biến môi trường; `_parse_response` tách `reasoning` nhưng không lưu làm bằng chứng. | Risk Analyst dùng `/api/generate` raw + JSON schema như Rule Assistant. Thinking không bao giờ được lưu, stream hay hiển thị. |
| AI Harvest (Rule Assistant) | Chạy đồng bộ, không có trace. | `rule_generator.run_turn` dùng chung cho endpoint cũ và endpoint có trace `POST /rules/assistant/runs`. |
| Sigma Validator (Agent B) | Chỉ chạy khi bấm "Tạo rule". | Chạy thêm ở bước `HISTORICAL_VALIDATION` của lượt có trace (chỉ đọc dataset + dry-run 24 giờ). |
| Risk Assessment Service | Ghi `risk_snapshot` (đã có từ 47d74bc). | Không đổi; Risk Analyst chỉ đọc. |
| AI Triage Service | Đã có trace cho phân tích sự cố (47d74bc). | Không đổi luồng; tên sự kiện chuẩn hóa. |
| Evidence Store / Alert Context | `load_alert_context`, `summarize_evidence_bundle`. | Dùng qua `ReadOnlyToolbox`. |
| AI Threat Memory | EXACT / SEMANTIC / FRESH / FALLBACK trong triage, stage `CACHE_LOOKUP`; cache hit thì `MODEL_INFERENCE` là `SKIPPED`. | Không đổi. Câu hỏi của analyst không dùng cache (không phát stage cache giả). |
| Frontend | `DecisionTracePanel` chỉ cho incident. | `ReasoningTracePanel` dùng chung, hook `useRunTrace`, khung "Hỏi AI Risk Analyst", trace trong Rule Assistant. |

## 2. Kiến trúc

```
SOC Admin ─▶ POST /api/v1/rules/assistant/runs        (AI Rule Generator)
          └▶ POST /api/v1/ai/incidents/{id}/questions  (AI Risk Analyst)
                 │  kiểm tra quyền, revision, slot TRƯỚC khi làm việc (404/409/422)
                 ▼
        AIAnalysisRun (task_type, actor, subject_id) ──▶ BackgroundTasks
                 │
                 ▼
   Reasoning Orchestrator ── ReadOnlyToolbox (read_evidence, read_risk_breakdown, …)
                 │             (block_ip / isolate_host / kill_process / quarantine_file không đăng ký được)
                 ├─▶ Ollama sec-q5 (JSON schema, additionalProperties=false, raw + empty think)
                 ├─▶ Verifier xác định (schema, evidence, điểm, claim, runtime)
                 │      └─ sai → sửa lại tối đa AI_REASONING_MAX_REVISIONS lần → hoặc từ chối
                 ▼
   TraceRecorder ─▶ PostgreSQL ai_decision_trace_events (sequence tăng dần, đã lọc secret/<think>)
                 └▶ TraceBroker ─▶ SSE GET /api/v1/ai/runs/{run_id}/stream (Last-Event-ID / after_sequence)
                                            ▼
                         React useRunTrace → ReasoningTracePanel "Quá trình phân tích"
```

Máy trạng thái (mỗi stage thuộc một phase; task chỉ phát stage nó thực sự chạy):
`CREATED → CONTEXT_RETRIEVAL → REQUIREMENT_CHECK → EVIDENCE_ANALYSIS → MODEL_GENERATION → TOOL_VALIDATION → RESULT_SYNTHESIS → COMPLETED | FAILED | TIMEOUT | NEEDS_CLARIFICATION`.

## 3. Thuật toán

### 3.1 AI Rule Generator (`app/services/ai/rule_generator.py`)

| Stage | Phase | Nguồn | Việc thật |
|---|---|---|---|
| `REQUEST_UNDERSTANDING` | REQUIREMENT_CHECK | AI_INFERENCE nếu là tin nhắn mới, ngược lại DETERMINISTIC | `request_constraints` (luật cố định), sau đó `rule_assistant.extract` (model trích intent; giá trị không có trong lời người dùng bị loại). Câu trả lời cho câu hỏi không gọi model. |
| `PLATFORM_LOGSOURCE` | REQUIREMENT_CHECK | DETERMINISTIC | Nền tảng và `process_creation/<product>` từ intent đã grounding; liệt kê tiến trình không thuộc nền tảng (vd. `sh` cho Windows). |
| `TELEMETRY_FIELDS` | CONTEXT_RETRIEVAL | ENDPOINT_AGENT | Trường Agent gửi + nền tảng/tiến trình quan sát 24 giờ (`observed_options`). |
| `CLARIFICATION` (terminal) | REQUIREMENT_CHECK | DETERMINISTIC | Còn thiếu slot → `clarification_required`, run `NEEDS_CLARIFICATION`; trạng thái hội thoại lưu ở `rule_conversations` (revision). |
| `SIGMA_GENERATION` | MODEL_GENERATION | DETERMINISTIC | Bộ biên dịch cố định `compile_rule` (model không viết Sigma). |
| `SCHEMA_RUNTIME_CHECK` | TOOL_VALIDATION | DETERMINISTIC | YAML/Sigma schema, `sigma_runtime.check_support`, quality lint, đúng nền tảng, không bị safe-process bỏ qua. Sai → `stage_failed RULE_CHECK_FAILED`, không đề xuất rule. |
| `HISTORICAL_VALIDATION` | TOOL_VALIDATION | DETERMINISTIC (HYBRID nếu có giải thích FP bằng LLM) | Agent B trên dataset có nhãn + dry-run 24 giờ. Verdict `FAILED/UNSUPPORTED` → `stage_failed VALIDATION_FAILED`. |
| `RESULT_EXPLANATION` | RESULT_SYNTHESIS | DETERMINISTIC | Chỉ nói "ĐẠT" khi Validator trả `PASSED`; `INCONCLUSIVE` ghi rõ "không phải là đạt". |

Model timeout → stage `TIMEOUT`, run `TIMEOUT` (`run_failed`), không có `run_completed`, không biên dịch rule.

### 3.2 AI Risk Analyst — câu hỏi về incident (`app/services/ai/risk_analyst.py`)

1. `INCIDENT_LOADED` — đọc incident (điểm, mức độ từ Detection Engine).
2. `EVIDENCE_RETRIEVAL` — `read_evidence` (Alert Context: HTTP, auth, tiến trình, flow).
3. `MATCHED_RULES` — `read_risk_breakdown` (snapshot / chain / factors).
4. `RISK_RULE_EXPLANATION` — đối chiếu tổng đóng góp với điểm lưu (cap, EMA, bypass). **Không tính lại điểm.**
5. `PROCESS_NETWORK_CORRELATION` — hoặc `SKIPPED` khi không có tiến trình/flow.
6. `ALTERNATIVE_EXPLANATIONS` — giải thích khác theo luật (quét không thành công, sai mật khẩu, tác vụ hợp lệ, dư EMA, kiểm thử được phép = UNKNOWN).
7. Dữ kiện F1…Fn (mỗi dữ kiện có certainty OBSERVED/CORRELATED/INFERRED/UNKNOWN và evidence ID thuộc sự cố). Nếu câu hỏi nêu điểm khác điểm lưu, thêm dữ kiện "Câu hỏi nêu điểm X, nhưng…".
8. `ANSWER_GENERATION` — model chỉ viết `conclusion`, chọn `fact_ids`/`alternative_ids`, gợi ý `recommendations`/`limitations` (JSON schema chặt).
9. `ANSWER_VERIFICATION` — 7 kiểm tra xác định: schema; chỉ trích dẫn dữ kiện có thật; mọi con số điểm trong kết luận phải có trong dữ liệu Detection Engine; evidence ID thuộc sự cố; không khẳng định thực thi khi thiếu bằng chứng tiến trình; không khẳng định root khi thiếu UID 0; không tuyên bố đã chặn/cách ly/kill khi không có hành động. Sai → quay lại bước 8 kèm danh sách lỗi (tối đa `AI_REASONING_MAX_REVISIONS`, mặc định 1). Vẫn sai → kết luận của model bị **từ chối**, kết luận xác định được ghi `conclusion_source = DETERMINISTIC`.
10. `RESULT_SYNTHESIS` — `StructuredExplanation` (Pydantic, `extra=forbid`) + một `answer_delta` chứa kết luận đã kiểm chứng.

Ollama timeout → `TIMEOUT` (không có `run_completed`), kết quả chỉ chứa dữ kiện và kết luận ghi rõ "không phải AI".

### 3.3 Phân tích sự cố (AI Triage, đã có từ 47d74bc)

Giữ nguyên: `INCIDENT_LOADED → EVIDENCE_RETRIEVAL → RISK_RULE_EXPLANATION → PROCESS_NETWORK_CORRELATION → CACHE_LOOKUP → MODEL_INFERENCE | DETERMINISTIC_FALLBACK → CLAIM_VERIFICATION → ANALYSIS_PERSISTENCE → RESPONSE_RECOMMENDATION (chỉ đọc)`. Exact cache hit: `MODEL_INFERENCE` là `SKIPPED`, không giả gọi model; semantic match chỉ là ca tham khảo; evidence ID được rebind theo sự cố hiện tại.

## 4. Schema

### Run (`GET /api/v1/ai/runs/{run_id}/trace` → `run`)

`run_id` (= `analysis_run_id`), `task_type` (`incident_analysis` | `risk_question` | `rule_generation`), `actor`, `subject_id` (conversation), `question`, `incident_id`, `agent_id`, `status`, `current_stage`, `current_phase`, `stage_status`, `model_name`, `error_code`, `error_message`, `result` (StructuredExplanation hoặc tóm tắt lượt Rule Generator), `created_at`, `started_at`, `completed_at`.

### Event (SSE `id:` = `sequence`, `event:` = `event_type`, `data:` = JSON)

`event_id`, `analysis_run_id`, `incident_id`, `sequence`, `event_type`, `stage`, `phase`, `status`, `source_type` (`ENDPOINT_AGENT` | `MANAGER_STORE` | `ANALYST_INPUT` | `AI_INFERENCE` | `DETERMINISTIC` | `HYBRID`), `started_at`, `completed_at`, `duration_ms`, `summary`, `evidence_refs`, `rule_refs`, `safe_result` (tóm tắt kết quả công cụ, đã lọc), `error_code`, `created_at`.

`event_type`: `run_started`, `stage_started`, `stage_completed`, `stage_skipped`, `stage_failed`, `clarification_required`, `answer_delta`, `run_completed`, `run_failed`. Sự kiện ghi trước đó (`analysis_started`, `model_answer_delta`, `analysis_completed`, `analysis_failed`) được đổi tên khi đọc; dữ liệu cũ không bị ghi lại.

Reconnect: client gửi `Last-Event-ID` hoặc `?after_sequence=` → server phát lại mọi sự kiện có `sequence` lớn hơn từ PostgreSQL rồi stream tiếp. Reload: run id lưu trong `sessionStorage`, trace đọc lại từ DB. Token không bao giờ được truyền qua query string.

### Quyền

Run của incident theo phạm vi Agent của operator. Run `rule_generation` chỉ chủ sở hữu xem được (người khác nhận 404). Câu hỏi Risk Analyst là thao tác chỉ đọc: analyst được hỏi, không endpoint nào trong luồng có thể thay đổi risk score hoặc tạo hành động ứng phó.

## 5. Giao diện

`ReasoningTracePanel` (dùng chung):
- Mở mặc định khi đang chạy, khi run vừa được theo dõi trực tiếp, khi thất bại, hết thời gian hoặc cần làm rõ.
- Ẩn/hiện chỉ đổi state cục bộ, không gọi API hay model.
- Mỗi bước có trạng thái, thời gian, nguồn, phase và tóm tắt. "Chi tiết" mở bằng chứng, rule, kiểm tra, verdict Validator, câu hỏi làm rõ và các giải thích khác.
- Bước chạy lại (revision) có thẻ riêng "(lần 2)".
- Có banner timeout/thất bại và nút "Thử lại" cho tác vụ an toàn.
- Không hiển thị raw JSON; thinking bị lọc ở cả backend lẫn frontend.

`RiskAnalystQA` (tab Phân tích AI của incident) hiển thị:
- kết luận và nguồn (AI đã kiểm chứng / tổng hợp từ dữ liệu, không phải AI);
- risk score của Detection Engine;
- dữ kiện có nhãn certainty và evidence;
- rule khớp, giải thích khác, dữ liệu còn thiếu;
- kết quả kiểm chứng;
- khuyến nghị (cần phê duyệt) và giới hạn.

`RuleAssistant` gửi lượt qua `/rules/assistant/runs`, xem trace trực tiếp, rồi nạp câu trả lời đã lưu (chỉ sau khi bản ghi run kết thúc) và hiển thị kết quả Validator trước khi tạo rule.

## 6. Cấu hình

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `AI_REASONING_MAX_REVISIONS` | 1 | Số lần sửa sau lần trả lời đầu (0–3). |
| `AI_ANALYST_TIMEOUT_SECONDS` | 240 | Timeout mỗi lần gọi model của Risk Analyst (CPU ~3 token/giây). |
| `ASSISTANT_TIMEOUT_SECONDS` | 120 | Timeout trích intent của Rule Generator (đã có). |

Schema DB: khi khởi động, `ensure_ai_run_schema` thêm cột mới vào `ai_analysis_runs` và bỏ NOT NULL của `incident_id` (idempotent, không xóa dữ liệu). Có thêm migration Alembic `e1f2a3b4c5d6` cho môi trường dùng Alembic.
