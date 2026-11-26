# Nguyên nhân gốc: AI Response Proposal không hoạt động

Sự cố quan sát được trên `inc_d7242d3eb8fa` (Agent `ip-172-31-32-238`, sqlmap gửi `POST /login`, ngày 26/11/2026). Tham chiếu dòng lệnh theo commit `1481484` trước khi sửa.

## Kết luận

AI Response Proposal **không bị lỗi ở backend Response Assist**. Giao diện đưa analyst vào hai đường xử lý cũ mà backend đã cố ý chặn với sự cố HTTP. Còn tab đúng (**AI Response Assist**) thì chưa từng được mở trong phiên này.

| Mã | Nguyên nhân | Vị trí |
| --- | --- | --- |
| RC1 | Nút *Đề xuất phản ứng AI* trong tab Actions gọi `POST /ai-analysis/suggest-response`. Với sự cố HTTP, `suggest_response` trả `None` mà không ghi gì. Route vẫn trả `200 {"status":"suggesting"}` và log `completed`. Giao diện chờ 45 lần × 4 giây rồi báo hết thời gian. | `manager/app/services/ai/ai_response_service.py:90`, `manager/app/routers/v1/incident_router.py:264-279`, `frontend/src/components/incidents/AISuggestionPanel.jsx:131` |
| RC2 | Tab Actions gắn nhãn *Gợi ý* cho **Isolate Host**, và HeroBanner cũng hiện nút này cho sự cố HTTP. Backend từ chối bằng `400 Use evidence-scoped response proposals for HTTP incidents`. | `frontend/src/components/incidents/ActionSuggestions.jsx:38`, `frontend/src/components/incidents/HeroBanner.jsx:219`, `manager/app/services/response/response_action_service.py:67` |
| RC3 | Lỗi được làm phẳng thành chuỗi văn bản. Giao diện không phân biệt được lỗi quyền, chính sách, thiếu bằng chứng hay Agent offline. | `frontend/src/api/api.js:39`, `manager/app/main.py` (handler không có mã kết quả) |
| RC4 | Response Assist cần Bearer token của operator. Token chỉ nhập được ở *Agents → Network & Firewall*. Nếu tab trình duyệt chưa có token, Response Assist trả 401 và không có chỗ nhập. | `manager/app/routers/v1/response_assist_router.py:34-48`, `frontend/src/components/incidents/ResponseAssist.jsx` |
| RC5 | `ActionSuggestions` gửi `onAction('refresh')`. Lệnh này đi tới `POST /incidents/{id}/action` và nhận `400 Unknown action_type 'refresh'`. | `frontend/src/components/incidents/ActionSuggestions.jsx:70` |

## Bằng chứng

Log của `larp-manager-1` trong 10 giờ trước khi chẩn đoán:

| Yêu cầu | Số lần | Kết quả |
| --- | --- | --- |
| `GET /incidents/inc_d7242d3eb8fa/ai-analysis` | 108 | 200. Giao diện chờ `suggested_action`. |
| `POST /incidents/inc_d7242d3eb8fa/ai-analysis/suggest-response` | 2 | 200 và log `completed`, nhưng `ai_analysis.suggested_action` vẫn `NULL` ở cả hai bản ghi. |
| `POST /incidents/inc_d7242d3eb8fa/action` | 5 | **400 Bad Request** |
| `GET/POST /incidents/{id}/response-proposals` | **0** | Tab Response Assist chưa từng được gọi. |
| `GET /response-proposals` không token (thử đọc) | 1 | `401 A valid administrator or operator access token is required` |

Chạy `investigate()` ở chế độ chỉ đọc trên DB thật cho chính sự cố này cho kết quả:

```text
classification sqli_tool_indicator, confidence 0.6
facts: POST /login, HTTP 200, peer 100.67.222.3, automation_hint sqlmap, payload_indicators []
missing: Verified application-side credential mismatch, Verified enforcement point
candidates: collect_additional_evidence (cần duyệt), generate_remediation_guidance (tự động), increase_monitoring (cần duyệt)
default proposal: collect_additional_evidence → REQUIRE_APPROVAL
```

Đây đúng là hành vi mong muốn cho chỉ dấu công cụ: điều tra, không chặn tự động.

## Không phải nguyên nhân

- `IncidentRepository.list returned 0 incidents (active_only=True)` đến từ truy vấn *Network findings* của dashboard (`dashboard_service.py:38`, `finding="network"`). Sự cố SQLi không phải network finding nên kết quả 0 là đúng.
- `Final score: 0` / `Calculated risk score 0.0` là điểm telemetry của host trong từng chu kỳ. Bằng chứng HTTP nằm trong `incidents.detection_evidence.behavior` và `web_access_logs`, nên `investigate()` không phụ thuộc điểm host. Kiểm thử `test_historical_incident_remains_readable_and_host_score_does_not_erase_http_evidence` đặt `risk_score = 0` và trạng thái `RESOLVED` mà phân tích vẫn giữ nguyên.
- Schema DB khớp model. Bảng `response_actions` có đủ cột `outcome` và `feedback_signal`.

## Tái hiện

Không gửi lệnh `isolate` tới Manager thật. Các kiểm thử dùng SQLite tạm, mô hình giả và Agent giả:

```bash
cd manager
PYTHONPATH=.. .venv/bin/python -m pytest app/test/test_response_proposal_routing.py -q
```

Trên mã trước khi sửa, 5/6 ca thất bại đúng như triệu chứng: `isolate` trả 400 trần, `suggest-response` trả `200 "suggesting"` cho sự cố HTTP và lỗi không có `outcome_code`.

## Bản sửa

**Backend**

- `app/core/response_outcome.py` định nghĩa `SUCCESS`, `INSUFFICIENT_EVIDENCE`, `POLICY_DENIED`, `APPROVAL_REQUIRED`, `AUTHORIZATION_FAILED`, `EXECUTOR_UNAVAILABLE`, `AGENT_OFFLINE`, `VALIDATION_ERROR`, `CONFLICT`, `NOT_FOUND` và `INTERNAL_ERROR`. Mọi body lỗi, kể cả 422, đều có `outcome_code`. Lỗi định tuyến có thêm `use: "response_assist"`.
- `suggest-response` từ chối ngay lúc gọi: sự cố HTTP nhận `409 POLICY_DENIED`, sự cố chưa có triage nhận `409 INSUFFICIENT_EVIDENCE`. Background log ghi rõ khi không tạo được đề xuất.
- Đường quick action và legacy apply trả `409 POLICY_DENIED` kèm `use: response_assist` cho sự cố HTTP. Kill tree thiếu danh tính tiến trình đã xác minh trả `INSUFFICIENT_EVIDENCE`.
- Response Assist gắn mã riêng cho từng trường hợp từ chối: thiếu bằng chứng, chưa duyệt, Agent offline, chính sách, xung đột và không có quyền. Phản hồi thành công có `outcome_code`.

**Giao diện**

- Sự cố HTTP mở thẳng tab *AI Response Assist*. Tab Actions thay panel đề xuất cũ và nút Isolate bằng lối dẫn sang Response Assist. HeroBanner hiện nút *AI Response Assist* thay cho *Isolate Host*.
- `api.js` giữ lại `status`, `outcome`, `use` và `requestId`. Response Assist hiện thông điệp theo từng mã và mở ô nhập token khi gặp `AUTHORIZATION_FAILED`. Token dùng chung khóa `larp_network_token` với tab Network.
- `onAction('refresh')` được thay bằng hàm tải lại sự cố.

**Phân quyền (P1, phát hiện trong khi truy vết)**

Middleware cũ miễn kiểm tra cho `/incidents` và `/agents`, và không phủ `/groups`, `/policies`, `/settings`, `/whitelist`, `/risk`, `/attack`. Vì vậy isolate, kill và đổi policy không cần credential, còn actor do client tự khai. Middleware mới áp dụng **default deny** khi đã cấu hình credential:

- Mọi request ghi cần token admin.
- Danh sách cho analyst được giới hạn theo method: assign, close, contain, false-positive, resolve, notes, rate, regenerate, suggest, dismiss, bulk-resolve, sửa sự cố, threat-intel check và report.
- Network module và Response Assist giữ kiểm tra theo phạm vi Agent của chúng.
- Actor ghi vào note và action là danh tính đã xác thực.

Chế độ phát triển, khi chưa cấu hình credential, giữ nguyên hành vi cũ.

## Kiểm thử hồi quy

| Bộ kiểm thử | Kết quả |
| --- | --- |
| `test_response_proposal_routing.py` (mới, 6 ca) | 6 đạt |
| `test_mutating_api_authorization.py` (mới, 21 ca) | 21 đạt |
| Toàn bộ `app/test` | 261 đạt, 5 thất bại có sẵn trước thay đổi (xem `CODE_MAP.md`) |
| `tests/integration` | 13 thất bại giống hệt bản gốc |
| `vite build` | Thành công, eslint không thêm lỗi mới |

## Triển khai

Container `larp-manager-1` không chạy `--reload`, frontend là image đã build. Bản sửa chỉ có hiệu lực sau khi người vận hành chạy:

```bash
docker compose restart manager
docker compose up -d --build frontend
```

Sau khi khởi động lại, mọi request ghi từ dashboard cần operator token. Nhập token ở Response Assist hoặc ở *Agents → Network & Firewall*.
