# LARP — phiên Dashboard, thực thi HTTP và thời gian tạo đề xuất

## Sự cố ngày 26/11/2026

Đã gọi **GET /api/v1/incidents/inc_cacf9928d315/response-proposals** trên Manager đang chạy, bỏ Bearer header. FastAPI trả **401**, `outcome_code=AUTHORIZATION_FAILED`, `request_id=req_00ec577d7401`. Chuỗi lỗi xuất phát từ `verify_operator_or_admin` tại `manager/app/core/network_security.py:84`, khi thiếu scheme Bearer hoặc thiếu token. Credential sai đi vào nhánh 401 khác. Scope hoặc role không đủ trả 403. Trước bản vá, credential cấu hình bằng SHA-256, không có thời hạn. Không có bản ghi header của lần bấm ban đầu để xác nhận trạng thái trình duyệt của người dùng.

Dashboard trước đây đọc credential từ ba khóa storage. Người dùng có thể mở Dashboard mà chưa từng nhập credential qua Network hoặc Response Assist. Refresh trong cùng tab vốn giữ sessionStorage. Giao diện thiếu bước đăng nhập chung để kiểm tra credential và thiết lập phiên với Manager.

**Điểm dừng thực tế nằm trước dispatch.** Truy vấn PostgreSQL đang chạy cho thấy bảng `response_actions` có **0 hàng**, bảng `commands` có **0 hàng chứa payload.assist_id**. Không có action ID, command ID, ACK, lỗi executor hoặc receipt để gán cho sự cố này. Runtime có hai operator, ba Agent credential và **0** mục `HTTP_RESPONSE_LAB_WAFS`. Đăng nhập thành công riêng lẻ vẫn chưa đủ điều kiện để cài lease trên Victim.

| Thuộc tính | Kết quả đọc trực tiếp |
|---|---|
| Incident | `inc_cacf9928d315`, Agent `ip-172-31-32-238` |
| Bằng chứng | Detector lưu 17 lần xác thực thất bại, 0 thành công. Sự kiện cuối liên kết tới HTTP 200 trên POST /login |
| Phân loại sau vá | `observed_login_failures`. Chạy lại `investigate` trong transaction PostgreSQL READ ONLY mất 11,05 ms |
| Phương án theo bằng chứng hiện có | Thu thập thêm, ghi hướng dẫn, tăng giám sát |
| Attribution | Log ghi nguồn 100.67.222.3. Sự cố lịch sử thiếu receipt trực tiếp còn TTL và cấu hình executor |
| Báo cáo của công cụ phía client | Flask dùng trường `password`. Fixture gửi nhầm trường, nhận HTTP 200 chứa “Sai tài khoản hoặc mật khẩu”, không có “Login failed”, không có phiên đăng nhập. Con số 16 không chứng minh mật khẩu đúng |

## Bản vá và API

Tất cả đường dẫn dưới đây có tiền tố `/api/v1`.

| Request | Hợp đồng |
|---|---|
| POST /auth/session | Header Bearer chứa credential operator/admin được cấp. Response 200 gồm access_token, expires_at (Unix seconds), actor và role, Cache-Control no-store. Credential Agent và phiên đã phát không được dùng để cấp phiên mới |
| GET /incidents/{id}/response-proposals | Trả investigation, policy_decision, actions, can_execute và agent_online sau xác thực và kiểm tra phạm vi |
| POST /incidents/{id}/response-proposals | Body rỗng hoặc action_type từ danh sách ứng viên. Trả bản ghi có action_id và recommendation_source. Mặc định dùng evidence_policy. model_review=true yêu cầu review bằng schema cũ cho đề xuất chưa lưu. ID phụ thuộc bằng chứng và phiên bản policy |
| POST /response-actions/{id}/{approve,reject,execute,rollback} | Body rỗng. Role admin hoặc operator đúng Agent. Kiểm tra lại evidence và policy khi duyệt/thực thi. Trường actor tự khai bị từ chối |
| GET /response-actions/{id} | Trả status, result, rollback_available và audit gồm actor, thời điểm, metadata |
| Legacy /actions, incident quick action và apply-suggestion | Dùng cùng bộ xác thực, kiểm tra Agent ở đường ghi. Action history có lọc scope tại DB. Credential Agent chỉ dùng cho giao thức Agent. Raw command API giữ credential quản trị legacy riêng |
| /policies | Dependency xác thực trong router. Ghi/evaluate cần admin. Kiểm tra phạm vi Agent đầu vào và tất cả thành viên đích khi evaluate policy nhóm |
| Lỗi | 401 khi cần đăng nhập, SESSION_EXPIRED khi hết hạn, 403 khi thiếu quyền, 409 khi thiếu bằng chứng/chưa duyệt/Agent offline, 422 cho body sai schema |

`frontend/src/api/api.js:17` gửi session Bearer. Dashboard có hộp đăng nhập chung, xóa phiên bị từ chối và phân biệt 403 với hết phiên. Session tồn tại một giờ trong tab và kiểm tra quyền hiện tại ở mỗi request. Đăng xuất xóa bản lưu trong trình duyệt. Một bearer đã sao chép còn dùng được đến khi hết hạn hoặc khi xoay credential/key. Nhiều worker/replica cần cùng secret `OPERATOR_SESSION_KEY` tối thiểu 32 ký tự. Với key ngẫu nhiên mặc định, khởi động lại Manager yêu cầu đăng nhập lại.

`manager/app/routers/v1/response_assist_router.py:48` cấp phiên. Hàm `proposals` tại dòng 80 xác thực trước khi lấy dữ liệu. Hàm `propose` tại dòng 99 lưu ứng viên. `incident_router.response_actor` tại dòng 33 lấy Agent từ incident và actor từ credential. Role operator phải khai báo danh sách Agent cụ thể; analyst đọc và đề xuất; admin giữ quyền quản trị hiện có.

## Chuỗi thực thi

| Bước | Bản ghi và điều kiện |
|---|---|
| Điều tra | `http_investigation.investigate` (dòng 119) đọc `incidents`, `web_access_logs` và `auth_events`. Trước bản vá, incident Flask có evidence_type=authentication không đi vào luồng HTTP. Hiện tại kiểm tra ID sự kiện, Agent, peer, method, route, trạng thái xác thực và request ID. Điểm host bằng 0 vẫn giữ kết quả điều tra HTTP |
| Đề xuất | `response_actions.id`, incident_id, agent_id, action_type, action_params chứa target, evidence_ids, TTL, policy, rationale. Sự kiện proposed và quyết định ghi vào `action_audit_logs` |
| Phê duyệt | `transition` dòng 174 xác thực actor và khóa action. pending_approval → approved. Gửi lại cùng thao tác có tính idempotent |
| Thu thập trên Agent | Dòng 218 đưa network_refresh vào `commands`, lưu command_id trong snapshot và assist_id trong payload. Agent xác thực nhận trên heartbeat. Manager đối chiếu ACK với command và snapshot. Thiếu snapshot dẫn tới kết quả thất bại trong fixture |
| HTTP/WAF | Dòng 231 gọi `waf_reconciliation.reconcile`. Adapter hiện có lưu lease theo action ID, peer, loại và deadline vào leases.db. Flask đọc cùng store. Nhánh này không tạo command ID hay ACK của Agent |
| Xác minh | `agent/vulnerable_web/response_guard.py:40` áp dụng trên POST /login của direct peer. Hook tại dòng 92 ghi request ID, peer, thời điểm, status và action ID. `lab_waf.verify` dòng 61 kiểm tra receipt đúng action, peer, HTTP status và cửa sổ lease. Khi chỉ có lease, trạng thái là verifying |
| Kết thúc | Rollback chỉ xóa lease do action sở hữu. Sau deadline Flask tự bỏ hiệu lực, kể cả khi Manager offline. Audit giữ lịch sử xác minh. Guidance kiểm tra note đã lưu. Monitoring ghi truy vấn có giới hạn thời gian |

**Điều kiện để chạy bản vá trong lab có Victim thật.** Manager và Flask phải nhìn thấy **cùng hai DB** qua thư mục riêng của Agent. Hai thư mục trùng tên trên hai máy độc lập không đáp ứng điều kiện này. Agent VPS đóng gói `agent/vulnerable_web/app.py`; bản entrypoint Flask khác phải thực sự cài hook mới có thể thực thi. Manager đọc `HTTP_RESPONSE_LAB_WAFS`, ứng dụng đọc `LARP_HTTP_LAB_STATE`. Với peer dải 100.64.0.0/10, cần khai báo chính xác IP thử nghiệm ở cả disposable_peers của Manager và `LARP_HTTP_DISPOSABLE_PEERS` của Flask, tránh protected_peers và trusted proxies. Vẫn cần request mới có direct-peer receipt. Port 5000 không chứng minh peer hoặc agent identity.

Giữ nguyên hai action type trên wire là `temporary_ip_block` và `apply_rate_limit`; cả hai thuộc Flask HTTP. TTL 300 giây. Rate limit cho phép ba POST mỗi cửa sổ 10 giây. GET, ICMP, SSH và kết nối quản lý không đi qua bộ lọc POST /login. Chưa bổ sung action firewall: sự cố này chỉ xác lập đích ứng dụng, không có scope interface/protocol đáng tin cậy và phép xác minh rollback độc lập cho network block. Không thay firewall, gửi lệnh tới Victim, restart hay deploy AWS.

## Đo độ trễ

| Mẫu | Kết quả |
|---|---|
| Log triage lúc 07:35:35 UTC | Ollama 46,239 s, gồm load 10,880 s, prompt evaluation 19,375 s (545 token), generation 15,895 s (65 token). Các lượt trước 42,786 s và 56,613 s. Log không có số queue wait độc lập của Ollama |
| Replay chỉ đọc cùng incident | Evidence retrieval 14,15 ms, context projection 0,32 ms, similar-case lookup 12,19 ms (0 match), knowledge retrieval 12,26 ms (2 reference) |
| POST proposal cục bộ trước/sau | Cùng fixture, hai lần chạy pytest độc lập, model giả có độ trễ 250 ms. Trước **507,8 ms**, một lượt inference. Sau **207,2 ms**, không gọi inference. Một mẫu mỗi phiên bản; không đại diện cho p95 hoặc thời gian trên Victim |
| Bên trong POST sau vá | Evidence và projection 15,24 ms, policy 0,0044 ms, INSERT/flush action 9,06 ms. Số INSERT chưa gồm commit và audit |
| Frontend | Chrome headless, bản build thật, API fixture. Từ click đăng nhập tới receipt hiển thị mất khoảng 0,2–0,5 s trong các lượt đo. Refresh cùng tab giữ header và receipt |

Trước bản vá, POST chờ `recommend` tối đa 12 giây rồi điều tra lại trước khi lưu. Còn triage narrative chạy trong job riêng. Dashboard hiện mặc định lưu ngay phương án deterministic, hiển thị bản ghi do POST trả về, sau đó refresh/poll. Khi chọn review, dùng cùng hàng đợi giới hạn của triage, gộp yêu cầu trùng, kiểm tra schema, candidate và evidence IDs. Exact cache chỉ bật khi cấu hình revision model bất biến qua `AI_RESPONSE_MODEL_VERSION`. Thay revision khi thay weights. Cache key bao gồm input, Agent, model, prompt/schema version và policy version. Similar cases chỉ cung cấp tham chiếu runbook trong guidance. Cấu hình sec-q5 và context được giữ nguyên.

Audit của optional review có thời gian chờ slot Manager, JSON validation và các duration Ollama thực sự trả về. Những stage này không chạy trên POST mặc định. Không có phép đo queue nội bộ của Ollama hoặc thời gian refresh của trình duyệt người dùng trong lần xảy ra sự cố.

## Kiểm thử và bằng chứng

Đối chiếu nguồn trước vá tại commit `abebd46`. Interceptor đọc ba khóa ở `frontend/src/api/api.js:18`. Bộ lọc chỉ nhận HTTP tại `http_investigation.py:113` và `:120` bỏ qua sự cố auth_events. Điểm chờ model ở `response_assist_router.py:95`. Hai nhánh thực thi ở dòng 191 (queue thu thập) và 204 (adapter ứng dụng).

**VERIFIED trên HTTP loopback.** Test dùng socket TCP, cùng HTTP client trước và sau khi cài lease, middleware Flask thật và WSGI peer cố định của lab. FastAPI dùng TestClient với DB tạm. Mỗi receipt bên dưới khớp request ID ghi vào kết quả của action.

| Action | POST /login | Receipt sau enforcement | Sau rollback |
|---|---|---|---|
| temporary_ip_block | 200 trước khi duyệt, 403 sau execute | b04f727585a74b98b5f380ec64ea41ce | 200 |
| apply_rate_limit | 200 trước action, ba lần đầu 200, lần thứ tư 429 | e2b0eaff0a194e3cbf2460dce2e42fe9 | 200 |

| Yêu cầu hồi quy | Kiểm tra |
|---|---|
| 1–5. Admin, operator, sai scope, thiếu token, hết phiên | Phiên admin duyệt và dispatch. Phiên operator đúng Agent duyệt được, sai Agent bị 403. Từ chối Agent credential, session hết TTL và gia hạn bằng chính session |
| 6–7. Refresh, legacy | Chrome reload dùng lại session và gửi Bearer. Legacy create/undo và process termination kiểm tra role và actor tại server |
| 8–9. Dispatch và ACK | Command được nhận qua WebSocket Agent fixture. Kiểm tra trùng approve/execute, ACK trước snapshot, offline và ACK thiếu evidence |
| 10–14. 403, 429, TTL, rollback, spoofing | HTTP loopback có receipt; Flask client kiểm tra hết TTL sau khởi tạo lại ứng dụng, lease cạnh tranh, rollback lỗi và thử lại, X-Forwarded-For và CF-Connecting-IP |
| 15–17. Proxy, nhầm kết quả công cụ, host risk 0 | Login handler của gói Agent kiểm tra trực tiếp peer thử nghiệm, proxy tin cậy và GET. Form sai vẫn nhận trang lỗi 200. Incident HTTP và xác thực vẫn có evidence khi host risk=0 |
| 18–20. Cache, concurrency, timeout | L1 xác minh version và tenant. Hai POST đồng thời nhận một action ID, một lượt inference và một chuỗi audit. Timeout trả policy_fallback. Đổi model revision vô hiệu hóa cache |
| 21–22. UI và dispatch trái quyền | Chrome hiển thị evidence receipt, Execute disabled. API từ chối giao dịch trái quyền, giữ trạng thái action. Trước execute, test đếm 0 command |

Các test chính nằm trong `manager/app/test/test_http_response_assist.py`, `test_response_phase2_verification.py`, `test_proposal_latency.py`, và `frontend/tests/response_session_browser.py`. Có thể chạy lại kiểm thử độc lập từ gốc repository:

```bash
(cd manager && DEBUG=false PYTHONPATH=.. .venv/bin/python -m pytest -q app/test/test_{http_response_assist,response_phase2_verification,mutating_api_authorization,response_proposal_routing,analysis_cache,proposal_latency,auth_evidence_pipeline,network_module,group_execution_policy,graduated_response,ai_http_triage_regression}.py)
(cd frontend && npm run build --silent)
manager/.venv/bin/python frontend/tests/response_session_browser.py
```

Hai lỗi trong `test_auth_evidence_pipeline.py` đã tái hiện riêng từ `git archive HEAD` trước bản vá: kiểm thử summary đòi cụm “5 thất bại” và kiểm thử ingest giả định chỉ tạo một incident trong khi pipeline tạo hai. Build Vite thành công với cảnh báo kích thước chunk và dynamic import. Kiểm tra production ở trên chỉ đọc trạng thái Manager/PostgreSQL. Browser dùng API fixture; số liệu 403/429 chỉ xác nhận thực thi trong lab.

## Kiểm thử và bằng chứng

Đối chiếu nguồn trước vá tại commit `abebd46`. Interceptor đọc ba khóa ở `frontend/src/api/api.js:18`. Bộ lọc chỉ nhận HTTP tại `http_investigation.py:113` và `:120` bỏ qua sự cố auth_events. Điểm chờ model ở `response_assist_router.py:95`. Hai nhánh thực thi ở dòng 191 (queue thu thập) và 204 (adapter ứng dụng).

**VERIFIED trên HTTP loopback.** Test dùng socket TCP, cùng HTTP client trước và sau khi cài lease, middleware Flask thật và WSGI peer cố định của lab. FastAPI dùng TestClient với DB tạm. Mỗi receipt bên dưới khớp request ID ghi vào kết quả của action.

| Action | POST /login | Receipt sau enforcement | Sau rollback |
|---|---|---|---|
| temporary_ip_block | 200 trước khi duyệt, 403 sau execute | b04f727585a74b98b5f380ec64ea41ce | 200 |
| apply_rate_limit | 200 trước action, ba lần đầu 200, lần thứ tư 429 | e2b0eaff0a194e3cbf2460dce2e42fe9 | 200 |

| Yêu cầu hồi quy | Kiểm tra |
|---|---|
| 1–5. Admin, operator, sai scope, thiếu token, hết phiên | Phiên admin duyệt và dispatch. Phiên operator đúng Agent duyệt được, sai Agent bị 403. Từ chối Agent credential, session hết TTL và gia hạn bằng chính session |
| 6–7. Refresh, legacy | Chrome reload dùng lại session và gửi Bearer. Legacy create/undo và process termination kiểm tra role và actor tại server |
| 8–9. Dispatch và ACK | Command được nhận qua WebSocket Agent fixture. Kiểm tra trùng approve/execute, ACK trước snapshot, offline và ACK thiếu evidence |
| 10–14. 403, 429, TTL, rollback, spoofing | HTTP loopback có receipt; Flask client kiểm tra hết TTL sau khởi tạo lại ứng dụng, lease cạnh tranh, rollback lỗi và thử lại, X-Forwarded-For và CF-Connecting-IP |
| 15–17. Proxy, nhầm kết quả công cụ, host risk 0 | Login handler của gói Agent kiểm tra trực tiếp peer thử nghiệm, proxy tin cậy và GET. Form sai vẫn nhận trang lỗi 200. Incident HTTP và xác thực vẫn có evidence khi host risk=0 |
| 18–20. Cache, concurrency, timeout | L1 xác minh version và tenant. Hai POST đồng thời nhận một action ID, một lượt inference và một chuỗi audit. Timeout trả policy_fallback. Đổi model revision vô hiệu hóa cache |
| 21–22. UI và dispatch trái quyền | Chrome hiển thị evidence receipt, Execute disabled. API từ chối giao dịch trái quyền, giữ trạng thái action. Trước execute, test đếm 0 command |

Các test chính nằm trong `manager/app/test/test_http_response_assist.py`, `test_response_phase2_verification.py`, `test_proposal_latency.py`, và `frontend/tests/response_session_browser.py`. Có thể chạy lại kiểm thử độc lập từ gốc repository:

```bash
(cd manager && DEBUG=false PYTHONPATH=.. .venv/bin/python -m pytest -q app/test/test_{http_response_assist,response_phase2_verification,mutating_api_authorization,response_proposal_routing,analysis_cache,proposal_latency,auth_evidence_pipeline,network_module,group_execution_policy,graduated_response,ai_http_triage_regression}.py)
(cd frontend && npm run build --silent)
manager/.venv/bin/python frontend/tests/response_session_browser.py
```

Hai lỗi trong `test_auth_evidence_pipeline.py` đã tái hiện riêng từ `git archive HEAD` trước bản vá: kiểm thử summary đòi cụm “5 thất bại” và kiểm thử ingest giả định chỉ tạo một incident trong khi pipeline tạo hai. Build Vite thành công với cảnh báo kích thước chunk và dynamic import. Kiểm tra production ở trên chỉ đọc trạng thái Manager/PostgreSQL. Browser dùng API fixture; số liệu 403/429 chỉ xác nhận thực thi trong lab.
