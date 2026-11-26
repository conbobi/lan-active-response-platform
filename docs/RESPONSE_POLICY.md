# Chính sách phản ứng (Response Assist)

Áp dụng cho `GET/POST /api/v1/incidents/{id}/response-proposals[/batch]` và `/api/v1/response-actions/...` (`manager/app/routers/v1/response_assist_router.py`, `services/response/response_plan.py`).

## Nguyên tắc

1. **AI đề xuất ≠ đã duyệt ≠ đã thực thi ≠ đã xác minh.** Model chỉ được chọn ứng viên do Manager tạo từ bằng chứng, hoặc trả `no_action`. Model không tạo mục tiêu, tham số hay quyền.
2. **Mục tiêu do server suy ra.** IP, endpoint và session lấy từ bản ghi đã lưu, không lấy từ request của client.
3. **Mỗi hành động có policy, phê duyệt, thực thi, xác minh và audit riêng.**
4. **ACK không chứng minh tác động.** Trạng thái chỉ là `succeeded` khi đã xác minh được tác động.
5. **Không chặn hay cô lập dựa trên một chỉ báo yếu.** User-Agent tự khai báo hay HTTP 200 không đủ.

## Hành động khả dụng

| Hành động | Phê duyệt | Điều kiện | Xác minh | Rollback |
| --- | --- | --- | --- | --- |
| `collect_additional_evidence` | Admin hoặc operator | Bằng chứng HTTP tương quan, Agent đã đăng ký và online | Snapshot `NETWORK_SNAPSHOT` mới + `related_records` | Chỉ đọc |
| `increase_monitoring` | Có | Quan sát nguồn đã lưu | Truy vấn `web_access_logs` có giới hạn, 5 phút | Dừng giám sát |
| `generate_remediation_guidance` | Tự động | Bằng chứng HTTP | Ghi chú đã được lưu vào DB | Xóa ghi chú |
| `apply_rate_limit` | Có | Payload SQL + quan sát trực tiếp còn mới (≤ 300 s, không forwarded) + peer thử nghiệm được phép + lab WAF đã cấu hình | Biên nhận HTTP **429** từ ứng dụng | Gỡ lease hoặc hết TTL 300 s |
| `temporary_ip_block` | Có | Như trên | Biên nhận HTTP **403** từ ứng dụng | Gỡ lease hoặc hết TTL 300 s |
| `revoke_session` | Có | Đã xác nhận cấp phiên sai thông tin đăng nhập (L4) | Biên nhận HTTP 401 cho đúng cookie | Không đảo ngược được, người dùng đăng nhập lại |
| `kill_process_tree`, `isolate` | Có (admin) | Chỉ khi có hậu khai thác đã xác minh. Thực thi trên **sự cố host liên quan**, qua đường xác minh PID + start time hiện có | Theo action host hiện có | `unisolate` |
| Khuyến nghị (`recommend_*`) | — | Chỉ hiển thị | — | — |

Chặn IP nguồn **không phải** cô lập máy kẻ tấn công. LARP chỉ chặn được traffic tại điểm thực thi do mình quản lý. Không có thao tác nào tác động lên máy không cài Agent.

## Quyết định theo từng hành động

`policy_decision` nhận một trong các giá trị: `ALLOW_AUTOMATIC` (chỉ hướng dẫn), `REQUIRE_APPROVAL`, `REQUIRE_MORE_EVIDENCE`, `ADVISORY_ONLY`, `DENY`. Thẻ không khả dụng luôn kèm `disabled_reason` và `outcome_code`, ví dụ:

- `EXECUTOR_UNAVAILABLE`: Agent chưa có lab WAF. Đây là tình trạng của VPS AWS hiện tại.
- `POLICY_DENIED`: peer không thuộc danh sách thử nghiệm, sự cố đã đóng, hoặc xung đột với hành động khác.
- `INSUFFICIENT_EVIDENCE`: chỉ có chỉ báo công cụ, nguồn đi qua proxy hoặc forwarded, hoặc quan sát đã cũ.

## Quy tắc lúc thực thi

- **Đánh giá lại:** mỗi lần duyệt hoặc thực thi đều chạy lại `investigate()`. Đề xuất không còn khớp bằng chứng hiện tại thì bị từ chối (`INSUFFICIENT_EVIDENCE`, `POLICY_DENIED`).
- **Sự cố lịch sử** (RESOLVED, CLOSED, FALSE_POSITIVE): vẫn phân tích được ở chế độ chỉ đọc. Chặn, giới hạn tốc độ, thu hồi phiên và giám sát bị từ chối (`POLICY_DENIED`). Thu thập và hướng dẫn chỉ đọc vẫn được phép.
- **Xung đột:** dùng hợp của `conflicts_with` trong playbook, cộng với việc block và rate limit cùng một peer. Hành động xung đột đang hiệu lực thì trả `409 POLICY_DENIED`, kèm `blocked_by`. Kiểm tra được tuần tự hóa bằng khóa dòng Agent trên PostgreSQL. Lab WAF còn bảo đảm mỗi peer chỉ có một lease.
- **Lô (batch):** mỗi mục đi đúng đường xử lý đơn lẻ và nhận `outcome_code` riêng. Yêu cầu chưa xác thực bị từ chối toàn bộ (401). Quyền theo Agent và vai trò được kiểm tra cho từng mục.
- **Mock mode:** `RESPONSE_MOCK_MODE=true` chỉ có hiệu lực khi `DEBUG=true`. Khi bật, không gửi lệnh tới Agent và không ghi lease WAF. Trạng thái là `mock_succeeded` với `outcome_code MOCK_ONLY`, `mock: true` và xác minh `mock`. Dashboard ghi rõ MOCK và không bao giờ coi đây là thành công.

## Bảo vệ ứng dụng LAB

`agent/vulnerable_web/app.py` **cố ý** có lỗi SQLi để demo và không được sửa. Khuyến nghị tham số hóa hiển thị bản vá đề xuất (`secure_code_diff`) cùng trích dẫn OWASP. Bản vá cần phê duyệt và thuộc một chế độ hardened tách riêng. Không có thao tác nào âm thầm tắt lỗ hổng lab.

## Phân quyền

Phân quyền xem `docs/RESPONSE_ROOT_CAUSE.md` và `docs/RESPONSE_AUTH_EXECUTION_LATENCY.md`. Middleware từ chối mặc định mọi request ghi. JWT có vai trò admin, operator hoặc analyst và phạm vi theo Agent. Actor ghi vào audit là danh tính đã xác thực.
