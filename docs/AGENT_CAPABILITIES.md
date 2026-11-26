# Năng lực của Agent và mô hình quyền

Tài liệu này mô tả năng lực Linux Agent hiện có, các khoảng trống so với mô hình executor theo capability, và thiết kế cho năng lực chặn HTTP trên endpoint (P8). **Phần P8 chưa được triển khai.**

## Hai kênh lệnh hiện có

| Kênh | Lệnh | Xác thực | Kiểm tra trên Agent |
| --- | --- | --- | --- |
| Kênh network (`agent/network_channel.py`) | `network_refresh`, `network_firewall` | Token riêng của Agent đã đăng ký (`NETWORK_AGENT_TOKENS`), `wss://`, `schema_version` 1, đúng `agent_id`, hạn giao 45 giây | Firewall: giao dịch UFW có fingerprint cấu hình tĩnh, SSH xác thực từ Manager, rollback timer độc lập, khôi phục lúc boot |
| Kênh legacy (`COMMAND_HANDLERS`, `agent/agent.py:execute_command`) | `isolate`, `unisolate`, `kill_process`, `kill_process_tree` (PID + start time), `quarantine`, `release_quarantine`, `yara_scan`, `self_update`, `syn_flood` | Agent chưa đăng ký vẫn kết nối được, không có ký lệnh | Mỗi handler tự kiểm tra tham số |

Agent không nhận script shell tùy ý từ Manager hay từ LLM: chỉ tên lệnh trong `COMMAND_HANDLERS` được gọi. Model trong Response Assist chỉ chọn trong danh sách ứng viên và không tạo lệnh.

## Khoảng trống (mở)

- `larp-agent.service` chạy `User=root` cho toàn bộ Agent, chưa tách collector không đặc quyền khỏi executor đặc quyền.
- `syn_flood` là công cụ tấn công nằm trong bảng lệnh của Agent nạn nhân, không có cổng xác nhận (CODE_MAP finding 3). Nên gỡ khỏi bản dựng production.
- `self_update` chỉ ghi log rồi **trả `success` mà không cập nhật gì**. Đây là báo cáo thành công giả, cần sửa thành `failed` hoặc gỡ bỏ.
- Agent chưa đăng ký được nhận lệnh legacy và `COMMAND_ACK` gắn theo `agent_id` khai báo (CODE_MAP finding 1, 75). Đề xuất: công tắc `REQUIRE_AGENT_ENROLLMENT` và gắn ACK với phiên đã xác thực.

## Thiết kế P8: chặn HTTP trên endpoint (chưa triển khai)

Hiện lab WAF chỉ chạy khi Manager và ứng dụng Flask dùng chung một thư mục (`HTTP_RESPONSE_LAB_WAFS`), và chỉ với peer thuộc RFC 5737. Vì vậy trên VPS AWS, Response Assist báo `EXECUTOR_UNAVAILABLE` cho chặn và giới hạn tốc độ. Đây là hành vi đúng: không giả thành công.

Phương án đề xuất là thêm lệnh thứ ba `network_http_guard` trên kênh network đã có, không tạo transport mới:

1. **Lệnh:** `{action: "network_http_guard", op: "activate"|"remove"|"status", peer, kind: "temporary_ip_block"|"apply_rate_limit", action_id, expires_at, nonce}`.
2. **Kiểm tra trên Agent:**
   - `peer` phải nằm trong allowlist cục bộ `/etc/larp-agent/http-guard.env`, do quản trị viên endpoint đặt.
   - Peer không được là loopback, IP của Manager, mạng quản trị hay CIDR SSH.
   - TTL tối đa 300 giây, nonce dùng một lần, `expires_at` tuyệt đối.
3. **Thực thi:** helper đặc quyền tối thiểu chỉ ghi `leases.db` của `response_guard.py` (`LARP_HTTP_LAB_STATE`). Không chạm firewall hệ thống.
4. **Xác minh:** Agent đọc biên nhận 403/429 từ `observations.db` và gửi trong `NETWORK_ACK`. Manager chỉ đánh dấu `succeeded` khi có biên nhận khớp `action_id`, peer và cửa sổ thời gian.
5. **Rollback:** `op: remove`, xác minh lease đã biến mất. Lease hết hạn mà không cần Manager.
6. **Kiểm thử:** Agent offline, ACK không có biên nhận, nonce phát lại, peer bị bảo vệ, TTL quá giới hạn, khởi động lại Agent trong khi lease còn hiệu lực.

Với Cloudflare Tunnel, IP nhìn thấy ở Flask là của proxy. Header forwarded chỉ được tin khi chuỗi proxy đã xác minh, nên chặn theo IP phải thực hiện ở WAF của Cloudflare, ngoài phạm vi Agent. Khi truy cập trực tiếp (Tailscale hoặc IP công khai), peer trực tiếp là nguồn đáng tin.

## Cô lập host

`isolate` giữ kênh Manager. Khôi phục khẩn cấp theo `agent/README_VPS.md` (mục khôi phục từ AWS console). Response Assist chỉ đề xuất cô lập khi hậu khai thác đã được xác minh, và việc thực thi đi qua sự cố host liên quan.
