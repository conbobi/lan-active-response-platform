# Kịch bản demo SOC: AI Response Assist

Mỗi bước ghi rõ trạng thái: **VERIFIED** (đã chạy và kiểm chứng), **TESTED** (có kiểm thử tự động, chưa chạy trên hệ thống thật) hoặc **NOT IMPLEMENTED**. Không giả lập kết quả thành công.

## Chuẩn bị

1. Khởi động lại Manager và build lại frontend để nạp mã mới. Hiện container không chạy `--reload`.

   ```bash
   docker compose restart manager
   docker compose up -d --build frontend
   ```

2. Đăng nhập dashboard bằng tài khoản SOC có vai trò admin hoặc operator và phạm vi chứa Agent mục tiêu.
3. Tùy chọn: bật L1 cache bằng `AI_RESPONSE_MODEL_VERSION=<digest model>` trong `.env`, rồi khởi động lại Manager.

## Demo A: chỉ báo sqlmap → điều tra, không chặn tự động

**VERIFIED** (logic chạy trên dữ liệu thật; giao diện kiểm bằng trình duyệt headless).

Từ máy hacker:

```bash
sqlmap -u "http://<IP_VPS>:5000/login" --data "username=a&password=b" --batch --level 1
```

Mở **Incidents → sự cố "Sqli tool indicator" → tab AI Response Assist**. Tab tự mở với sự cố HTTP.

Kết quả mong đợi:

- Đánh giá `sqli · mức 1 · tool_indicator`.
- Không ánh xạ MITRE và mức nguy hiểm *Thấp*.
- Kế hoạch gồm thu thập bằng chứng, giám sát và hướng dẫn khắc phục.
- Chặn và rate limit không khả dụng, kèm lý do. Trên VPS AWS lý do là `EXECUTOR_UNAVAILABLE`.

Với brute force bằng Hydra, kiểm chứng trên `inc_90940e8f23fb` cho kết quả `authentication_brute_force`, **T1110** với 17 evidence ref và trích dẫn ATT&CK T1110/DET0463. Rate limit hiện `EXECUTOR_UNAVAILABLE`.

## Demo B: dò SQLi đã xác minh → chặn tạm, xác minh 403/429, rollback

- **TESTED:** `test_verified_flask_response`, `test_conflicting_traffic_actions_on_same_peer`, `test_historical_incident_is_read_only_for_enforcement` chạy với ứng dụng Flask thật có `response_guard`.
- Giao diện: **VERIFIED** bằng trình duyệt headless với payload sinh từ backend thật.
- **Trên VPS AWS: NOT IMPLEMENTED**, cần năng lực P8 (`docs/AGENT_CAPABILITIES.md`).

Hiện chỉ chạy được trên máy Manager, khi Manager và Flask dùng chung thư mục lab:

1. Đặt `LARP_HTTP_LAB_STATE=/srv/larp-lab` cho ứng dụng Flask chạy cục bộ. Đặt `HTTP_RESPONSE_LAB_WAFS='{"<agent_id>":{"directory":"/srv/larp-lab","disposable_peers":["192.0.2.42"],"protected_peers":[]}}'` cho Manager.
2. Gửi request từ peer thử nghiệm 192.0.2.42, ví dụ thêm địa chỉ đó vào `lo` rồi dùng `curl --interface 192.0.2.42`. Cần sudo, nên làm trên máy lab, không làm trên production.
3. Request có payload, ví dụ `username=' OR 1=1 --`, đưa sự cố lên `probing`, ánh xạ T1190 kèm evidence ref.
4. Chọn *rate limit* và *temporary IP block*, rồi bấm **Đề xuất các hành động đã chọn**. Mỗi mục có `outcome_code` riêng.
5. **Phê duyệt đã chọn**, sau đó **Execute** từng hành động. Nếu thực thi cái thứ hai trong khi cái đầu còn hiệu lực, hệ thống trả `POLICY_DENIED`, kèm `blocked_by`.
6. Request tiếp theo nhận 403 (hoặc 429 sau 3 request trong 10 giây). Thẻ hành động chuyển sang `succeeded` với biên nhận request ID.
7. **Rollback / Undo** gỡ lease và xác minh lease đã biến mất. Request sau đó nhận 200.

## Demo C: RCE/process/network → đề xuất ngăn chặn host

- **TESTED:** `test_host_actions_only_for_verified_post_exploitation` và các kiểm thử tương quan trong `test_pattern_engine.py`.
- **Chưa chạy end-to-end trên VPS.**

1. Khai thác command injection `/ping` để ứng dụng web sinh shell có kết nối ra ngoài, chỉ trên VPS lab.
2. Luật `builtin_linux_network_shell` tạo sự cố host. Sự cố HTTP chỉ nhận hoạt động này là **đã tương quan** khi tiến trình cha là ứng dụng web và khớp PID + start time.
3. Kế hoạch thêm `kill_process_tree` và `isolate`, kèm liên kết tới sự cố host. Việc thực thi đi qua đường kill hoặc isolate đã xác minh của sự cố đó: cần admin, xác nhận và audit.
4. Nếu tương quan chưa được xác minh, sự cố HTTP chỉ ghi "liên quan, chưa tương quan" và không đề xuất ngăn chặn host.

## Kiểm tra lỗi

| Hiện tượng | `outcome_code` | Cách xử lý |
| --- | --- | --- |
| Chưa đăng nhập hoặc thiếu quyền | `AUTHORIZATION_FAILED` / `SIGN_IN_REQUIRED` | Đăng nhập bằng tài khoản có phạm vi Agent |
| Agent offline khi thu thập | `AGENT_OFFLINE` | Kiểm tra `journalctl -u larp-agent` |
| Không chặn được trên AWS | `EXECUTOR_UNAVAILABLE` | Bình thường, cần P8 |
| Sự cố đã đóng | `POLICY_DENIED` | Mở lại sự cố nếu cần phản ứng mới |
| Mock mode | `MOCK_ONLY` | Không phải tác động thật |
