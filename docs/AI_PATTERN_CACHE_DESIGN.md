# Thiết kế cache phân tích AI

Mục tiêu là giảm độ trễ khi gặp lại cùng bằng chứng hoặc cùng mẫu hành vi, mà không tái sử dụng sai kết luận. `keep_alive` của Ollama chỉ giữ model trong RAM, không phải bộ nhớ điều tra. Không fine-tune model bằng sự cố chưa được xác minh. `num_ctx` giữ nguyên.

Mã nguồn nằm ở `manager/app/services/ai/analysis_cache.py` và các bảng `ai_analysis_cache`, `incident_pattern_cases` (migration `b7e4c2a91d35`, tạo thêm bằng `create_all` khi khởi động).

## L1: cache phân tích chính xác

- **Khóa:** sha256 trên JSON chuẩn hóa của đầu vào model (văn bản prompt đúng như model nhận), loại phát hiện, tên model, revision model, phiên bản prompt (hash system prompt), phiên bản schema (hash JSON schema), `kb_version` và tenant. Khóa không dùng tiêu đề sự cố hay risk score riêng lẻ.
- **Chỉ bật khi revision model được ghim** bằng `AI_RESPONSE_MODEL_VERSION`. Tag `sec-q5:latest` có thể đổi weights mà giữ tên. Đổi revision khi thay model.
- **Nội dung lưu:** chỉ output đã qua schema (TriageVerdict, EvidenceAssessment, ModelChoice). Khi hit, output được kiểm lại theo prompt hiện tại và `validate_verdict` theo context hiện tại. Evidence ID bịa sẽ bị loại và model được gọi lại.
- **Không cache:** trạng thái phê duyệt, phân quyền hay thực thi. `put()` từ chối khóa dạng status, approved, authorization, dispatch, executed. Riêng `http_status` và `authentication_status` là dữ kiện quan sát nên được phép.
- **Dữ liệu nhạy cảm:** password, token, cookie, session, Authorization, raw payload và body bị xóa trước khi lưu. Bearer, Basic và JWT trong văn bản bị che.
- **Giới hạn:** TTL 24 giờ (`AI_CACHE_TTL_SECONDS`), tối đa 5000 dòng (`AI_CACHE_MAX_ROWS`), mỗi payload 64 KB. Bản ghi hết hạn hoặc lệch phiên bản tính là stale miss. Bằng chứng mới của cùng sự cố làm bản cũ bị thay thế.
- **Regenerate thủ công** bỏ qua bước đọc nhưng vẫn ghi. Lỗi cache không bao giờ làm hỏng triage, vì mỗi lần đọc và ghi dùng một session ngắn riêng.

## L2: truy xuất ca tương tự

Fingerprint gồm: phân loại, HTTP method, endpoint chuẩn hóa (số, UUID và hex được thay bằng placeholder, bỏ query string), chỉ báo công cụ, nhóm chỉ báo payload, kết quả xác thực, hành vi tiến trình, chiều kết nối và mức đầy đủ bằng chứng. **IP nguồn, PID, request ID, session và thời điểm không phải đặc trưng.** Độ tương đồng là Jaccard có trọng số, ngưỡng 0,8. Khác phân loại thì bằng 0.

- Chỉ trả về ca đã được analyst gán nhãn (`labeled_by`), cùng tenant (Agent).
- Kết quả chỉ gồm incident ID, độ tương đồng, phân loại, nhãn, playbook và tham chiếu kiến thức. Không trả IP, PID, request ID, session, kết quả khai thác hay quyền thực thi.
- Ca được ghi khi analyst gán nhãn sự cố (`IncidentService._record_labeled_case`) và khi tạo ghi chú khắc phục. Không ghi trên đường tạo đề xuất, vì kiểm thử đề xuất đồng thời cho thấy tranh chấp ghi.
- Dashboard ghi rõ ca tương tự là "Tham khảo — không phải bằng chứng của sự cố này".

## L3: cache truy xuất kiến thức

LRU trong bộ nhớ, có TTL và an toàn luồng, khóa theo (`kb_version`, truy vấn chuẩn hóa, danh mục, attack ID, giới hạn). Đổi `kb_version` thì toàn bộ bị vô hiệu.

## Đo đạc

`cache_stats()` trả hit, miss, stale, eviction và p50/p95 cho từng tầng. Benchmark: `scripts/benchmark_ai_triage.py`, chạy trên SQLite tạm, không chạm DB production.

Kết quả ngày 26/11/2026 với `sec-q5:latest` thật chạy CPU trên máy Manager, 5 lượt:

| Bước | p50 | p95 |
| --- | --- | --- |
| Suy luận lần đầu (cold) | 28,0 s | — |
| Suy luận khi L1 miss | 40,7 s | 40,9 s |
| **L1 hit** | **14 ms** | 21 ms |
| L2 `find_similar` | 1,3 ms | 3,9 ms |
| L3 tìm KB, miss | 0,14 ms | 0,23 ms |
| L3 tìm KB, hit | 0,02 ms | 0,03 ms |

Prompt khoảng 640 token, output khoảng 70 token, tỷ lệ hit L1 trong benchmark 5/10. RSS tăng khoảng 740 MB, phần lớn do nạp tokenizer GGUF.

Các lượt "warm" chậm hơn lượt đầu. `ai_client.generate` gán cứng `num_ctx: 8192` trong khi triage truyền 4096, nên Ollama có thể nạp lại context. Theo yêu cầu không đổi `num_ctx`, mục này được ghi lại để quyết định sau.

Tỷ lệ khớp nhầm ngữ nghĩa của L2 chưa đo được vì chưa có tập sự cố có nhãn đủ lớn. Các kiểm thử chỉ kiểm hành vi theo ngưỡng.
