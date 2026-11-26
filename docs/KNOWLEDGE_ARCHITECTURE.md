# Kiến trúc Knowledge Base

Knowledge Base (KB) cục bộ cung cấp tài liệu tham khảo có nguồn cho triage và Response Assist. **Kiến thức không phải bằng chứng.** Kết luận về một sự cố chỉ dựa trên evidence ID của chính sự cố đó. Tài liệu tham khảo được trích dẫn riêng bằng `chunk_id`.

## Nguồn

Lần đồng bộ ngày 26/11/2026 tạo ra `kb_version 226193840554…` với 278 chunk.

| `source_id` | Phiên bản | Giấy phép | Chunk |
| --- | --- | --- | --- |
| `mitre-attack` | ATT&CK v20.1 (STIX 2.1, `enterprise-attack-20.1.json`) | MITRE ATT&CK Terms of Use | 67 |
| `owasp-sqli-prevention` | git `9a91ba5a` | CC BY-SA 4.0 | 18 |
| `owasp-query-parameterization` | git `9a91ba5a` | CC BY-SA 4.0 | 17 |
| `owasp-os-command-injection` | git `6629957e` | CC BY-SA 4.0 | 18 |
| `nist-sp800-61r3` | SP 800-61 Rev. 3 (April 2025) | U.S. Government work | 59 |
| `larp-runbooks` | sha256 thư mục runbook | Nội bộ, đánh dấu `[INTERNAL]` | 99 |

MITRE gồm 23 kỹ thuật: T1190, T1046, T1110 (.001/.003/.004), T1059 (.004/.006), T1071 (.001), T1041, T1048, T1105, T1078, T1505.003, T1595 (.002), T1053.003, T1543.002, T1098.004, T1572 và T1021.004. Ngoài ra có DET0080 cùng các analytic AN0219–AN0225, và các detection strategy liên kết (chỉ analytic Linux). ATT&CK v20.1 không còn trường `x_mitre_detection`, nên phần phát hiện lấy từ detection strategy. Tên kỹ thuật trong runbook nội bộ được lấy từ dữ liệu STIX lúc build, không viết tay.

## Bố cục

```text
manager/knowledge/
  sources/sources.lock.json     URL, phiên bản, sha256 của bản tải về
  sources/raw/                  bản tải về (git-ignored)
  runbooks/*.md                 11 runbook nội bộ
  detection_patterns/*.yaml     thang mức bằng chứng (P3)
  response_playbooks/*.yaml     hành động theo mức (P6)
  chunks.jsonl                  KnowledgeChunk, mỗi dòng một chunk, tối đa 1200 ký tự
  knowledge_manifest.json       kb_version, nguồn, giấy phép, ngày đồng bộ
```

Mỗi runbook tách rõ các phần: chỉ báo quan sát, bằng chứng cần có, ánh xạ ATT&CK, giải thích khác, bước điều tra, phương án phản ứng, điều kiện thực thi, rủi ro vận hành và hướng dẫn rollback.

## Đồng bộ và tính toàn vẹn

```bash
cd manager
PYTHONPATH=.. .venv/bin/python scripts/sync_knowledge.py            # tải lại, kiểm sha256 theo lock
PYTHONPATH=.. .venv/bin/python scripts/sync_knowledge.py --offline  # build lại từ raw, không dùng mạng
```

Cùng một đầu vào cho ra `chunks.jsonl` giống hệt từng byte. `kb_version` là sha256 của các dòng đã sắp xếp. Lúc nạp, `kb_store` tính lại hash. Nếu hash lệch, một dòng sai schema hoặc thiếu tệp, KB được phục vụ rỗng, không bao giờ một phần. Khối code của OWASP được giữ nguyên nguyên văn.

## Truy xuất

`app/services/ai/knowledge/kb_store.py` dựng chỉ mục SQLite FTS5 trong bộ nhớ, xếp hạng bằng bm25, ở lần dùng đầu tiên. Không dùng vector database vì BM25 đủ cho 278 chunk tiếng Anh có thuật ngữ cố định.

- Truy vấn là dữ liệu không tin cậy: chỉ giữ tối đa 16 từ, mỗi từ được đặt trong ngoặc kép, toán tử FTS bị loại bỏ. Lỗi cú pháp FTS không bao giờ ném ra ngoài.
- `search(...)` trả tối đa 8 chunk. Prompt triage chỉ nhận tối đa 2 tham chiếu trong ngân sách 400 token, không bao giờ cả KB.
- Triage chọn tài liệu theo technique ID đã được ánh xạ và xác thực (`by_attack_id`), không theo văn bản của sự cố. Văn bản do kẻ tấn công kiểm soát (User-Agent, cmdline, path) không thể điều khiển việc chọn chunk.
- Truy vấn tự do xếp code mẫu theo ngôn ngữ của OWASP lên trên phần hướng dẫn. Vì vậy khuyến nghị tham số hóa trỏ cố định vào `owasp-sqli-prevention:primary-defenses:0` và `parameterized-queries:0`.

Runbook viết bằng tiếng Anh vì bộ stem porter chỉ hỗ trợ tiếng Anh. Phần giải thích hiển thị cho analyst là tiếng Việt và được sinh từ YAML pattern.

## Bằng chứng ↔ kiến thức (P3)

`pattern_engine.assess(...)` đặt bằng chứng lên một thang mức xác định:

| Mẫu | Mức | ATT&CK |
| --- | --- | --- |
| SQLi | L1 tool_indicator (chỉ User-Agent) → L2 probing (payload) → L3 exploitation_suspected (cấp phiên tương quan) → L4 exploitation_confirmed (sai thông tin đăng nhập vẫn được cấp phiên, xác minh phía ứng dụng) | T1190 từ L2, chỉ khi có evidence ref. L1 không ánh xạ. Không bao giờ T1110 hoặc T1218. |
| Automated HTTP | automation_indicator | Không |
| Authentication abuse | repeated_auth_failures → authentication_brute_force → brute_force_success | T1110 khi đạt tiêu chí brute force |
| Network scanning | inbound_port_contacts → service_scanning | T1046 |
| Reverse shell | suspicious_shell_socket → reverse_shell_confirmed | T1059.004 khi process, socket và FD liên kết |
| Web command injection | related_host_activity → web_server_spawned_shell | T1059 khi tiến trình cha là ứng dụng web, khớp PID và start time |

Ánh xạ không có evidence ref sẽ bị loại. Hoạt động host chỉ được đưa vào kết luận SQLi khi đã xác minh tương quan. Nếu chưa, nó được ghi là "liên quan, chưa tương quan".
