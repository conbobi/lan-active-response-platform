# LARP EDR — Kiểm thử chấp nhận AI Agent và chất lượng phát hiện

Ngày kiểm thử: 27/11/2026. Môi trường: Manager và Ollama chạy local (docker), model `sec-q5:latest`, Agent thật trên VPS `ip-172-31-32-238`.

Không có thao tác nào trên AWS. Không kích hoạt rule production. Không block, unblock, kill, isolate hay quarantine. Không chạy reverse shell.

## Cách đọc báo cáo

Mỗi kết quả ghi rõ nó đến từ đâu:

| Nhãn | Nghĩa |
|---|---|
| **LIVE-AI** | Gọi Ollama thật qua HTTP API của một Manager cô lập (pytest, SQLite riêng). Không mock model. |
| **LIVE-DB** | Đọc dữ liệu thật trong PostgreSQL của Manager local. Chỉ đọc, không ghi. |
| **DASHBOARD** | Ảnh chụp Dashboard thật. |
| **MOCK** | Test tất định, model được thay bằng câu trả lời cố định. Kiểm tra workflow backend, không đánh giá chất lượng model. |
| **BLOCKED** | Không thực hiện được; lý do ghi kèm. |

Bằng chứng nằm trong [docs/uat-evidence/](uat-evidence/):

- Các file `A.json`–`E.json` và `*.png` là **baseline trước khi sửa**. Chúng được chụp trên Dashboard thật bởi phiên kiểm thử trước, tài khoản `uat-admin2`.
- `after/A.json`–`after/E.json` là kết quả **LIVE-AI sau khi sửa**.
- `agent_b_result.json` chứa kết quả kiểm định Agent B của 10 rule; script tạo ra nó là `agent_b_uat.py`.

## Tóm tắt

| Tiêu chí chấp nhận | Kết quả | Căn cứ |
|---|---|---|
| AI nhận biết yêu cầu mơ hồ | ĐẠT (sau sửa) | LIVE-AI B, C: `NEEDS_CLARIFICATION`, nền tảng `null` |
| AI hỏi lại khi thực sự thiếu thông tin | ĐẠT | LIVE-AI A chỉ hỏi tiến trình cha; B, C hỏi hành vi và nền tảng |
| Admin không biết Sigma được hướng dẫn | ĐẠT một phần | Có giải thích và 3 lựa chọn bấm được; giải thích là văn bản cố định, không do AI sinh |
| Sigma đúng platform và logsource | ĐẠT | Bộ biên dịch cố định; E bị chặn khi mâu thuẫn |
| Rule chạy được trên runtime | ĐẠT (sau sửa) | Trước khi sửa: rule `sh + whoami` được tạo nhưng runtime không bao giờ khớp |
| Agent B kiểm định đúng dataset | ĐẠT, có giới hạn | Linux dùng dataset Linux, Windows dùng fixture Windows; mẫu tấn công đều là synthetic |
| Rule kém chất lượng bị từ chối | ĐẠT (sau sửa) | Trước khi sửa: rule "mọi /bin/sh", rule từ ngữ CTI, rule Windows chứa `/bin/sh` chỉ INCONCLUSIVE, và được kích hoạt sau 24 giờ |
| Rule kích hoạt phát hiện được sự kiện test | ĐẠT (integration cô lập) | Có test: monitor → activate → telemetry → incident có `rule_id`; mẫu benign không khớp |
| Cache phân biệt exact, semantic và miss | ĐẠT | Test + LIVE-DB: 12 EXACT, 2 SEMANTIC, 4 FRESH |
| AI suy luận trên evidence hiện tại | **CHƯA ĐẠT với incident reverse shell** | LIVE-DB: mọi incident chuỗi xâm nhập đều rơi về báo cáo tất định (`budget_exceeded` hoặc hết thời gian); chưa lần nào được model phân tích |
| AI không hallucinate host compromise | ĐẠT | Báo cáo chuỗi chỉ kết luận RCE, root, reverse shell khi có evidence; có test |
| Response đúng policy và khả năng Agent | ĐẠT | Test response và containment |
| Không tự thực thi containment | ĐẠT | Có test; không có thao tác thật nào trong đợt này |
| Giao diện phản ánh đúng backend | ĐẠT một phần | Đã sửa nhãn phân loại và nhãn nguồn `budget_exceeded`; **chưa kiểm thử lại trên Dashboard sau khi sửa** (BLOCKED) |

## 1–2. Bảng test và kết quả: AI Harvest hiểu yêu cầu

Đường đi: `POST /api/v1/rules/assistant`.

1. Model chỉ điền một *intent* nhỏ: tiến trình cha, tiến trình con, từ khóa lệnh, nền tảng.
2. Mọi giá trị model đưa ra phải xuất hiện trong lời người dùng; giá trị nào model tự đoán thì bị bỏ và hỏi lại.
3. Bộ biên dịch cố định sinh Sigma. **Model không viết YAML.**

| ID | Đầu vào | Kỳ vọng | Trước khi sửa (DASHBOARD/API baseline) | Sau khi sửa (LIVE-AI) | Kết quả |
|---|---|---|---|---|---|
| A | "Phát hiện web server Linux sinh tiến trình shell sau khi nhận request HTTP đáng ngờ." | Linux, process_creation, hỏi tiến trình cha, nói rõ giới hạn HTTP | Linux, `child=[shell]`, hỏi tiến trình cha; 5 giá trị model đoán bị loại | Như trước, cộng thông báo: "Sigma process_creation chỉ thấy tiến trình, không thấy request HTTP; việc nối request với tiến trình do Web Compromise Chain làm" | ĐẠT |
| B | "Tạo luật phát hiện hacker vào server." | Không tạo rule rộng; hỏi nền tảng và hành vi | **Tự gán `platform: linux`**, chỉ hỏi "tiến trình nào" | `NEEDS_CLARIFICATION`, `platform: null`; hỏi hành vi (3 lựa chọn), rồi nền tảng, tiến trình cha, tiến trình con | ĐẠT |
| C | "Tôi không biết Sigma là gì. Tôi muốn phát hiện ai đó chiếm quyền web server." | Giải thích Sigma, telemetry, báo nhầm; đề xuất lựa chọn | Tự gán Linux; không giải thích; không có lựa chọn | Giải thích Sigma (cần dữ liệu gì, khi nào báo nhầm) và 3 lựa chọn: *Web process sinh shell*, *Upload được thực thi*, *Web process kết nối outbound* | ĐẠT |
| D | "Phát hiện mọi hacker, kể cả khi không có log." | Nêu giới hạn, không hứa 100% | Tự gán Linux và mức `critical`, hỏi tiến trình | `INSUFFICIENT_TELEMETRY`, **không gọi model**; nói rõ không bộ phát hiện nào đạt 100%, cần bật telemetry và kiểm tra coverage | ĐẠT |
| E | "Tạo luật Windows để phát hiện /bin/sh chạy trên Linux." | Phát hiện mâu thuẫn, hỏi lại | **Âm thầm chọn Linux**, không cảnh báo (xem `E.png`) | `NEEDS_CLARIFICATION`: "Yêu cầu nhắc cả Windows và Linux"; hỏi nền tảng. Nếu chọn Windows: hỏi lại vì `sh` không phải tiến trình Windows | ĐẠT |
| CTI | "Built-in Web Server Spawning Shell report" (đường CTI) | Rule kém bị từ chối, báo lỗi đúng | Từ chối đúng sau 2 lần thử, nhưng trả **502 INTERNAL_ERROR** | Trả 422: "AI đã sinh rule nhưng rule không qua kiểm tra chất lượng nên không được lưu: …" | ĐẠT |

Hai lần chạy model thật cho cùng câu cho kết quả khác nhau ở các giá trị bị loại, ví dụ model lúc đoán `curl`, lúc đoán `wget`. Kết luận cuối không đổi, vì các giá trị đó đều bị lọc trước khi tới bộ biên dịch.

### Luồng hỏi lại có trạng thái thật (mục 3 của đề bài)

Một bản nháp dở dang đã có trong working tree khi tôi bắt đầu. Tôi rà lại, hoàn thiện và viết test cho nó. Luồng gồm:

- **Trạng thái ở backend.** Bảng `rule_conversations` lưu `owner`, `revision` và `state`. Migration là `c72d6e1f037a`.
- **Lưu và mở lại sau khi tải lại trang.** Gửi `resume: true` để lấy lại lượt cuối.
- **Revision lạc quan.** Gửi revision cũ thì nhận 409.
- **Câu trả lời phải khớp câu hỏi đang mở.** Trả lời một slot không được hỏi thì nhận 422.
- **Hội thoại là riêng tư.** Admin khác mở hội thoại thì nhận 404.
- **Rule được biên dịch từ trạng thái đã lưu.** Intent do trình duyệt gửi kèm khi tạo rule bị bỏ qua; có test chứng minh rằng gửi `windows/cmd.exe` vẫn tạo ra rule Linux đúng như hội thoại.

Bốn phân loại được trả về ở mỗi lượt:

| Phân loại | Quyết định bởi |
|---|---|
| `READY_TO_GENERATE` | Không còn câu hỏi và bộ biên dịch sinh được Sigma |
| `NEEDS_CLARIFICATION` | Còn câu hỏi, hoặc yêu cầu nhắc cả hai nền tảng |
| `UNSUPPORTED_REQUIREMENT` | Yêu cầu cần sự kiện DNS, registry, file hoặc mạng; hoặc người dùng chọn "Upload được thực thi" hay "kết nối outbound". Hai hành vi này cần ghép sự kiện file hoặc flow với tiến trình, đã có bộ phát hiện Web Compromise Chain làm, nên không ép thành Sigma. |
| `INSUFFICIENT_TELEMETRY` | Yêu cầu nói rõ là không có log hoặc telemetry |

Phân loại do quy tắc tất định quyết định, **không phải do model**. Model chỉ được gọi khi phân loại cho phép. Điều này đúng yêu cầu "không giả định model có khả năng hỏi lại chỉ vì prompt có câu ask user".

Nếu Admin không biết nền tảng, câu hỏi gợi ý nền tảng suy ra từ đường dẫn tiến trình mà Agent gửi trong 24 giờ qua, ví dụ: "Telemetry tiến trình 24 giờ qua chỉ có máy Linux; đây là gợi ý, cần bạn xác nhận". Hệ thống không tự chọn thay. Bảng `agents` không có trường hệ điều hành, nên đây là nguồn đã xác minh duy nhất.

## 3. Chất lượng Sigma rule

Mọi rule do Rule Assistant tạo đều đi qua `compile_rule`:

- một khối `selection`;
- modifier thuộc tập runtime hỗ trợ;
- field có trong telemetry Agent;
- MITRE gán theo bảng cố định khi người dùng không nêu.

Rule mẫu của kịch bản C sau khi chọn *Web process sinh shell → linux → vulnerable_web/app.py*:

```yaml
logsource: {category: process_creation, product: linux}
detection:
  selection:
    ParentCommandLine|contains: [vulnerable_web/app.py]
    Image|endswith: [/sh, /dash, /bash, /zsh]
  condition: selection
tags: [attack.t1059.004]
```

Trả lời năm câu hỏi đề bài yêu cầu cho rule này:

| Câu hỏi | Trả lời |
|---|---|
| Phát hiện điều gì? | Web app `vulnerable_web/app.py` sinh shell. |
| Dựa vào trường nào? | `ParentCommandLine`, `Image`. |
| Vì sao đáng ngờ? | Web app sinh shell là dấu hiệu thực thi lệnh từ request. |
| Khi nào báo nhầm? | Agent B đo được: endpoint `/ping` hợp lệ cũng chạy `/bin/sh -c ping …`, nên rule này **không đạt** (FPR 8,33%). Cần thêm điều kiện nối lệnh (xem C2 ở mục 5). |
| Agent có đủ dữ liệu không? | Có: Agent gửi tiến trình cha, `exe` và dòng lệnh. |

**Lỗi tìm thấy và đã sửa:** rule chạy được về cú pháp nhưng không bao giờ bắn.

- Runtime có chính sách *safe-process*: `sh`, `bash`, `python3`… bị bỏ qua nếu rule không nêu tiến trình cha, trừ khi dòng lệnh có payload reverse shell.
- Trước khi sửa, Rule Assistant vẫn coi rule `sh + whoami` (không có tiến trình cha) là đủ điều kiện và tạo nó.
- Đo bằng matcher dùng chung: rule đó khớp **0** lần với `sh -c whoami`, còn cùng rule có tiến trình cha thì khớp 1 lần.
- Sau khi sửa: trợ lý bắt buộc hỏi tiến trình cha và nêu lý do (chính sách safe-process).

## 4. Câu hỏi AI đã hỏi lại (LIVE-AI)

| Case | Câu hỏi, theo thứ tự |
|---|---|
| A | "Tiến trình cha (web server) cụ thể là gì? Chọn tiến trình Agent đang thấy hoặc gõ tên." |
| B | "Bạn muốn phát hiện hành vi nào trên máy chủ?" [3 lựa chọn] → "Rule áp dụng cho máy Linux hay Windows?" → tiến trình cha → tiến trình con |
| C | Như B, kèm giải thích Sigma |
| D | Không hỏi; giải thích giới hạn |
| E | "Rule áp dụng cho máy Linux hay Windows?" (nêu rõ mâu thuẫn). Chọn Linux thì hỏi tiến trình cha (safe-process); chọn Windows thì hỏi đổi tiến trình hoặc đổi nền tảng. |

Trong lab cô lập, danh sách gợi ý tiến trình cha rỗng vì không có telemetry. Trên DB thật, cũng hàm đó trả về `/opt/larp-agent/vulnerable_web/app.py` và `/opt/larp-agent/agent.py`. Việc gợi ý `agent.py` (chính Agent EDR) là không hữu ích; xem mục 14.

## 5. Agent B — kiểm định lịch sử

**Cách chọn dataset** (theo `validation_service.labelled_dataset`):

- **Rule Linux:** dùng `knowledge/validation/linux_process_v1.jsonl`, 45 bản ghi:
  - 9 mẫu tấn công `synthetic_lab_code`: các biến thể command injection và một mẫu reverse shell;
  - 24 mẫu benign lấy thật từ VPS (`lab_vps_snapshot`);
  - 12 mẫu benign synthetic, trong đó có hard negative: 3 lần `/ping` hợp lệ do web app chạy `sh`, phiên admin, cron, systemd, dpkg, lệnh thu thập của Agent.
- **Rule Windows:** fixture synthetic 20 dòng, được ghi nhãn là synthetic.
- **Nhãn (ground truth):** do người gán trong dataset. Không dùng `is_suspicious` hay output của detector.
- **So khớp:** `sigma_runtime.matching_events`, chung với Detection Engine, gồm cả chính sách safe-process. Có test `test_validator_and_runtime_agree_on_every_labelled_event`.
- **Công thức:**
  - Precision = TP/(TP+FP)
  - Recall = TP/(TP+FN)
  - FPR = FP/(FP+TN)
  - F1 = 2TP/(2TP+FP+FN), tương đương 2PR/(P+R)
  - Mẫu số bằng 0 thì giá trị là `null`, không coi là đạt.
- **Ngưỡng:** FPR ≤ 5%, Precision ≥ 95%, TP > 0. Ngưỡng **không thay đổi** trong đợt này.

Kết quả (`agent_b_result.json`, chạy trên 45 bản ghi):

| Rule | Verdict | TP | FP | FN | TN | Precision | Recall | FPR | F1 |
|---|---|---|---|---|---|---|---|---|---|
| C1: web app sinh shell, không điều kiện lệnh | FAILED | 9 | 3 | 0 | 33 | 0,75 | 1,00 | 0,083 | 0,857 |
| C2: web app sinh shell + nối lệnh | PASSED | 9 | 0 | 0 | 36 | 1,00 | 1,00 | 0,000 | 1,000 |
| E1: `sh` + `whoami`, không tiến trình cha | INCONCLUSIVE | 0 | 0 | 0 | 36 | – | – | 0,000 | – |
| X1: mọi `/bin/sh` (viết tay) | INCONCLUSIVE | 0 | 0 | 0 | 36 | – | – | 0,000 | – |
| X2: từ ngữ CTI "Adversaries", "exploit" | **FAILED** (lint) | – | – | – | – | – | – | – | – |
| X3: product windows + `/bin/sh` | **FAILED** (lint) | – | – | – | – | – | – | – | – |
| X4: field `TargetObject` không thu thập | UNSUPPORTED_BY_ENGINE | – | – | – | – | – | – | – | – |
| X5: modifier `base64offset` | UNSUPPORTED_BY_ENGINE | – | – | – | – | – | – | – | – |
| X6: `condition: selection and filter` | UNSUPPORTED_BY_ENGINE | – | – | – | – | – | – | – | – |

Ghi chú cho kết quả trên:

- **C1 và C2:** các FP của C1 chính là 3 hard negative `/ping`. Đây là ví dụ Agent B chặn đúng một rule kém, và chỉ ra đúng điều kiện còn thiếu.
- **E1, X1, X1b:** "INCONCLUSIVE, khớp 0/36" là kết quả *đúng với runtime*.
  - Trên Debian, `/bin/sh` là `/usr/bin/dash`, nên `Image|endswith: /sh` không bao giờ khớp.
  - Shell không có tiến trình cha thì bị safe-process loại.
  - Agent B giờ ghi rõ "Rule không khớp mẫu nào: kiểm tra điều kiện có xảy ra được trên telemetry thật". Rule Assistant thì không còn cho tạo E1.
- **Đã sửa ở Agent B:**
  1. Lint không cần dataset: từ chối product khác nền tảng của giá trị (X3), và rule chỉ khớp từ ngữ mô tả (X2). Trước khi sửa, cả hai chỉ INCONCLUSIVE, và sau 24 giờ giám sát thì cổng promotion cho phép kích hoạt.
  2. Khi không có mẫu tấn công tương ứng, vẫn đo FPR trên mẫu benign. Một rule ồn bị **FAILED** thay vì INCONCLUSIVE. Chế độ chỉ-benign không bao giờ cho PASSED. Có test: rule "con của agent.py" khớp ít nhất 4 mẫu benign và bị FAILED.
  3. Khi mọi mẫu tấn công là synthetic, kết quả kèm `dataset.limitations`: "không chứng minh rule sẵn sàng cho production".
- **Giới hạn còn lại:**
  - 9 mẫu tấn công là quá ít để ước lượng Recall có ý nghĩa thống kê.
  - Fixture Windows có một dòng `bash` của Linux.
  - Chưa có dataset nào cho rule không nhắm vào web shell.

## 6. Kích hoạt rule và phát hiện ở runtime

Kiểm chứng bằng integration test cô lập (`test_conversation_create_monitor_then_promote_and_detect`, model được MOCK chỉ ở bước trích intent):

1. Hội thoại → `/assistant/create` → rule ở trạng thái `monitoring`; confusion `{tp:9, fp:0, fn:0, tn:36}`.
2. Gửi telemetry qua `RuleEngine.evaluate` (đúng đường ingestion):
   - có 1 *monitor hit* cho `sh -c ping …;id`;
   - **không** có hit cho `sh -c ping 8.8.8.8`;
   - cùng tiến trình xuất hiện ở 2 snapshot vẫn chỉ tính 1 hit;
   - không tạo incident nào.
3. `POST /rules/{id}/activate` với RBAC admin. Trường `approved_by` ghi người phê duyệt.
4. Chạy lại: có 1 incident với `detection_evidence.rule_id` bằng rule đó.

Hai test khác chứng minh cổng kích hoạt:

- Rule INCONCLUSIVE chỉ kích hoạt được sau 24 giờ giám sát (`test_rule_without_labelled_data_is_promotable_only_after_monitoring`).
- Rule FAILED không kích hoạt được (`test_failed_rule_keeps_monitoring_but_cannot_be_promoted`).

Ba loại khớp được tách riêng:

| Loại | Nguồn |
|---|---|
| Sigma | `RuleCandidate`, `detection_evidence.rule_id` = UUID của rule |
| Process Chain Rule | `ProcessChainRule` |
| Web Compromise Chain | `RULE_ID = web_compromise_chain`, kèm điều kiện từng giai đoạn và `link` giải thích cách nối evidence |

Rule của đợt này **không được kích hoạt** trên Manager thật.

## 7. AI Threat Memory cache

Cache đã có trong source (`app/services/ai/threat_memory.py`). Test bao phủ:

| Tiêu chí | Test | Kết quả |
|---|---|---|
| Exact match khi khác incident, PID, IP, thời gian | `test_fingerprint_ignores_instance_values_and_is_deterministic`, `test_miss_calls_model_then_same_technique_with_other_ip_pid_is_an_exact_hit` | ĐẠT |
| Không sao chép evidence ID cũ | `rebind` gắn lại theo *vai trò*; `test_rebinding_requires_every_role_in_the_current_incident` | ĐẠT |
| Semantic chỉ là ngữ cảnh | `test_semantic_match_is_context_only`. Mẫu tương tự được đưa vào prompt với nhãn "Reference only (not evidence)" và model vẫn phân tích evidence hiện tại. | ĐẠT |
| Miss gọi model rồi mới lưu | `test_miss_calls_model…`, `test_timeout_and_invalid_output_are_not_stored` | ĐẠT |
| Vô hiệu: TTL, model/prompt, trạng thái, schema telemetry | `test_unusable_entries_are_not_reused`; hàm `usable()` kiểm tra cả `telemetry_schema_version` | ĐẠT |
| Vô hiệu khi rule thay đổi | `test_rule_change_invalidates_entries` | ĐẠT |
| Vô hiệu khi evidence thay đổi | Fingerprint đổi khi chuỗi leo thang (`test_escalating_chain_changes_the_fingerprint`) | ĐẠT |
| SOC đánh dấu sai | `test_analysis_source_view_and_mark_incorrect_revokes_the_entry`, `test_learning_never_overrides_a_soc_rejection` | ĐẠT |
| Không dùng approval hay kết quả thực thi đã cache | Template chỉ chứa phân loại, MITRE và vai trò evidence; playbook chỉ là *tên tham khảo*; `test_ai_and_cache_never_create_containment_actions` | ĐẠT |

**Benchmark trên dữ liệu thật** (LIVE-DB, bảng `threat_memory_events`, 38 lần quyết định ngày 27/11/2026):

| Quyết định | Số lần | Thời gian tra (ms, TB) | Tổng thời gian (trung vị) |
|---|---|---|---|
| EXACT_CACHE | 12 | 17,5 | **60 ms** |
| FRESH_LLM | 4 | 13 | khoảng 93 s (LLM khoảng 82–96 s) |
| SEMANTIC_ASSISTED | 2 | 8 | khoảng 92 s |
| RULE_BASED_FALLBACK | 20 | 40 | khoảng 115 s (hết thời gian), hoặc vài chục ms (`budget_exceeded`) |

Tỉ lệ exact hit là 12/38 (32%). Mỗi lần hit tiết kiệm khoảng 90 giây CPU của model. Toàn bộ 5 mục memory thuộc incident HTTP hoặc xác thực, có `platform: unknown`, vì `platform_of` chỉ suy nền tảng từ tiến trình (xem mục 14).

## 8. AI giám sát và suy luận sâu

Hai chuỗi tương quan được xây bằng mã tất định, không dùng LLM:

- **Web Compromise Chain:** auth bypass → upload → command injection → web sinh shell → thực thi file → kết nối outbound → root.
- **Episode theo PID web:** hai lần khai thác cùng một tiến trình web là hai incident riêng.

Risk score chỉ đến từ rule (`test_score_comes_only_from_the_rule`). Có test chứng minh:

- curl đơn lẻ không được leo thang;
- upload mà không có thực thi chưa phải RCE;
- `/ping` hợp lệ không phải một giai đoạn tấn công;
- kết nối của tiến trình không liên quan không bị gán vào chuỗi.

**Đánh giá trên incident thật `inc_a72de6e000dc`** (reverse shell tới `100.67.222.3:4444` lúc 14:13 ngày 27/11):

| Thước đo | Đánh giá |
|---|---|
| Evidence coverage | Đủ: 9 tiến trình (PID, cha, euid, thời điểm), file `/tmp/uploads/backdoor.py`, socket gắn stdin/stdout xác minh qua inode |
| Causal consistency | Đúng: web (P1) → `sh -c ping …;python3 backdoor.py` (P2) → python (P4) giữ socket → bash (P5) → `whoami`, `ls` |
| Temporal consistency | Đúng; các mốc giờ theo GMT+7 |
| Unsupported claims | 0. "Root" có euid 0; "reverse shell" có socket gắn stdio; "Tên file không phải căn cứ kết luận độc hại" |
| Missed evidence | **1, đã sửa:** báo cáo ghi "Command injection: chưa có bằng chứng" dù P2 có ký tự nối lệnh. Giờ báo cáo ghi: chưa có request HTTP mang chỉ báo injection, nhưng dòng lệnh shell [P2] phù hợp command injection. Điểm rủi ro không đổi, để tránh tính trùng với giai đoạn "web sinh shell". |
| Uncertainty | Đúng: các request `/ping` được ghi là *Suy luận*, kèm lý do không xác nhận được (web app chưa gửi PID tiến trình con) |
| Recommendation relevance | Đúng: dừng PID 223363 (xác minh PID và thời điểm khởi chạy), cách ly file sau khi lấy SHA-256, cần SOC Admin phê duyệt |

**Phát hiện quan trọng (chưa sửa):** phân tích trên **không phải do AI**. Cả 5 lần triage incident chuỗi (3 incident) đều kết thúc RULE_BASED_FALLBACK:

- Có lần `budget_exceeded`: prompt giới hạn 10 bản ghi tiến trình và một ngân sách token; mỗi lệnh kẻ tấn công gõ trong reverse shell lại thêm một tiến trình bắt buộc.
- Có lần hết thời gian sau khoảng 115 s.

Trước khi sửa, dòng "Nguồn" hiện `budget_exceeded` thô kèm "Độ tin cậy 90%", nên người đọc dễ tưởng AI đã phân tích. Đã sửa thành: "Bằng chứng vượt giới hạn ngữ cảnh của mô hình nên không gửi cho AI — … KHÔNG phải phân tích AI".

## 9. AI đề xuất phản ứng

| Kỳ vọng | Có trong hệ thống? | Căn cứ |
|---|---|---|
| Hỏi đáp tự do: "Tôi phát hiện có shell đáng ngờ… không biết xử lý thế nào" | **Không**. Không có endpoint chat tự do; tư vấn gắn với từng incident. | Rà source |
| Giải thích tình trạng, ưu tiên điều tra và thu thập evidence | Có, trong báo cáo incident (mục 8) | LIVE-DB `inc_a72de6e000dc` |
| Kill tiến trình chỉ khi xác minh PID và thời điểm khởi chạy | Có | `test_verified_process_stop_uses_current_parent_and_reports_failures` |
| Quarantine sau khi xác minh, có rollback | Có | `test_inspect_then_quarantine_with_approval_then_restore` |
| Không block IP chỉ vì curl hay công cụ | Có | `test_tool_indicator_plan_investigates_and_never_blocks` |
| Không quarantine chỉ vì tên file | Có | Báo cáo ghi rõ; quarantine cần approval và evidence |
| Không thực thi khi Agent offline hoặc thiếu khả năng | Có | `test_offline_agent_and_missing_capability_never_produce_success` |
| Approval của incident cũ không dùng cho incident mới | Có (bằng chứng đổi thì approval mất hiệu lực) | `test_changed_evidence_invalidates_approval`, `test_historical_incident_is_read_only_for_enforcement` |
| LLM không tạo lệnh shell tùy ý | Có: hành động thuộc danh sách cố định `SUPPORTED_ACTIONS`; chống prompt injection | `test_prompt_injection_in_user_agent_does_not_change_plan` |

Kết luận: ĐẠT một phần. Mọi ràng buộc an toàn đều đạt; còn thiếu kênh hỏi đáp tự do cho Admin chưa có kinh nghiệm.

## 10. Kiểm thử trên Dashboard thật

**BLOCKED cho phần sau khi sửa.**

- Không có Playwright trong môi trường. Có Google Chrome nhưng không có thư viện điều khiển.
- Quan trọng hơn: tôi không có thông tin đăng nhập. Việc tự tạo token admin trong container đã bị chặn, và **tôi không vượt qua chặn đó**.
- Ảnh baseline trước khi sửa (`A.png`–`E.png`, `CTI.png`) là ảnh Dashboard thật do phiên trước chụp.
- Frontend đã được rebuild (local). Route mới trả 401 khi không đăng nhập (qua nginx).

## 11. Thuật toán và kiến trúc

| | Thuật toán | Input → Output | Logic chính | Độ phức tạp | Trong source? | Có test? |
|---|---|---|---|---|---|---|
| A | Deterministic threat fingerprinting | Incident + context → SHA-256 | Băm JSON chuẩn hoá: rule, phiên bản, vai trò evidence, đặc trưng hành vi, nền tảng, phiên bản schema; bỏ ID, PID, IP, thời gian | O(n) theo số evidence | Có | Có |
| B | Exact-cache matching | Fingerprint → mục memory | Truy vấn có chỉ mục `fingerprint =`, rồi `usable()`, rồi gắn lại vai trò (mỗi vai trò đúng một evidence) | O(log N) + O(n) | Có | Có |
| C | Semantic similarity retrieval | Token đặc trưng → top-3 | Jaccard \|A∩B\|/\|A∪B\| ≥ 0,25, cùng nền tảng, model và prompt, tối đa 500 ứng viên; chỉ làm ngữ cảnh | O(k·t) | Có | Có |
| D | Behavioral correlation graph | Tiến trình, flow, sự kiện app → chuỗi | Cây cha–con theo (PID, thời điểm khởi chạy); socket gắn qua inode; request gắn qua `child_pid` ±3 s | O(P log P + E) | Có | Có |
| E | Temporal event correlation | Chuỗi → episode | Tách episode theo PID web, khoảng nghỉ 600 s; cửa sổ 60 phút | O(E log E) | Có | Có |
| F | Rule-based risk scoring | Giai đoạn → điểm | Cộng trọng số cố định theo giai đoạn; LLM không sửa điểm | O(S) | Có | Có |
| G | Evidence-grounded AI reasoning | Context → verdict | Model trả JSON theo schema; ID evidence phải nằm trong prompt; MITRE thuộc danh sách cho phép; vượt ngân sách hoặc lỗi thì dùng báo cáo tất định | – | Có | Có. **Thực tế chưa chạy được cho incident chuỗi** (mục 8). |
| H | Response policy evaluation | Verdict + khả năng Agent → đề xuất | Danh sách hành động cố định, điều kiện evidence, approval gắn phiên bản evidence | – | Có | Có |
| I | Cache invalidation | Mục memory → dùng được hay không | TTL 14 ngày, trạng thái, phiên bản fingerprint, schema, model và prompt, playbook; rule đổi; SOC thu hồi | O(1) | Có | Có |
| J | Detection feedback loop | Monitor hit, kết quả kiểm định → promotion | Giám sát ≥ 24 giờ hoặc PASSED, admin kích hoạt; SOC đánh dấu sai thì thu hồi memory. **Chưa có:** đưa FP thực tế trở lại dataset của Agent B. | – | Một phần | Một phần |

## 12. Nguyên nhân gốc

Theo mức ảnh hưởng:

1. **[Cao, chưa sửa]** Incident chuỗi xâm nhập không bao giờ được LLM phân tích.
   - Prompt giới hạn 10 tiến trình bắt buộc và một ngân sách token.
   - Reverse shell càng chạy lệnh thì càng sinh thêm tiến trình bắt buộc.
   - Các lần còn lại hết thời gian khoảng 115 s, vì model chạy CPU mất 80–100 s mỗi lần và `OLLAMA_NUM_PARALLEL=1`.
2. **[Cao, đã sửa]** Rule Assistant tạo rule mà runtime không bao giờ bắn (shell hoặc interpreter không có tiến trình cha, bị safe-process loại).
3. **[Cao, đã sửa]** Agent B không từ chối rule sai nền tảng hoặc chỉ khớp từ ngữ CTI. Chúng thành INCONCLUSIVE và kích hoạt được sau 24 giờ.
4. **[Trung bình, đã sửa]** Yêu cầu mơ hồ hoặc mâu thuẫn được model tự gán nền tảng (B, C, D, E).
5. **[Trung bình, đã sửa]** Không có trạng thái hội thoại ở backend. Bản nháp có sẵn đã được hoàn thiện và kiểm thử.
6. **[Trung bình, đã sửa]** Báo cáo chuỗi ghi "Command injection: chưa có bằng chứng" dù dòng lệnh shell có dấu nối lệnh; nhãn `budget_exceeded` không nói rõ đó không phải AI.
7. **[Thấp, đã sửa]** CTI Harvest trả 502 INTERNAL_ERROR khi rule do model sinh bị từ chối vì chất lượng.
8. **[Thấp, chưa sửa]** Không có kênh hỏi đáp tự do về ứng phó (mục 9).
9. **[Thấp, chưa sửa]** Threat Memory ghi `platform: unknown` cho incident HTTP và xác thực.
10. **[Thấp, chưa sửa]** Danh sách gợi ý tiến trình cha có cả `agent.py` của chính Agent.

## 13. File thay đổi

**Backend:**

- `manager/app/services/ai/rule_assistant.py`
  - Phân loại yêu cầu: `request_constraints`, `SCENARIOS`, `scenario_question`, `apply_scenario`.
  - Gợi ý nền tảng từ telemetry.
  - Phát hiện tiến trình sai nền tảng (`_foreign_children`).
  - Bắt buộc tiến trình cha khi runtime sẽ bỏ qua (`_runtime_ignored`).
- `manager/app/api/routes/rules.py`
  - Lượt hội thoại có trạng thái (hoàn thiện bản nháp).
  - Gọi model cả khi mâu thuẫn nền tảng (để không mất `/bin/sh`).
  - Trả 422 khi rule do AI sinh bị từ chối vì chất lượng.
- `manager/app/models/rule_conversation.py`, `manager/alembic/versions/c72d6e1f037a_rule_conversations.py`, `manager/app/models/__init__.py` (đăng ký model).
- `manager/app/services/ai/validation_service.py`: `quality_problems`; đo FPR chỉ-benign; `dataset.limitations`; công thức F1 khi mẫu số bằng 0.
- `manager/app/services/ai/threat_memory.py`: tra exact bằng truy vấn có chỉ mục thay cho lọc 500 dòng trong Python; lọc ứng viên semantic trong SQL. Đây là thay đổi của bản nháp có sẵn, tôi đã rà lại.
- `manager/app/services/ai/chain_report.py`: nhãn `budget_exceeded`; ghi chú command injection lấy từ dòng lệnh shell.

**Frontend:**

- `frontend/src/components/ai/RuleAssistant.jsx`: hội thoại lưu và mở lại; nút "Yêu cầu mới"; nhãn phân loại tiếng Việt có màu kèm mã gốc.

**Test:**

- Mới: `manager/app/test/test_harvest_clarification.py`.
- Sửa: `test_rule_assistant.py`, `test_sigma_web_shell_e2e.py`, `test_containment.py`.

**Bằng chứng:** `docs/uat-evidence/after/*.json`, `docs/uat-evidence/agent_b_result.json`, `docs/uat-evidence/agent_b_uat.py`.

## 14. Kết quả test

| Bộ | Kết quả | Loại |
|---|---|---|
| `test_harvest_clarification.py` (tất định) | 7 passed | MOCK model, DB cô lập |
| `test_harvest_clarification.py::test_real_model_uat` A–E | **5 passed** (169 s) | LIVE-AI, DB cô lập |
| `test_rule_assistant.py` | 8 passed, 2 skipped (test model thật cũ, opt-in) | MOCK |
| `test_sigma_web_shell_e2e.py` | 20 passed, 2 skipped | MOCK + dataset thật |
| `test_containment.py` | 9 passed | Integration cô lập |
| Toàn bộ Manager | Không có lỗi mới. Còn đúng 5 lỗi đã có từ trước (`test_auth_evidence_pipeline` ×2, `test_reconnect_watchdog`, `test_risk_rules` 20≠19, `test_process_tree_improved`), cùng danh sách với baseline `94aff22` đo ở phiên trước | Container: 542 passed. Các file cần đường dẫn host chạy lại trên host: 87 + 29 + 9 passed |

Không chạy lại test Agent vì đợt này không sửa mã Agent.

Ghi chú về môi trường chạy test:

- Trong container, một số file test lỗi vì thiếu Flask, thiếu `docker-compose.yml`, hoặc đường dẫn `/agent`.
- Trên host, thư mục rỗng `manager/agent` (điểm mount Docker) che mất package `agent`.
- Vì vậy bộ test được chia: phần lớn chạy trong container, các file cần đường dẫn host chạy trên host.

## 15. Chưa được xác minh trên thực tế

- Dashboard sau khi sửa (mục 10): cần đăng nhập để thao tác lại.
- Luồng tạo rule → kích hoạt → incident trên **Manager thật**: chỉ chạy trong integration cô lập, theo đúng ràng buộc "không tự activate rule production".
- Toàn bộ pipeline với model thật từ lượt đầu đến khi rule được kích hoạt: model thật chỉ tham gia lượt đầu (A–E); các lượt sau không gọi model theo thiết kế.
- LLM phân tích một incident reverse shell: chưa có lần nào thành công (mục 8).
- Kênh hỏi đáp ứng phó tự do: chưa có.

## 16. Đề xuất tiếp theo

1. **Gọn ngữ cảnh chuỗi cho model.** Gộp các lệnh con của shell tương tác (`whoami`, `ls`…) thành một bản ghi tóm tắt có ID. Tiến trình bắt buộc khi đó chỉ còn: web, shell, payload, holder socket. Đặt thời gian chờ triage theo đo đạc (hiện 80–100 s mỗi lần trên CPU).
2. **Mở rộng dataset Agent B.** Thêm mẫu tấn công thật từ lab (đã có chuỗi `ping;python3 backdoor.py` thật), và mẫu cho rule không phải web shell. Báo khoảng tin cậy cho Recall.
3. **Đưa FP thực tế vào vòng phản hồi.** Monitor hit được SOC gắn nhãn sẽ trở thành mẫu benign có nhãn.
4. **Thêm kênh "Hỏi AI về incident này".** Trả lời tự do nhưng chỉ dựa trên evidence của incident đang mở, và chỉ đề xuất hành động thuộc danh sách policy.
5. **Bỏ chính Agent EDR khỏi danh sách gợi ý tiến trình cha.** Ghi nền tảng của incident HTTP theo Agent nguồn.

## Hướng dẫn thao tác lại trên Dashboard

1. Đăng nhập Dashboard local bằng tài khoản admin. Vào **AI Rule Harvest** → **Trợ lý tạo rule (ngôn ngữ tự nhiên)**.
2. Lần lượt gõ các câu A–E ở mục 1. Mỗi câu bấm **Yêu cầu mới** trước. Kỳ vọng:
   - **B:** dòng trạng thái vàng "Cần bạn trả lời thêm…" (`NEEDS_CLARIFICATION`), 3 nút lựa chọn hành vi.
   - **D:** dòng đỏ "Thiếu nguồn dữ liệu…", không có câu hỏi, không có rule.
   - **E:** hỏi Linux hay Windows. Chọn **windows**: hỏi lại vì `sh` không phải tiến trình Windows. Chọn **linux**: hỏi tiến trình cha (nêu chính sách safe-process).
3. Với C: chọn **Web process sinh shell** → **linux** → `vulnerable_web/app.py`. Rule xuất hiện. Nhấn F5: hội thoại được mở lại.
4. Chỉ khi muốn thử kiểm định: bấm **Tạo rule & bắt đầu giám sát**. Rule ở chế độ *monitoring*, không tạo incident. Kỳ vọng Agent B **không đạt** (FP ở 3 mẫu `/ping`). Muốn có rule đạt thì tích **Nối lệnh** rồi **Cập nhật & kiểm tra**. Không bấm kích hoạt trên Manager thật nếu chưa quyết định.
