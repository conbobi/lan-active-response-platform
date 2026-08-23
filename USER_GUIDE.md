# HƯỚNG DẪN SỬ DỤNG HỆ THỐNG LAN ACTIVE RESPONSE MANAGER (LARP)

Chào mừng bạn đến với **LAN Active Response Platform (LARP)** – Hệ thống giám sát, phân tích rủi ro an ninh mạng và tự động phản ứng sự cố cho mạng nội bộ. Document này sẽ hướng dẫn chi tiết cách vận hành từng chức năng trên giao diện quản trị dành cho nhân viên vận hành và chuyên viên an ninh mạng.

---

## 📑 MỤC LỤC
1. [Dashboard (Bảng Điều Khiển Tổng Quan)](#1-dashboard-bảng-điều-khiển-tổng-quan)
2. [Agents (Quản Lý Thiết Bị / Máy Trạm)](#2-agents-quản-lý-thiết-bị--máy-trạm)
3. [Alerts (Cảnh Báo An Ninh)](#3-alerts-cảnh-báo-an-ninh)
4. [Network (Sơ Đồ Mạng 3D & Điều Phối Băng Thông)](#4-network-sơ-đồ-mạng-3d--điều-phối-băng-thông)
5. [Incidents (Quản Lý Sự Cố An Ninh Mạng)](#5-incidents-quản-lý-sự-cố-an-ninh-mạng)
6. [Commands (Nhật Ký & Phát Lệnh Phản Ứng)](#6-commands-nhật-ký--phát-lệnh-phản-ứng)
7. [Risk Assessment (Đánh Giá Rủi Ro Telemetry)](#7-risk-assessment-đánh-giá-rủi-ro-telemetry)
8. [Detection Rules (Quản Lý 13 Quy Tắc Phát Hiện)](#8-detection-rules-quản-lý-13-quy-tắc-phát-hiện)
9. [Threat Intelligence (Tra Cứu Chỉ Báo Đe Dọa)](#9-threat-intelligence-tra-cứu-chỉ-báo-đe-dọa)
10. [Process Tree (Cây Tiến Trình & Gốc Rễ Mối Đe Dọa)](#10-process-tree-cây-tiến-trình--gốc-rễ-mối-đe-dọa)
11. [Reports (Xuất Báo Cáo Định Kỳ)](#11-reports-xuất-báo-cáo-định-kỳ)
12. [Whitelist (Danh Sách Trắng An Toàn)](#12-whitelist-danh-sách-trắng-an-toàn)
13. [Notifications (Cấu Hình Kênh Thông Báo)](#13-notifications-cấu-hình-kênh-thông-báo)
14. [Rules Engine (Quy Tắc Giám Sát Lượng Truy Cập)](#14-rules-engine-quy-tắc-giám-sát-lượng-truy-cập)
15. [Attack Sim (Mô Phỏng Tấn Công Mạng)](#15-attack-sim-mô-phỏng-tấn-công-mạng)
16. [Settings (Cấu Hình Hệ Thống & Ngưỡng Rủi Ro)](#16-settings-cấu-hình-hệ-thống--ngưỡng-rủi-ro)

---

## 1. Dashboard (Bảng Điều Khiển Tổng Quan)

### 🎯 Mục đích
Cung cấp cái nhìn toàn cảnh thời gian thực về sức khỏe hệ thống mạng nội bộ, số lượng thiết bị đang hoạt động, điểm số rủi ro trung bình, biểu đồ lưu lượng mạng và các cảnh báo mới nhất.

### 🛠️ Hướng dẫn thao tác
1. **Xem chỉ số KPI nhanh**: Ở hàng đầu tiên, theo dõi 4 thẻ:
   - *Online Agents*: Số lượng máy trạm/thiết bị đang hoạt động.
   - *Alerts Today*: Số cảnh báo phát sinh trong ngày.
   - *Average Risk Score*: Điểm rủi ro trung bình của toàn hệ thống (0 - 100).
   - *Blocked IPs*: Số lượng IP bị ngăn chặn tự động.
2. **Quan sát lưu lượng mạng**: Theo dõi biểu đồ *Network Traffic* để nhận diện biến động lưu lượng bất thường (gói SYN/s, UDP/s).
3. **Theo dõi trạng thái Live WebSocket**: Nhãn `LIVE WS` góc trên bên phải báo hiệu kết nối dữ liệu trực tiếp với máy chủ đang sẵn sàng.
4. **Xem chi tiết máy trạm**: Nhấp vào dòng bất kỳ trong bảng *Agent Table* để mở modal xem thông tin CPU, RAM, Disk và IP của máy trạm đó.

### ⚠️ Lưu ý
- Nếu nhãn hiển thị `OFFLINE`, dữ liệu trên trang sẽ tự động cập nhật qua định kỳ thay vì theo thời gian thực. Hãy kiểm tra kết nối mạng hoặc máy chủ backend.

---

## 2. Agents (Quản Lý Thiết Bị / Máy Trạm)

### 🎯 Mục đích
Quản lý tập trung toàn bộ máy trạm/server có cài đặt LARP Agent trong mạng LAN, cho phép cô lập mạng (isolate) ngay lập tức khi phát hiện máy bị nhiễm mã độc hoặc khôi phục kết nối (unisolate).

### 🛠️ Hướng dẫn thao tác
1. **Tìm kiếm & Lọc**: Sử dụng ô tìm kiếm hoặc thanh lọc theo trạng thái (`Online`, `Offline`, `Isolated`) để tra cứu máy trạm theo tên hoặc IP.
2. **Cách Cô Lập Máy Trạm (Isolate)**:
   - Nhấp nút **Isolate** tại dòng tương ứng với máy trạm nghi ngờ.
   - Hệ thống sẽ kích hoạt eBPF/Firewall trên agent để ngắt kết nối mạng của máy đó, ngăn chặn mã độc lây lan sang các máy khác trong LAN.
3. **Cách Khôi Phục Kết Nối (Unisolate)**:
   - Nhấp nút **Unisolate** để mở lại kết nối mạng cho máy trạm sau khi đã xử lý xong sự cố.

### ⚠️ Lưu ý
- Khi một máy trạm bị **Isolate**, máy đó sẽ bị ngắt lưu lượng mạng với bên ngoài nhưng vẫn giữ kết nối điều khiển an toàn với máy chủ LARP Manager.

---

## 3. Alerts (Cảnh Báo An Ninh)

### 🎯 Mục đích
Tổng hợp và hiển thị danh sách các sự kiện bất thường, dấu hiệu tấn công hoặc nguy cơ mất an toàn thông tin được ghi nhận từ các agent.

### 🛠️ Hướng dẫn thao tác
1. **Lọc cảnh báo**: Chọn tab tương ứng (`All`, `Critical`, `High`, `Medium`, `Low`) để xem sự kiện theo mức độ nghiêm trọng.
2. **Tìm kiếm sự kiện**: Nhập tên tiến trình, IP hoặc loại sự kiện vào ô tìm kiếm.
3. **Xem chi tiết**: Nhấp vào một cảnh báo để xem thông số chi tiết (Thời gian, Agent gửi về, Mức rủi ro Risk Score, và hành động gợi ý).

### ⚠️ Lưu ý
- Các cảnh báo mức **Critical** (Màu đỏ) cần được ưu tiên xử lý ngay lập tức để tránh nguy cơ Ransomware mã hóa dữ liệu hàng loạt.

---

## 4. Network (Sơ Đồ Mạng 3D & Điều Phối Băng Thông)

### 🎯 Mục đích
Trực quan hóa toàn bộ mô hình kết nối mạng LAN dưới dạng mô hình 3D tương tác. Cho phép tìm đường đi ngắn nhất (Dijkstra) có xét yêu cầu băng thông và mô phỏng sự cố đứt tuyến cáp/kết nối.

### 🛠️ Hướng dẫn thao tác
1. **Thao tác với không gian 3D**:
   - **Xoay**: Giữ chuột trái và di chuyển.
   - **Phóng to/Thu nhỏ**: Xoay con trỏ chuột.
   - **Di chuyển**: Giữ chuột phải và kéo.
2. **Tìm Đường Đi Tối Ưu (Find Path)**:
   - Chọn nút nguồn (Source Agent) và nút đích (Destination Agent).
   - Nhập số **Bandwidth (Mbps)** yêu cầu (ví dụ: 100 Mbps).
   - Nhấp nút **Find Optimal Path**. Đường đi ngắn nhất và đủ băng thông sẽ sáng lên màu vàng trên không gian 3D.
3. **Giải Phóng Đường Đi (Release Path)**:
   - Khi không còn nhu cầu duy trì luồng ưu tiên, nhấp nút **Release Path** trên thanh công cụ để hoàn trả băng thông đã cấp phát.
4. **Mô Phỏng Sự Cố Kết Nối (Simulate Link Failure)**:
   - Nhấp trực tiếp vào một đường liên kết (Link) giữa 2 nút trên đồ thị 3D để ngắt kết nối đó. Hệ thống sẽ tự động tính toán lại đường đi vòng thay thế.

### ⚠️ Lưu ý
- Nếu băng thông yêu cầu vượt quá dung lượng còn lại của các liên kết, hệ thống sẽ thông báo không tìm thấy đường đi thỏa mãn.

---

## 5. Incidents (Quản Lý Sự Cố An Ninh Mạng)

### 🎯 Mục đích
Theo dõi vòng đời xử lý sự cố an ninh (Incident Response Lifecycle), phân công chuyên viên phân tích (Analyst) và đánh dấu hoàn tất giải quyết sự cố.

### 🛠️ Hướng dẫn thao tác
1. **Phân công xử lý (Assign Incident)**:
   - Nhấp nút **Assign** tại sự cố đang ở trạng thái `Open`.
   - Nhập tên hoặc ID của chuyên viên an ninh đảm nhận và nhấn **Confirm Assign**.
2. **Giải quyết sự cố (Resolve Incident)**:
   - Sau khi kiểm tra và khắc phục xong mối đe dọa, nhấp nút **Resolve** để đóng sự cố. Trạng thái sự cố sẽ chuyển sang `Resolved`.

### ⚠️ Lưu ý
- Tất cả các sự cố ở trạng thái `Open` cần được phân công người theo dõi trong vòng 15 phút từ khi phát sinh.

---

## 6. Commands (Nhật Ký & Phát Lệnh Phản Ứng)

### 🎯 Mục đích
Cho phép quản trị viên phát lệnh điều khiển trực tiếp (Active Response Commands) tới các agent và theo dõi nhật ký thực thi lệnh trong hệ thống.

### 🛠️ Hướng dẫn thao tác
1. **Phát lệnh mới (Dispatch Command)**:
   - Nhấp nút **Dispatch Command** ở góc trên bên phải.
   - Chọn **Target Agent** (chọn 1 máy cụ thể hoặc `ALL AGENTS`).
   - Chọn loại lệnh: `isolate_agent`, `unisolate_agent`, `update_firewall_rule`, `collect_sys_logs`, `execute_script`.
   - Nhập tham số JSON (nếu có) và nhấn **Dispatch Command**.
2. **Gửi lại lệnh bị lỗi (Retry Command)**:
   - Nếu một lệnh hiển thị trạng thái `FAILED`, nhấp nút **Retry** để máy chủ gửi lại lệnh đến agent.

### ⚠️ Lưu ý
- Việc phát lệnh đến `ALL AGENTS` (Broadcast) có thể ảnh hưởng đến toàn bộ mạng LAN, hãy kiểm tra kỹ tham số trước khi gửi.

---

## 7. Risk Assessment (Đánh Giá Rủi Ro Telemetry)

### 🎯 Mục đích
Đánh giá mức độ độc hại của máy trạm dựa trên 13 quy tắc phân tích hành vi (Telemetry Analysis). Hệ thống tính toán điểm số Risk Score (0-100) và liệt kê các nhân tố rủi ro.

### 🛠️ Hướng dẫn thao tác
1. **Thử nghiệm nhanh với Kịch Bản Mẫu (Presets)**:
   - Nhấp vào một trong các nút mẫu: **Ransomware Burst** (Tấn công mã hóa), **Privilege Escalation** (Leo thang đặc quyền), hoặc **Normal Telemetry** (Hoạt động bình thường). Form nhập liệu sẽ tự động điền các chỉ số tương ứng.
2. **Nhập dữ liệu thủ công**:
   - Chọn máy trạm cần đánh giá (`Target Agent`).
   - Tùy chỉnh mức CPU, số lượng tệp thay đổi.
   - Đánh dấu các hành vi nghi vấn (Xóa Shadow Copy, Lệnh nghi vấn, Sửa Registry, Dump Credential,...).
3. **Xem kết quả**:
   - Nhấp **Evaluate Risk Score**. Đồng hồ rủi ro sẽ hiển thị điểm số tổng hợp và danh sách các **Triggered Risk Factors** đóng góp vào điểm số đó.

### ⚠️ Lưu ý
- Điểm rủi ro **>= 85** sẽ kích hoạt chính sách tự động cô lập máy trạm nếu chế độ Auto-Response đang bật trong Settings.

---

## 8. Detection Rules (Quản Lý 13 Quy Tắc Phát Hiện)

### 🎯 Mục đích
Cho phép quản trị viên cấu hình bật/tắt và điều chỉnh trọng số điểm số (Weight) của 13 quy tắc phát hiện mối đe dọa cố định trong LARP Engine.

### 🛠️ Hướng dẫn thao tác
1. **Bật/Tắt quy tắc**:
   - Gạt công tắc ở cột **Status** để kích hoạt hoặc tạm dừng một quy tắc phát hiện.
2. **Đổi trọng số điểm (Risk Weight)**:
   - Thay đổi giá trị trong ô **Risk Weight** (ví dụ: đổi từ 25pt lên 40pt đối với quy tắc Ransomware). Hệ thống sẽ tự động lưu lại.
3. **Thêm / Chỉnh sửa quy tắc**:
   - Nhấp nút **Add Detection Rule** hoặc biểu tượng **Edit** để cập nhật tên, mô tả và cấu hình JSON của quy tắc.

### ⚠️ Lưu ý
- Việc tăng trọng số của một quy tắc sẽ làm cho điểm rủi ro tổng hợp của máy trạm tăng nhanh hơn khi quy tắc đó bị vi phạm.

---

## 9. Threat Intelligence (Tra Cứu Chỉ Báo Đe Dọa)

### 🎯 Mục đích
Tra cứu thông tin tình báo an ninh mạng (Cyber Threat Intelligence) cho một địa chỉ IP, tên miền (Domain), mã băm tệp (File Hash MD5/SHA256) hoặc URL.

### 🛠️ Hướng dẫn thao tác
1. Chọn **Indicator Type** (IP, Domain, Hash, URL).
2. Nhập giá trị cần kiểm tra vào ô **Indicator Value** (hoặc nhấp các nút thử nhanh như *Malicious C2 IP*).
3. Nhấp **Check Indicator Reputation**.
4. Hệ thống sẽ trả về kết quả Đánh giá (`MALICIOUS` hoặc `CLEAN`), Điểm rủi ro, Phân loại mối đe dọa và chi tiết JSON.

### ⚠️ Lưu ý
- Khi phát hiện một IP hoặc Hash bị gắn nhãn `MALICIOUS`, bạn nên thêm ngay vào Whitelist (nếu là nhầm lẫn) hoặc phát lệnh ngắt kết nối IP đó trên máy trạm.

---

## 10. Process Tree (Cây Tiến Trình & Gốc Rễ Mối Đe Dọa)

### 🎯 Mục đích
Trực quan hóa cấu trúc cây cha-con của các tiến trình đang chạy trên máy trạm. Giúp chuyên viên SOC truy tìm gốc rễ cuộc tấn công (Root Cause Analysis) và tiêu diệt tiến trình độc hại.

### 🛠️ Hướng dẫn thao tác
1. Chọn máy trạm cần kiểm tra ở menu góc trên.
2. **Xem tiến trình nghi vấn**: Khối thẻ đỏ góc trên cùng sẽ liệt kê các tiến trình bị hệ thống gắn nhãn **SUSPICIOUS** (ví dụ: `vssadmin.exe`, `nc`, `cmd.exe`).
3. **Xem Cây tiến trình**: Theo dõi cây thư mục phía dưới để biết tiến trình nào đã khởi tạo ra tiến trình độc hại (ví dụ: `Word.exe` mở `Powershell.exe`).
4. **Diệt Tiến Trình (Kill Process)**:
   - Nhấp nút **Kill** hoặc **Terminate PID** bên cạnh tiến trình độc hại.
   - Xác nhận trên modal để phát lệnh gửi tín hiệu `SIGKILL` tiêu diệt tiến trình ngay trên agent.

### ⚠️ Lưu ý
- Hãy cẩn trọng trước khi diệt các tiến trình hệ thống quan trọng (`systemd`, `explorer.exe`, `svchost.exe`) để tránh gây treo máy trạm.

---

## 11. Reports (Xuất Báo Cáo Định Kỳ)

### 🎯 Mục đích
Tự động tổng hợp dữ liệu sự cố, xu hướng rủi ro và tình trạng an ninh mạng theo từng tháng thành file báo cáo định dạng PDF.

### 🛠️ Hướng dẫn thao tác
1. **Tạo báo cáo mới**:
   - Nhấp nút **Generate New Report**.
   - Chọn Tháng và Năm cần lập báo cáo.
   - Nhấp **Generate Report**.
2. **Tải báo cáo PDF**:
   - Tại bảng danh sách báo cáo, nhấp nút **Download PDF** tương ứng để tải tệp báo cáo về máy tính.

### ⚠️ Lưu ý
- Báo cáo PDF bao gồm biểu đồ tổng hợp và số liệu thống kê thích hợp để gửi cho cấp quản lý hoặc bộ phận tuân thủ an ninh.

---

## 12. Whitelist (Danh Sách Trắng An Toàn)

### 🎯 Mục đích
Định nghĩa danh sách các tiến trình, đường dẫn tệp hoặc IP tin tưởng. Các tiến trình nằm trong Whitelist sẽ không bị hệ thống tự động ngăn chặn hay tính điểm rủi ro.

### 🛠️ Hướng dẫn thao tác
1. **Thêm quy tắc Whitelist**:
   - Nhấp nút **Add Whitelist Entry**.
   - Chọn phạm vi máy trạm (`GLOBAL` cho tất cả máy, hoặc chọn 1 máy cụ thể).
   - Nhập **Process Name** (ví dụ: `sshd`, `backup.exe`), **Binary Path** và **Reason** (Lý do miễn trừ).
   - Nhấp **Add Whitelist Rule**.
2. **Xóa khỏi Whitelist**:
   - Nhấp nút **Remove** dòng tương ứng để hủy bỏ quyền miễn trừ.

### ⚠️ Lưu ý
- Chỉ thêm vào Whitelist các phần mềm có nguồn gốc rõ ràng và đã được bộ phận IT phê duyệt để tránh bị kẻ tấn công lợi dụng.

---

## 13. Notifications (Cấu Hình Kênh Thông Báo)

### 🎯 Mục đích
Cấu hình các kênh nhận thông báo cảnh báo tức thì (Email SMTP, Slack Webhook, Telegram Bot) và xem nhật ký gửi tin nhắn.

### 🛠️ Hướng dẫn thao tác
1. **Thêm kênh thông báo**:
   - Nhấp **Add Notification Channel**.
   - Chọn kênh (Email, Webhook, Slack, Telegram) và nhập địa chỉ nhận / URL Webhook.
   - Nhấp **Save Channel**.
2. **Xem Nhật ký gửi (Dispatch Audit Logs)**:
   - Chuyển sang tab *Dispatch Audit Logs* để kiểm tra trạng thái gửi tin nhắn (`DELIVERED` hoặc `FAILED`).

### ⚠️ Lưu ý
- Đảm bảo URL Webhook của Slack/Telegram đang hoạt động chính xác bằng cách kiểm tra nhật ký sau khi phát sinh cảnh báo thử nghiệm.

---

## 14. Rules Engine (Quy Tắc Giám Sát Lượng Truy Cập)

### 🎯 Mục đích
Tạo và quản lý các quy tắc giám sát lưu lượng mạng (Packet rate, Port scan, SYN flood) cho các luồng dữ liệu kết nối.

### 🛠️ Hướng dẫn thao tác
1. Xem danh sách các quy tắc lọc lưu lượng hiện tại.
2. Bật/tắt hoặc chỉnh sửa ngưỡng tần suất lưu lượng (Packet per second) cho từng giao thức.

---

## 15. Attack Sim (Mô Phỏng Tấn Công Mạng)

### 🎯 Mục đích
Cung cấp công cụ mô phỏng tấn công từ chối dịch vụ (SYN Flood) hoặc gửi gói tin bất thường để kiểm thử khả năng phát hiện và tự động cô lập của hệ thống LARP.

### 🛠️ Hướng dẫn thao tác
1. Select Target Agent (Máy trạm mục tiêu).
2. Nhập số lượng gói tin/giây (gói SYN/s).
3. Nhấp **Launch Attack Sim** để bắt đầu đợt mô phỏng.
4. Quan sát phản ứng tự động trên *Dashboard* và trang *Alerts*.

### ⚠️ Lưu ý
- Tính năng này chỉ sử dụng trong môi trường thử nghiệm (Testbed/Lab). Không chạy mô phỏng trên mạng sản xuất (Production).

---

## 16. Settings (Cấu Hình Hệ Thống & Ngưỡng Rủi Ro)

### 🎯 Mục đích
Thiết lập các tham số vận hành cốt lõi của hệ thống LARP Manager, bao gồm 4 mức ngưỡng leo thang rủi ro và bật/tắt phản ứng tự động.

### 🛠️ Hướng dẫn thao tác
1. **Điều chỉnh 4 Mức Ngưỡng Rủi Ro (Risk Threshold Escalation Policy)**:
   - **Auto Isolation Threshold** (Mặc định: 85): Máy trạm đạt điểm này sẽ bị tự động cô lập mạng.
   - **Interactive Alert with Action Buttons** (Mặc định: 70): Hiển thị cảnh báo khẩn cấp kèm nút Isolate/Kill nhanh.
   - **Standard Alert Threshold** (Mặc định: 50): Ghi nhận cảnh báo tiêu chuẩn.
   - **Telemetry Log Threshold** (Mặc định: 20): Ghi nhật ký ngầm.
2. **Bật/Tắt Tự Động Phản Ứng (Automated Active Response)**:
   - Gạt công tắc *Automated Active Response* để cho phép hoặc cấm hệ thống tự động khóa mạng máy trạm.
3. Nhấp **Save Changes** để lưu cấu hình lên máy chủ.

### ⚠️ Lưu ý
- Trong giai đoạn đầu triển khai hệ thống, nên đặt *Auto Isolation Threshold* ở mức cao (>= 85-90) và theo dõi kỹ để tránh cô lập nhầm các máy trạm làm việc bình thường.

---

**LARP Support Team — Hệ Thống Giám Sát Và Phản Ứng Mạng Nội Bộ**
