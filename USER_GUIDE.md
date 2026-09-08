# HƯỚNG DẪN SỬ DỤNG HỆ THỐNG LAN ACTIVE RESPONSE MANAGER (LARP)

Chào mừng bạn đến với **LAN Active Response Platform (LARP)** – Hệ thống giám sát an ninh mạng nội bộ toàn diện, phân tích rủi ro theo thời gian thực (Real-time Telemetry Risk Assessment), tự động phát hiện chuỗi tiến trình độc hại và kích hoạt phản ứng phòng vệ chủ động (Active Response).

Tài liệu này cung cấp hướng dẫn vận hành chi tiết dành cho Chuyên viên Quản trị Hệ thống (SysAdmin) và Kỹ sư Phân tích Trung tâm Điều hành An ninh Mạng (SOC Analyst).

---

## 📑 MỤC LỤC
1. [Tổng Quan Kiến Trúc & Các Phân Hệ Chính](#1-tổng-quan-kiến-trúc--các-phân-hệ-chính)
2. [Hướng Dẫn Đọc Số Liệu & Nhận Diện Nguy Cơ](#2-hướng-dẫn-đọc-số-liệu--nhận-diện-nguy-cơ)
   - [2.1. Đánh Giá Điểm Rủi Ro (Risk Score)](#21-đánh-giá-điểm-rủi-ro-risk-score)
   - [2.2. Phân Tích Lưu Lượng Mạng (Network Traffic & Flow Data)](#22-phân-tích-lưu-lượng-mạng-network-traffic--flow-data)
   - [2.3. Cây Tiến Trình (Process Tree) & Cơ Chế Lọc Zombie](#23-cây-tiến-trình-process-tree--cơ-chế-lọc-zombie)
   - [2.4. Quản Lý Sự Cố (Incidents & FIM Alerting)](#24-quản-lý-sự-cố-incidents--fim-alerting)
   - [2.5. Quản Lý Luật Phát Hiện (Detection Rules & Dynamic Process Chains)](#25-quản-lý-luật-phát-hiện-detection-rules--dynamic-process-chains)
3. [Hướng Dẫn Chi Tiết Các Trang Chức Năng Trên Giao Diện Web](#3-hướng-dẫn-chi-tiết-các-trang-chức-năng-trên-giao-diện-web)
   - [Dashboard](#31-dashboard-bảng-điều-khiển-tổng-quan)
   - [Agents Management](#32-agents-quản-lý-thiết-bị-máy-trạm)
   - [Alerts](#33-alerts-cảnh-báo-an-ninh)
   - [Incidents](#34-incidents-quản-lý-sự-cố)
   - [Process Tree & Threat Root Cause](#35-process-tree-cây-tiến-trình--gốc-rễ-đe-dọa)
   - [Detection Rules & Process Chains](#36-detection-rules-process-groups--process-chains)
   - [Risk Assessment](#37-risk-assessment-phân-tích-telemetry)
   - [Network 3D Topology](#38-network-sơ-đồ-mạng-3d--điều-phối-băng-thông)
   - [Commands & Active Response](#39-commands-phát-lệnh-điều-khiển)
   - [Whitelist & Settings](#310-whitelist--settings-cấu-hình-hệ-thống)
4. [Hướng Dẫn Chạy Các Kịch Bản Demo Thử Nghiệm Nhanh (Bash Scripts)](#4-hướng-dẫn-chạy-các-kịch-bản-demo-thử-nghiệm-nhanh-bash-scripts)
   - [Demo 1: File Integrity Monitoring (`demo_fim.sh`)](#demo-1-file-integrity-monitoring-demo_fimsh)
   - [Demo 2: Thu Thập Lưu Lượng Mạng Thật (`demo_network_traffic.sh`)](#demo-2-thu-thập-lưu-lượng-mạng-thật-demo_network_trafficsh)
   - [Demo 3: Cây Tiến Trình & Lọc Zombie (`demo_process_tree.sh`)](#demo-3-cây-tiến-trình--lọc-zombie-demo_process_treesh)
   - [Demo 4: Tự Phục Hồi Kết Nối & Watchdog (`demo_reconnect.sh`)](#demo-4-tự-phục-hồi-kết-nối--watchdog-demo_reconnectsh)
5. [Quy Trình Xử Lý Sự Cố Khẩn Cấp (SOP)](#5-quy-trình-xử-lý-sự-cố-khẩn-cấp-sop)

---

## 1. Tổng Quan Kiến Trúc & Các Phân Hệ Chính

LARP được thiết kế theo mô hình **Manager - Agent** giao tiếp hai chiều thời gian thực qua **WebSocket (WS)**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     LARP MANAGER (FastAPI + PostgreSQL)                │
│  - REST API & WebSocket Handler (/api/v1/ws/{agent_id})                 │
│  - Real-time Flow Analytics & FIM Incident Generator                    │
│  - Dynamic Process Chain Detection & Risk Engine (13 Rules)             │
└────────────▲───────────────────────────────────────────────▲────────────┘
             │ WebSocket (Heartbeat, Commands, Logs)         │
             ▼                                               ▼
┌─────────────────────────────┐                 ┌─────────────────────────┐
│     LARP AGENT (client1)    │                 │   REACT VITE DASHBOARD  │
│ - Process Tree Collector    │                 │ - Live WS Flow Charts   │
│ - Real Flow Stats Delta     │                 │ - Process Tree Explorer │
│ - FIM Monitor (SHA-256)     │                 │ - Dynamic Rule Manager  │
│ - Reconnect Exponential     │                 │ - Incident SOC Board    │
│ - Watchdog (30s exit)       │                 └─────────────────────────┘
└─────────────────────────────┘
```

- **Manager**: Điều phối trung tâm, lưu trữ cơ sở dữ liệu PostgreSQL (`flows`, `incidents`, `process_groups`, `process_chain_rules`, `detection_rules`), đánh giá rủi ro và phát lệnh điều khiển.
- **Agent**: Triển khai trên máy trạm/máy chủ Linux. Định kỳ gửi Telemetry, Flow Stats thật (tính toán qua `psutil.net_io_counters`), phát hiện thay đổi file (FIM SHA-256), cây tiến trình (lọc sạch zombie) và cơ chế tự phục hồi kết nối.
- **Frontend Dashboard**: Ứng dụng web React Vite cung cấp giao diện trực quan hóa cao cấp, đồ thị thời gian thực, bảng điều khiển SOC và cây tiến trình động.

---

## 2. Hướng Dẫn Đọc Số Liệu & Nhận Diện Nguy Cơ

### 2.1. Đánh Giá Điểm Rủi Ro (Risk Score)

Hệ thống chấm điểm rủi ro cho từng Agent trên thang điểm từ **0 đến 100** dựa trên 13 quy tắc phân tích hành vi và trọng số vi phạm:

| Mức Độ | Dải Điểm (Risk Score) | Màu Sắc | Ý Nghĩa & Nguy Cơ | Hành Động Đề Xuất |
| :--- | :---: | :---: | :--- | :--- |
| **Low** | 0 – 49 | 🟢 Xanh lục | Hoạt động bình thường. Lưu lượng và tiến trình nằm trong ngưỡng cho phép. | Tiếp tục giám sát định kỳ. |
| **Medium** | 50 – 69 | 🟡 Vàng | Xuất hiện hành vi đáng ngờ nhẹ (quét cổng nội bộ, tăng CPU đột biến, tệp hệ thống phụ bị sửa). | SOC ghi nhận và theo dõi sát. |
| **High** | 70 – 84 | 🟠 Cam | Dấu hiệu tấn công rõ rệt (chuỗi tiến trình lạ, kết nối C2 IP độc hại, sửa Registry/Cron). | Gửi cảnh báo khẩn, khuyến nghị Isolate hoặc Kill Process. |
| **Critical** | 85 – 100 | 🔴 Đỏ | Mối đe dọa nghiêm trọng (Ransomware xóa Shadow Copies, FIM phát hiện sửa `/etc/passwd`, DDoS flood). | **Tự động cô lập mạng (Auto-Isolate)** và phát thông báo đa kênh. |

> **Chính sách Leo Thang Rủi Ro (Risk Escalation Policy):**
> - `Điểm >= 20`: Ghi nhận Telemetry Log ngầm.
> - `Điểm >= 50`: Phát cảnh báo tiêu chuẩn (Standard Alert).
> - `Điểm >= 70`: Bật thông báo tương tác nổi (Interactive Notification kèm nút Isolate/Kill).
> - `Điểm >= 85`: Tự động ngắt kết nối mạng của Agent (Auto-Isolate) nếu bật thiết lập *Automated Active Response*.

---

### 2.2. Phân Tích Lưu Lượng Mạng (Network Traffic & Flow Data)

Phân hệ Network Flow thu thập **dữ liệu lưu lượng thực tế** (`FLOW_STATS`) trực tiếp từ card mạng thông qua các delta đo lường giữa hai chu kỳ gửi:

- `bytes_sent`: Lượng byte gửi đi trong chu kỳ.
- `bytes_recv`: Lượng byte nhận về trong chu kỳ.
- `packets_sent`: Tổng số gói tin gửi đi.
- `packets_recv`: Tổng số gói tin nhận về.
- `tcp`: Số gói tin TCP gửi/nhận.
- `udp`: Số gói tin UDP gửi/nhận.

#### Cách nhận diện các hình thức tấn công mạng điển hình:

```
[1. TẤN CÔNG DoS / DDoS]
   Packets Rate: ──▲── (Tăng vọt hàng chục nghìn gói/giây)
   Kích thước gói: Nhỏ (SYN packet, UDP flood)
   -> Biểu đồ: Cột Packets tăng vọt dựng đứng, CPU agent tăng cao.

[2. ĐÁNH CẮP DỮ LIỆU (DATA EXFILTRATION)]
   Bytes Sent:   ──▲── (Tăng đột biến hàng trăm MB / GB gửi ra ngoài)
   Bytes Recv:   ───── (Gần như không đổi hoặc rất thấp)
   -> Biểu đồ: Chênh lệch rõ nét giữa Bytes Sent (rất cao) và Bytes Recv (rất thấp).

[3. DÒ QUÉT CỔNG / MẠNG (PORT SCAN / SYN SWEEP)]
   TCP Packets:  ──▲── (Hàng loạt gói SYN gửi tới nhiều cổng/IP đích)
   Bytes:        ─── (Bytes rất nhỏ do chỉ có cờ bắt tay SYN mà không truyền data)
   -> Biểu đồ: Tỷ lệ TCP packets/s cao bất thường nhưng tổng Bytes cực thấp.
```

---

### 2.3. Cây Tiến Trình (Process Tree) & Cơ Chế Lọc Zombie

Trang **Process Tree** giúp chuyên viên SOC phân tích cấu trúc cha-con của mọi tiến trình đang chạy:

1. **Gốc Cây Tiến Trình (Root Node PID 1)**:
   - Tất cả các tiến trình mồ côi (Orphan Processes có `ppid = 0` hoặc cha không tồn tại) đều được hệ thống tự động gắn vào nút gốc PID 1 (`systemd` / `init`).
   - Điều này đảm bảo cây tiến trình luôn toàn vẹn và không bị đứt đoạn hiển thị.
2. **Cơ Chế Lọc Sạch Tiến Trình Zombie**:
   - Tiến trình Zombie (trạng thái `STATUS_ZOMBIE`, `defunct`) là tiến trình con đã kết thúc nhưng tiến trình cha chưa gọi hàm `wait()`.
   - Hàm `collect_process_info()` của Agent **chủ động loại bỏ** các tiến trình zombie này. Điều này giữ cho cây tiến trình luôn gọn gàng, không bị nghẽn giao diện bởi các tiến trình rác đã chết.
3. **Thao Tác Diệt Tiến Trình**:
   - **Kill Process**: Gửi tín hiệu `SIGKILL` tiêu diệt đúng PID chỉ định.
   - **Kill Process Tree**: Duyệt đệ quy và tiêu diệt đồng loạt toàn bộ nhánh tiến trình con và cháu của PID được chọn, ngăn chặn mã độc tự sinh lại (anti-respawn).

---

### 2.4. Quản Lý Sự Cố (Incidents & FIM Alerting)

Cơ chế **File Integrity Monitoring (FIM)** giám sát mã băm SHA-256 của các tệp tin quan trọng:
- `/etc/passwd`, `/etc/shadow`, `/etc/hosts` (Tệp hệ thống nhạy cảm)
- `/tmp/malware_sim/` (Thư mục kiểm thử mã độc)

#### Quy trình xử lý cảnh báo FIM:
1. **Lập Baseline Ban Đầu**: Khi Agent khởi động, toàn bộ mã băm SHA-256 ban đầu được lưu lại.
2. **Chống Gửi Cảnh Báo Trùng Lặp (State Transition Alerting)**:
   - Khi một file bị thay đổi (Modification), thêm mới (Creation), hoặc bị xóa (Deletion), Agent gửi đúng **01 gói tin cảnh báo duy nhất** (`FIM_ALERT`) và lập tức cập nhật lại hash mới.
   - Các chu kỳ quét tiếp theo sẽ không gửi lặp lại, tránh gây quá tải hộp thư SOC (Alert Flooding).
3. **Tự Động Tạo Sự Cố (Automatic Incident Creation)**:
   - Nếu tệp bị sửa đổi nằm trong danh sách nhạy cảm (như `/etc/passwd` hoặc `/etc/shadow`), Manager sẽ tự động tạo một sự cố mức **CRITICAL** trên bảng Incidents với tiêu đề:
     `FIM Alert: /etc/passwd modified on client1`.

---

### 2.5. Quản Lý Luật Phát Hiện (Detection Rules & Dynamic Process Chains)

Hệ thống hỗ trợ 2 tầng luật phát hiện:

#### 13 Quy Tắc Cố Định Cốt Lõi (Core Detection Rules):
1. `cpu_spike`: Tăng vọt CPU đột biến.
2. `suspicious_process`: Khởi chạy công cụ tấn công (`mimikatz`, `nmap`, `netcat`, `nc`, `hydra`).
3. `network_connection`: Kết nối vượt ngưỡng số lượng port/kết nối.
4. `file_changes`: Tạo/sửa tệp hàng loạt (dấu hiệu Ransomware).
5. `process_chain`: Chuỗi tiến trình độc hại (ví dụ Word gọi PowerShell).
6. `injection`: Chèn mã tiến trình (`ptrace`, `/proc/self/mem`).
7. `living_off_land`: Lợi dụng tiện ích có sẵn của OS (LoLBins: `powershell -enc`, `certutil -urlcache`, `curl | bash`).
8. `registry`: Thay đổi khóa khởi động tự động (Persistence).
9. `credential_dumping`: Trích xuất thông tin đăng nhập (`lsass`, `/etc/shadow`).
10. `shadow_copy`: Xóa bản sao lưu (`vssadmin delete shadows`).
11. `c2_communication`: Liên lạc IP máy chủ điều khiển độc hại (Command & Control).
12. `lateral_movement`: Dò quét và lây lan trong mạng LAN (SMB/RDP/SSH sweep).
13. `mass_file_modification`: Sửa đổi phần mở rộng tệp hàng loạt (`.locked`, `.crypto`).

#### Quản Lý Chuỗi Tiến Trình Động (Dynamic Process Chains):
Không cần sửa code Python, quản trị viên có thể tự cấu hình:
- **Process Groups (Nhóm tiến trình)**: Nhóm các tiến trình có chung đặc điểm:
  - `Office Applications`: `["winword.exe", "excel.exe", "powerpnt.exe"]`
  - `Script Interpreters`: `["powershell.exe", "cmd.exe", "bash", "sh", "python3"]`
  - `Download Utilities`: `["curl", "wget", "certutil.exe"]`
- **Process Chain Rules (Luật chuỗi cha - con)**:
  - Chọn Nhóm Cha (`Parent Group`) -> Chọn Nhóm Con (`Child Group`).
  - Gán trọng số vi phạm (Risk Weight, ví dụ: 30pt).
  - Tự động phát hiện khi bất kỳ tiến trình nào thuộc Nhóm Cha khởi chạy tiến trình thuộc Nhóm Con!

---

## 3. Hướng Dẫn Chi Tiết Các Trang Chức Năng Trên Giao Diện Web

### 3.1. Dashboard (Bảng Điều Khiển Tổng Quan)
- **Truy cập**: `http://localhost:5173/`
- **Thành phần giao diện**:
  - **4 thẻ chỉ số nhanh**:
    - *Online Agents*: Số máy trạm đang kết nối thời gian thực.
    - *Alerts Today*: Số cảnh báo phát sinh trong 24 giờ qua.
    - *Average Risk Score*: Điểm rủi ro trung bình mạng LAN.
    - *Blocked IPs*: Số lượng IP đang bị khóa.
  - **Biểu đồ Network Traffic (Real-time Flow Chart)**: Hiển thị biến thiên lưu lượng `bytes_sent` và `bytes_recv` nhận từ các agent.
  - **Bảng Agent Table**: Bấm vào từng dòng để xem cấu hình chi tiết (IP, CPU, RAM, Disk, Uptime).

### 3.2. Agents (Quản Lý Thiết Bị / Máy Trạm)
- **Truy cập**: `http://localhost:5173/agents`
- **Thao tác**:
  - Xem danh sách toàn bộ thiết bị trong mạng kèm địa chỉ IP và trạng thái kết nối.
  - **Isolate Agent**: Nhấn nút **Isolate** để cô lập thiết bị khi bị tấn công. Agent sẽ kích hoạt luật tường lửa chặn toàn bộ traffic ra/vào LAN ngoại trừ kênh quản trị LARP.
  - **Unisolate Agent**: Mở lại kết nối bình thường sau khi đã dọn dẹp sạch mã độc.

### 3.3. Alerts (Cảnh Báo An Ninh)
- **Truy cập**: `http://localhost:5173/alerts`
- **Thao tác**:
  - Lọc theo mức độ nghiêm trọng: `All`, `Critical`, `High`, `Medium`, `Low`.
  - Tìm kiếm theo tên tiến trình hoặc IP nguồn.
  - Xem chi tiết dấu vết vi phạm và các luật đã bị kích hoạt.

### 3.4. Incidents (Quản Lý Sự Cố)
- **Truy cập**: `http://localhost:5173/incidents`
- **Thao tác**:
  - Xem danh sách sự cố được tạo tự động (bao gồm sự cố từ FIM).
  - **Phân công (Assign)**: Gán sự cố cho nhân sự SOC phụ trách.
  - **Giải quyết (Resolve)**: Cập nhật sự cố sang trạng thái `Resolved` sau khi hoàn tất khắc phục.

### 3.5. Process Tree (Cây Tiến Trình & Gốc Rễ Đe Dọa)
- **Truy cập**: `http://localhost:5173/processes`
- **Thao tác**:
  - Chọn Agent từ menu trên cùng.
  - Theo dõi danh sách các tiến trình nghi vấn được bôi màu đỏ/cam.
  - Khám phá sơ đồ cây cha-con tương tác.
  - Thao tác **Kill PID** (diệt 1 tiến trình) hoặc **Kill Tree** (diệt sạch cây tiến trình con cháu).

### 3.6. Detection Rules (Process Groups & Process Chains)
- **Truy cập**: `http://localhost:5173/detection-rules`
- **Thao tác**:
  - **Tab 1: Detection Rules**: Bật/tắt 13 luật cố định và điều chỉnh điểm số trọng số (`weight`).
  - **Tab 2: Process Groups**: Tạo các nhóm mẫu tiến trình (ví dụ: nhóm Office, nhóm Shell).
  - **Tab 3: Process Chain Rules**: Tạo quy tắc phát hiện chuỗi cha-con giữa 2 nhóm tiến trình.

### 3.7. Risk Assessment (Phân Tích Telemetry)
- **Truy cập**: `http://localhost:5173/risk-assessment`
- **Thao tác**:
  - Chạy thử nhanh với các kịch bản mẫu: *Ransomware Burst*, *Privilege Escalation*, *Normal Telemetry*.
  - Nhập thông số telemetry và nhấn **Evaluate Risk Score** để xem phân tích các nhân tố rủi ro.

### 3.8. Network (Sơ Đồ Mạng 3D & Điều Phối Băng Thông)
- **Truy cập**: `http://localhost:5173/network`
- **Thao tác**:
  - Xoay, phóng to, thu nhỏ không gian mạng 3D.
  - Chọn Source Agent và Destination Agent, nhập nhu cầu băng thông để tìm đường truyền tối ưu (Dijkstra).
  - Bấm vào một đường kết nối để mô phỏng đứt cáp và xem thuật toán tự tìm đường vòng.

### 3.9. Commands (Phát Lệnh Điều Khiển)
- **Truy cập**: `http://localhost:5173/commands`
- **Thao tác**:
  - Phát lệnh trực tiếp xuống Agent: cô lập máy, cập nhật luật firewall, thu thập log hệ thống hoặc chạy script tùy chỉnh.
  - Theo dõi trạng thái hoàn thành (`PENDING`, `COMPLETED`, `FAILED`) và nút **Retry** gửi lại lệnh.

### 3.10. Whitelist & Settings (Cấu Hình Hệ Thống)
- **Truy cập**: `http://localhost:5173/whitelist` và `http://localhost:5173/settings`
- **Thao tác**:
  - Thêm tiến trình hoặc đường dẫn file tin cậy vào Whitelist để không bị tính điểm rủi ro.
  - Cấu hình 4 ngưỡng leo thang rủi ro (Risk Thresholds: 20, 50, 70, 85).
  - Bật/tắt tính năng Tự động phản ứng (Automated Active Response).

---

## 4. Hướng Dẫn Chạy Các Kịch Bản Demo Thử Nghiệm Nhanh (Bash Scripts)

Tất cả các script demo đã được chuẩn bị sẵn trong thư mục `agent/malware_sim/`. Bạn có thể chạy trực tiếp trên máy trạm hoặc bên trong Docker container của Agent.

```bash
# Di chuyển vào thư mục chứa script
cd agent/malware_sim/
```

---

### Demo 1: File Integrity Monitoring (`demo_fim.sh`)

#### Mục đích kiểm chứng:
Kiểm chứng khả năng tính toán mã băm SHA-256 cơ sở, phát hiện chính xác khi có tệp tin bị can thiệp và chỉ gửi 01 cảnh báo duy nhất (tránh alert flooding).

#### Cách chạy:
- **Chạy trực tiếp trên máy host:**
  ```bash
  ./agent/malware_sim/demo_fim.sh
  ```
- **Hoặc chạy trong container `client1`:**
  ```bash
  docker exec -it larp-client1-1 /bin/bash /app/malware_sim/demo_fim.sh
  ```

#### Kết quả hiển thị trên Terminal:
```
=================================================================
        DEMO: FILE INTEGRITY MONITORING (FIM) KIỂM TRA HASH      
=================================================================

[Bước 1] Khởi tạo các file dữ liệu mẫu trong /tmp/fim_demo...
 -> Đã tạo 3 file: config.txt, credentials.txt, audit_log.txt

[Bước 2] Tính toán mã băm SHA-256 cơ sở (Baseline)...
Tên file                      | SHA-256 Hash ban đầu                                         
------------------------------------------------------------------------------------------------------
audit_log.txt                  | 18365cbf6bc0025f924d421ec94a1a13087fcb4dda96e1bf0c5a2bf9e932a034
config.txt                     | 730c0a5caddd4137c42d8ab7731e38d13ddca89d2cf3f177327e1671f46d01b9
credentials.txt                | fecb560aa9d7d24ac01713b1c8bebb0a71d6b14833c1e68bc9ae28f70f42b97b

[Bước 3] Giả lập kẻ tấn công chỉnh sửa file credentials.txt...
 -> Đã thêm chuỗi độc hại vào credentials.txt!

[Bước 4] Quét lại tính toàn vẹn (Integrity Check) và đối soát:...
------------------------------------------------------------------------------------------------------
Tên file            | Trạng thái | Chi tiết hash
------------------------------------------------------------------------------------------------------
audit_log.txt        | UNCHANGED    | 18365cbf6bc0025f924d421ec94a1a13087fcb4dda96e1bf0c5a2bf9e932a034
config.txt           | UNCHANGED    | 730c0a5caddd4137c42d8ab7731e38d13ddca89d2cf3f177327e1671f46d01b9
credentials.txt      | MODIFIED     | Cũ: fecb560aa9d7d24ac01713b1c8bebb0a71d6b14833c1e68bc9ae28f70f42b97b
                     |              | Mới: d20c4d4fd6e15a8eac66a2e9df58faa77236e5721cac9246cbd352f59d466da5

[THÀNH CÔNG] Cơ chế FIM đã phát hiện chính xác file credentials.txt bị sửa đổi!
```

#### Cách kiểm tra trên giao diện Web:
1. Mở trang **Incidents** (`http://localhost:5173/incidents`).
2. Quan sát sự cố mới được tạo với nhãn `CRITICAL` và tóm tắt tệp tin bị thay đổi.

---

### Demo 2: Thu Thập Lưu Lượng Mạng Thật (`demo_network_traffic.sh`)

#### Mục đích kiểm chứng:
Tạo lưu lượng mạng (ICMP / HTTP traffic) trong 10-15 giây để kiểm chứng tính năng thu thập Network Flow Stats thật và hiển thị biểu đồ Network Traffic trên Dashboard.

#### Cách chạy:
- **Chạy trực tiếp trên máy host:**
  ```bash
  ./agent/malware_sim/demo_network_traffic.sh 127.0.0.1 8002
  ```
- **Hoặc chạy trong container `client1`:**
  ```bash
  docker exec -it larp-client1-1 /bin/bash /app/malware_sim/demo_network_traffic.sh manager 8000
  ```

#### Kết quả hiển thị trên Terminal:
```
=================================================================
       DEMO: PHÁT SINH LƯU LƯỢNG MẠNG (NETWORK TRAFFIC)         
=================================================================
[*] Mục tiêu: manager:8000
[*] Thời gian chạy: 12 giây

[Bước 1] Bắt đầu phát sinh traffic liên tục (HTTP GET requests & Ping)...
 -> Đang tạo lưu lượng mạng... [12/12s]

[THÀNH CÔNG] Đã hoàn thành đợt phát sinh traffic trong 12 giây!
```

#### Cách kiểm tra trên giao diện Web:
1. Mở trang **Dashboard** (`http://localhost:5173/`).
2. Quan sát biểu đồ **Network Traffic**:
   - Bạn sẽ thấy đường lưu lượng `bytes_sent` và `packets_sent` tăng vọt tạo thành một đỉnh nhọn (spike) rõ rệt.
   - Các gói tin được lưu trực tiếp vào cơ sở dữ liệu `flows` của PostgreSQL và hiển thị chuẩn xác thay vì dữ liệu giả lập (synthetic data).

---

### Demo 3: Cây Tiến Trình & Lọc Zombie (`demo_process_tree.sh`)

#### Mục đích kiểm chứng:
Tạo cấu trúc tiến trình lồng nhau 3 cấp (`bash` -> `python3` -> `sleep`) và 1 tiến trình Zombie (`<defunct>`) để kiểm chứng khả năng phân cấp trực quan và tính năng tự động lọc bỏ tiến trình zombie.

#### Cách chạy:
- **Chạy trực tiếp trên máy host:**
  ```bash
  ./agent/malware_sim/demo_process_tree.sh
  ```
- **Hoặc chạy trong container `client1`:**
  ```bash
  docker exec -it larp-client1-1 /bin/bash /app/malware_sim/demo_process_tree.sh
  ```

#### Kết quả hiển thị trên Terminal:
```
=================================================================
    DEMO: PROCESS TREE PHÂN CẤP LỒNG NHAU VÀ TIẾN TRÌNH ZOMBIE  
=================================================================

[Bước 1] Khởi chạy tiến trình Python tạo phân cấp cây và Zombie...

[THÔNG TIN CÂY TIẾN TRÌNH ĐÃ TẠO]:
 1. [Cha (Bash)]        PID: 651467 (demo_process_tree.sh)
    └── 2. [Con (Python3)]  PID: 651468
        ├── 3. [Cháu (Sleep)]   PID: 651470
        └── 4. [Zombie Child]   PID: 651471 (Trạng thái: Z / <defunct>)

[Bước 2] Kiểm tra trạng thái thực tế bằng lệnh 'ps':
    PID    PPID STAT CMD
 651467  651466 S    bash ./agent/malware_sim/demo_process_tree.sh
 651468  651467 S    python3 -
 651470  651468 S    sleep 60
 651471  651468 Z    [python3] <defunct>
```

#### Cách kiểm tra trên giao diện Web:
1. Mở trang **Process Tree** (`http://localhost:5173/processes`).
2. Chọn đúng Agent mục tiêu (ví dụ: `client1`).
3. **Kiểm tra phân cấp cây**: Nhận diện rõ ràng `python3` là cha của tiến trình `sleep`.
4. **Kiểm tra lọc Zombie**: Tiến trình có PID Zombie (`PID 651471`) **hoàn toàn biến mất** khỏi cây tiến trình, không làm rác giao diện giám sát.
5. **Thử nghiệm tính năng Kill Tree**: Nhấn nút **Kill Tree** tại PID `python3` -> Cả tiến trình cha lẫn tiến trình con `sleep` đều bị tiêu diệt ngay lập tức.

---

### Demo 4: Tự Phục Hồi Kết Nối & Watchdog (`demo_reconnect.sh`)

#### Mục đích kiểm chứng:
Kiểm chứng khả năng chịu lỗi (Fault Tolerance) của Agent khi Manager gặp sự cố:
- Thử lại kết nối theo hàm mũ (Exponential Backoff: 2s -> 4s -> 8s -> 15s).
- Cơ chế Watchdog phát hiện mất Heartbeat ACK quá 30s sẽ kích hoạt `os._exit(1)`.
- Chính sách `restart: unless-stopped` của Docker tự khởi động lại Agent sạch sẽ.

#### Cách chạy:
Chạy trên máy host (nơi có quyền điều khiển Docker daemon):
```bash
./agent/malware_sim/demo_reconnect.sh
```

#### Kết quả hiển thị trên Terminal:
```
=================================================================
     DEMO: RECONNECT EXPONENTIAL BACKOFF & WATCHDOG RECOVERY    
=================================================================
[*] Container Manager: larp-manager-1
[*] Container Client1: larp-client1-1

[Bước 1] Dừng container Manager (larp-manager-1) trong 10 giây...
[!] Manager đã tạm dừng.
[Bước 2] Quan sát Client1 phát hiện mất kết nối và kích hoạt Exponential Backoff:
 -> Reconnecting in 2s...
 -> Reconnecting in 4s...
 -> Reconnecting in 8s...

[Bước 3] Khởi động lại container Manager...
[+] Manager đã hoạt động trở lại!
[Bước 4] Theo dõi Client1 tự động Reconnect và đồng bộ lại Heartbeat:
 -> Connected to Manager successfully!
 -> Heartbeat restored. Delay reset to 2s.

[THÀNH CÔNG] Cơ chế Reconnect & Watchdog hoạt động hoàn hảo!
```

---

## 5. Quy Trình Xử Lý Sự Cố Khẩn Cấp (SOP)

Khi hệ thống phát cảnh báo mức **High** hoặc **Critical**:

```
[BƯỚC 1: XÁC MINH (VERIFY)]
  ├── Vào trang Alerts & Incidents.
  └── Xem chi tiết nguyên nhân vi phạm (Rule vi phạm, File bị sửa, IP kết nối).

[BƯỚC 2: CÔ LẬP KHẨN CẤP (CONTAINMENT)]
  ├── Nhấn nút "Isolate" tại trang Agents hoặc banner cảnh báo khẩn.
  └── Thiết bị bị ngắt kết nối với toàn bộ mạng nội bộ, chặn lây lan ngang.

[BƯỚC 3: PHÂN TÍCH GỐC RỄ (ROOT CAUSE)]
  ├── Mở trang Process Tree.
  └── Kiểm tra cây tiến trình độc hại, xác định phần mềm khởi tạo ban đầu.
  └── Bấm "Kill Tree" để tiêu diệt toàn bộ cây tiến trình độc hại.

[BƯỚC 4: KHẮC PHỤC & MỞ LẠI (RECOVERY)]
  ├── Xóa bỏ tệp độc hại, khôi phục tệp hệ thống nếu FIM phát hiện sửa đổi.
  ├── Nhấn "Unisolate" trên trang Agents để đưa máy trạm hoạt động trở lại.
  └── Đóng sự cố trên trang Incidents (Chuyển trạng thái sang Resolved).
```

---

*Tài liệu được cập nhật tự động và đồng bộ với nền tảng LARP phiên bản mới nhất.*
