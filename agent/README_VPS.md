# Hướng dẫn Triển khai LARP Agent & Vulnerable Web lên AWS Linux VPS

Tài liệu này hướng dẫn cách triển khai gói Client hoàn chỉnh gồm **LARP EDR Linux Agent** và **Vulnerable Web App** lên máy chủ AWS Linux VPS (Debian / Ubuntu) độc lập không qua Cloudflare Tunnel.

---

## 📁 1. Cấu trúc thư mục `agent/` sau khi tối ưu

Thư mục `agent/` hiện chỉ chứa mã nguồn dành riêng cho máy Linux Client / Victim:
- Đã tách toàn bộ mã nguồn Windows (`win_agent_cpp`, `win_agent_minimal.py`) sang `windows_agent/`.
- Đã tách toàn bộ kịch bản tấn công demo (`malware_sim/*.sh`) sang `attacks/malware_sim/` để sử dụng riêng trên máy Hacker.
- Tích hợp sẵn `vulnerable_web/app.py` với logging tự động (`access.log` và `auth.log`).

```text
agent/
├── agent.py                 # Core Linux EDR Agent (gửi tiến trình, socket, file, risk score)
├── auth_monitor.py          # Giám sát đăng nhập SSH/PAM và Web Login (Brute Force detection)
├── connection_tracker.py    # Theo dõi kết nối mạng outbound & beaconing
├── dns_sniffer.py           # Bắt gói tin DNS truy vấn
├── fim.py                   # Giám sát tính toàn vẹn file (File Integrity Monitoring)
├── watchdog.py              # Tự phục hồi agent khi bị tắt hoặc gặp lỗi
├── web_log_monitor.py       # Giám sát access.log phát hiện Hydra, nmap, sqlmap, traversal
├── yara_scanner.py          # Quét chữ ký mã độc YARA
├── commands/                # Lệnh phản ứng nhanh: isolate, kill_process_tree, quarantine...
├── vulnerable_web/
│   └── app.py               # Ứng dụng web có lỗ hổng (SQLi, Command Injection, Hydra Target)
├── larp-agent.service       # File cấu hình Systemd tự khởi động cho LARP Agent
├── vulnerable-web.service   # File cấu hình Systemd tự khởi động cho Vulnerable Web
├── setup_vps.sh             # Script cài đặt và cấu hình 1-click tự động trên VPS
├── deploy_to_vps.sh         # Script đồng bộ từ máy cá nhân lên VPS qua SSH
└── requirements.txt         # Thư viện Python: psutil, websockets, yara-python, Flask, requests
```

---

## 🚀 2. Cách triển khai lên AWS VPS

### Lưu ý trên AWS EC2 Security Group:
Trước khi chạy, đảm bảo **Security Group** của máy ảo AWS đã mở:
- **Cổng 22 (SSH)**: Cho phép kết nối SSH quản trị.
- **Cổng 5000 (Custom TCP)**: Cho phép máy hacker truy cập ứng dụng web demo (`0.0.0.0/0`).

---

### Cách 1: Triển khai từ xa từ máy cá nhân (Khuyên dùng)
Trên máy của bạn, chạy script tự động với IP public của VPS:
```bash
cd ~/Mon_hoc/Do_an_tot_nghiep/larp/agent
bash deploy_to_vps.sh <IP_PUBLIC_VPS>
```
*Script sẽ tự động dùng khóa `~/.ssh/key-debian-aws.pem`, rsync toàn bộ code lên VPS và tự chạy `setup_vps.sh`.*

---

### Cách 2: Chạy trực tiếp trên VPS (nếu đã SSH vào terminal VPS)
Nếu bạn đã mở sẵn terminal trên VPS (`admin@ip-172-31-32-238:~$`):

1. **Tải code về VPS** (hoặc copy từ máy local):
```bash
# Clone hoặc rsync mã nguồn vào thư mục ~/agent trên VPS
git clone https://github.com/conbobi/lan-active-response-platform.git ~/larp
cd ~/larp/agent
```

2. **Chạy script cài đặt tự động**:
```bash
sudo bash setup_vps.sh
```

Script sẽ tự động:
1. Cài các gói cần thiết: `python3-venv`, `build-essential`, `libyara-dev`, `ufw`, `iptables`, `sqlite3`, `curl`.
2. Tạo thư mục hệ thống chuẩn: `/opt/larp-agent`.
3. Khởi tạo Python venv và cài `requirements.txt`.
4. Tạo thư mục log `/var/log/vulnerable_web/` với quyền ghi.
5. Cài đặt và bật 2 dịch vụ Systemd:
   - `larp-agent.service` (kết nối trực tiếp tới `wss://edr.alwayready.id.vn/ws/agent`).
   - `vulnerable-web.service` (lắng nghe trên `0.0.0.0:5000`).

---

## 🔍 3. Kiểm tra hoạt động trên VPS

```bash
# 1. Kiểm tra trạng thái 2 dịch vụ:
systemctl status larp-agent
systemctl status vulnerable-web

# 2. Xem log kết nối LARP Agent về Manager:
journalctl -u larp-agent -f

# 3. Xem log Vulnerable Web:
journalctl -u vulnerable-web -f

# 4. Xem log HTTP Access thời gian thực khi Hacker quét web:
tail -f /var/log/vulnerable_web/access.log
```

---

## 🎯 4. Kịch bản test từ máy Hacker

Từ máy Hacker, tấn công trực tiếp vào IP Public của VPS:
```bash
# Test 1: Quét dịch vụ bằng nmap
nmap -sV -sC -p 5000 <IP_PUBLIC_VPS>

# Test 2: Brute force mật khẩu bằng Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 5000 <IP_PUBLIC_VPS> http-post-form "/login:username=^USER^&password=^PASS^:F=Sai tài khoản hoặc mật khẩu"

# Test 3: Command Injection qua endpoint /ping
curl "http://<IP_PUBLIC_VPS>:5000/ping?ip=127.0.0.1;id;whoami"
```

Khi các kịch bản này chạy:
- Mọi request của Hydra/nmap đều được ghi lại vào `/var/log/vulnerable_web/access.log`.
- `web_log_monitor.py` và `auth_monitor.py` trên LARP Agent lập tức gửi telemetry cảnh báo về Manager.
- Dashboard EDR tại [https://edr.alwayready.id.vn](https://edr.alwayready.id.vn) sẽ hiển thị cảnh báo đỏ **ACTIVE THREAT DETECTED** cùng nút **1-Click Isolate Host**!
