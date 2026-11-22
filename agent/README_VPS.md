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

## Network & Firewall

Mở **Agents → chọn Agent → Network & Firewall**. Tab hiển thị trạng thái
thu thập, thời điểm snapshot, UFW và chính sách kernel, socket TCP/UDP,
interface, route, NAT, firewall events và audit. Socket bind ngoài loopback
được báo riêng với khả năng truy cập từ Internet. AWS Security Group,
Network ACL, VPC routing và public IP translation hiển thị
`Unknown / Not integrated` khi chưa có tích hợp AWS.

### Đăng ký Manager và Agent

Cài các gói bổ sung qua `setup_vps.sh`. Module dùng `iproute2` cho
`ip` và `ss`, `ufw`, `nftables`, `iptables` và `systemd`/journal.
Telemetry dùng WebSocket `wss://` hiện có và credential riêng cho từng Agent.
Tạo credential riêng cho từng Agent và từng người dùng. Lặp lệnh bên dưới cho
mỗi credential. Giữ token gốc bí mật và chỉ đưa SHA-256 vào Manager.

```bash
python3 -c 'import hashlib, secrets; value=secrets.token_urlsafe(48); print(value); print(hashlib.sha256(value.encode()).hexdigest())'
```

Thêm vào môi trường Manager hoặc vào tệp `.env` của Docker Compose (đã cấu hình sẵn trong dự án):

```dotenv
NETWORK_AGENT_TOKENS='{"ip-172-31-32-238": "a3b1d109854ae8d23040793f11374aaabb11014746b3bf49701d0a8bab78fa3f", "aws-debian-01": "d576510fc793221db0256cb74fd4ac484fc1739899fb0cef3a1c790698dbd484", "my-desktop": "edfb86a94df7190ce23ab4c6bfc3b04530709afe92ba0c71fc7cf0ab46d13e30"}'
NETWORK_OPERATORS='{"soc-admin": {"token_sha256": "011d070f33c53a87cc6376535d470ed8ccf019527f16d68d84a5cd4edece8d78", "role": "admin", "agents": ["ip-172-31-32-238", "aws-debian-01", "my-desktop"]}, "soc-reader": {"token_sha256": "a0065f84f08797257645db4c02e3e9f5bc7f462cfaccca1d135b0e4f9f1390ef", "role": "analyst", "agents": ["ip-172-31-32-238", "aws-debian-01", "my-desktop"]}}'
NETWORK_LEGACY_ADMIN_TOKEN=6884edc739038179c2c588e38dcbbdb7c2b14c31f4a1c5eb7aee3894477f1097
LARP_MANAGER_DEBUG=false
```

Các Token bí mật tương ứng:
- **SOC Admin Token (Dùng trên Dashboard)**: `larp-token-soc-admin-3bcddf770e95f201fa77f157d9d4ab6237a63fd16098c2eb` (giao diện đã tự động nạp sẵn)
- **VPS Agent Token (`ip-172-31-32-238`)**: `larp-token-vps-172-db4d769ecc13846b3c80469b41951d4a8e96fc57c10883e3`
- **AWS Debian Agent Token (`aws-debian-01`)**: `larp-token-aws-debian-2908d361b405b178bacfe1232b5a07a295d250e6ba5bea38`
- **Desktop Agent Token (`my-desktop`)**: `larp-token-desktop-cc032846c9f2f308900e4289f3139e3a767e0c99c9d36254`

Trên Debian VPS, sau khi đồng bộ mã nguồn, chạy bằng tài khoản có quyền sudo:

```bash
cd ~/agent
sudo bash setup_vps.sh
sudo install -d -m 0700 /etc/larp-agent
sudo nano /etc/larp-agent/network.env
sudo chmod 0600 /etc/larp-agent/network.env
sudo systemctl restart larp-agent.service
sudo journalctl -u larp-agent.service -n 50 --no-pager
```

Nội dung cấu hình tệp `/etc/larp-agent/network.env` trên VPS:

```dotenv
AGENT_ID=ip-172-31-32-238
MANAGER_URL=wss://edr.alwayready.id.vn/ws/agent
LARP_NETWORK_AGENT_TOKEN=larp-token-vps-172-db4d769ecc13846b3c80469b41951d4a8e96fc57c10883e3
```

Từ thư mục gốc của repo trên Manager.

```bash
docker compose up -d --build manager frontend
docker compose logs --tail 50 manager
```

Migration `31cc534dcc0f` thêm bảng `network_snapshots` và cột nullable
`process_info.process_start_time`. Manager Docker cũng thực hiện hai thay đổi
bổ sung khi khởi động. Bảng giữ một snapshot mỗi Agent. Mỗi snapshot giữ tối
đa 500 dòng trên mỗi bảng telemetry và hiển thị số dòng thu thập được khi có
giới hạn. Firewall events giữ tối đa 500 bản ghi trong 24 giờ. Tác vụ ghi tận
dụng `commands`, `response_actions` và `action_audit_logs`.

### Bật quản trị UFW trên endpoint

Trước khi bật, kiểm tra bằng quyền quản trị cục bộ hoặc AWS console rằng SSH
từ các CIDR đã duyệt hoạt động và Security Group cho phép kết nối đó.
Kiểm tra rule SSH có hiệu lực theo cấu hình UFW sẽ được áp dụng khi bật.
Mỗi CIDR cần một rule TCP rõ ràng cho cổng SSH. Nếu UFW đang tắt,
dùng `ufw show added` để kiểm tra rule cấu hình sẵn. Profile hỗ trợ UFW
qua iptables-nft, `MANAGE_BUILTINS=no`, IPv6 bật và mặc định outgoing ACCEPT.
Rule người dùng trong profile phải là rule inbound TCP/UDP một cổng.
Cơ chế sẽ từ chối chain filter ngoài UFW, containment đang hoạt động,
legacy iptables đang sử dụng và các cấu hình vượt ngoài phạm vi rollback.
Docker, nftables riêng, iptables legacy, NAT và route vẫn có thể xem.

Duyệt các tệp before/after/init/sysctl mặc định của UFW và lấy fingerprint.

```bash
sudo /opt/larp-agent/venv/bin/python /opt/larp-agent/firewall_control.py fingerprint
sudoedit /etc/larp-agent/network.env
sudo systemctl daemon-reload
sudo systemctl enable --now larp-firewall-rollback.timer
sudo systemctl restart larp-agent.service
sudo systemctl status larp-firewall-rollback.timer --no-pager
```

Thêm cấu hình bên dưới vào `network.env`. CIDR ví dụ phải được thay bằng
mạng nguồn SSH đã duyệt, theo góc nhìn của VPS.

```dotenv
LARP_UFW_CONTROL=1
LARP_UFW_STATIC_SHA256=<reviewed-static-ufw-fingerprint>
LARP_UFW_SSH_CIDRS=<approved-admin-ip/32>
LARP_UFW_SSH_PORT=22
LARP_UFW_ROLLBACK_SECONDS=90
```

Kiểm tra lần đầu trên endpoint dùng riêng cho thử nghiệm.

1. Vào **Overview** rồi bấm **Refresh**. Đối chiếu socket, route và UFW với
   `ss -tulnp`, `ip -j route show table all` và `sudo ufw status verbose`.
2. Dùng token analyst xác nhận chỉ có quyền đọc và refresh. Dùng token admin
   gửi một thay đổi đã duyệt. Theo dõi command ACK và hạn rollback trong tab
   **Firewall Rules**. Lệnh disable có hiệu lực tạm thời theo mặc định.
3. Sau khi Agent xác nhận áp dụng, mở một **phiên SSH mới** từ CIDR đã duyệt,
   rồi chạy lệnh sau với ID transaction trên dashboard.

   ```bash
   sudo --preserve-env=SSH_CONNECTION /bin/bash -c 'set -a; . /etc/larp-agent/network.env; set +a; exec /opt/larp-agent/venv/bin/python /opt/larp-agent/firewall_control.py approve "$1"' _ TRANSACTION_ID
   ```

4. Bấm **Commit change** và nhập lý do. Manager và Agent kiểm tra ACK, trạng
   thái UFW mới, phiên SSH và kết nối TLS mới tới Manager. Nếu không commit,
   timer cục bộ phục hồi cấu hình trước đó. Kiểm tra **Audit History** và
   nhật ký sau đây trên endpoint thử nghiệm.

   ```bash
   sudo journalctl -u larp-firewall-rollback.service -n 50 --no-pager
   ```

Nếu có tác vụ đang chờ commit, thực hiện các thay đổi UFW bên ngoài LARP sau
khi giao dịch kết thúc. Worker so sánh cấu hình trước khi phục hồi. Trạng
thái `rollback_failed` cần khôi phục qua console hoặc kênh quản trị đã duyệt.
Dữ liệu phục hồi cục bộ được bảo vệ quyền root trong
`/var/lib/larp-agent/firewall-transaction.json`.

Giữ service demo tắt giữa các phiên kiểm thử.

```bash
sudo systemctl disable --now vulnerable-web.service
```

### API và WebSocket

- `GET /api/v1/network/agents/{agent_id}/{section}` với `overview`,
  `firewall`, `ports`, `connections`, `groups`, `interfaces`, `routes`,
  `policy`, `neighbors`, `nat`, `events` hoặc `audit`.
- `POST /api/v1/network/agents/{agent_id}/refresh`.
- `POST /api/v1/network/agents/{agent_id}/firewall/actions` với
  `enable`, `disable`, `reload`, `add_rule`, `delete_rule`,
  `set_policy`, `set_logging`, `commit` hoặc `rollback`.
- `GET /api/v1/network/agents/{agent_id}/commands/{command_id}`.
- Agent gửi `NETWORK_SNAPSHOT`, `NETWORK_ACK` và `NETWORK_TRANSACTION`
  qua `/ws/agent`. Manager giao `network_command` trong phản hồi heartbeat,
  hạn giao 45 giây và không tự động gửi lại.

Định hướng kết nối được ghi nhận khi quan sát được bắt tay TCP. Socket được
ghép với tiến trình khi xác minh được inode và thời điểm tạo tiến trình.
ASN hiện dùng bảng CIDR tham chiếu cục bộ. Bằng chứng DNS được để trống khi
telemetry chỉ có câu hỏi DNS. Sự kiện DROP/REJECT là dữ liệu quan sát firewall.
