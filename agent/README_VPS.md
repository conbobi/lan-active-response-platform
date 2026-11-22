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
Script dùng khóa `~/.ssh/key-debian-aws.pem` để đồng bộ mã nguồn và chạy
`setup_vps.sh`. Cần có `rsync` trên cả máy cá nhân lẫn VPS. Trên VPS Debian
mới, cài `rsync` trước khi chạy script lần đầu.

```bash
sudo apt-get update && sudo apt-get install -y rsync
```

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
1. Cài các gói cần thiết: `python3-venv`, `build-essential`, `libyara-dev`, `iproute2`, `nftables`, `iptables`, `sqlite3`, `curl`.
2. Tạo thư mục hệ thống chuẩn: `/opt/larp-agent`.
3. Khởi tạo Python venv và cài `requirements.txt`.
4. Tạo thư mục log `/var/log/vulnerable_web/` với quyền ghi.
5. Cài các unit systemd và khởi động `larp-agent.service`. Demo và quản trị
   UFW cần được bật riêng khi triển khai.

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

Cài các gói telemetry qua `setup_vps.sh`. Script cài Agent không cài UFW để
tránh chạy hook Debconf có thể bật firewall. Cài hoặc nâng cấp UFW riêng qua
AWS Systems Manager, EC2 Serial Console hoặc kênh bảo trì đã kiểm chứng.
Telemetry dùng `iproute2`, `nftables`, `iptables` và systemd journal.
Telemetry dùng WebSocket `wss://` hiện có và credential riêng cho từng Agent.
Tạo credential riêng cho từng Agent và từng người dùng. Lặp lệnh bên dưới cho
mỗi credential. Giữ token gốc bí mật và chỉ đưa SHA-256 vào Manager.

```bash
python3 -c 'import hashlib, secrets; value=secrets.token_urlsafe(48); print(value); print(hashlib.sha256(value.encode()).hexdigest())'
```

Thêm digest vào môi trường Manager hoặc tệp `.env` của Docker Compose.
Hãy thu hồi và thay mọi token mặc định từ bản triển khai cũ, bao gồm token
Agent, token operator và token legacy. Frontend giữ token người dùng trong
bộ nhớ của tab và gửi Bearer token theo vai trò trên từng Agent.

```dotenv
NETWORK_AGENT_TOKENS='{"aws-debian-01":"<sha256-agent-token>"}'
NETWORK_OPERATORS='{"soc-admin":{"token_sha256":"<sha256-admin-token>","role":"admin","agents":["aws-debian-01"]},"soc-reader":{"token_sha256":"<sha256-reader-token>","role":"analyst","agents":["aws-debian-01"]}}'
NETWORK_LEGACY_ADMIN_TOKEN=<sha256-legacy-admin-token>
LARP_MANAGER_DEBUG=false
```

`NETWORK_LEGACY_ADMIN_TOKEN` bảo vệ các API ghi cũ và API đọc command/audit
cũ. Gửi token legacy qua client quản trị đã xác thực để gọi các API đó.
Token Network theo từng Agent chỉ có hiệu lực trong module Network.

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
LARP_NETWORK_AGENT_TOKEN=<agent-token>
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

Mặc định module chỉ đọc. Chuẩn bị ngoài băng trên một endpoint thử nghiệm
và giữ một phiên console mở trong toàn bộ quá trình cài đặt.

1. Kiểm tra socket SSH đang lắng nghe bằng `sudo ss -H -ltnpe`. Agent
   tự phát hiện cổng từ `sshd` hoặc `ssh.socket` đang chạy và từ chối cấu hình
   không xác định được một cổng quản trị duy nhất. `LARP_UFW_SSH_PORT` là
   giá trị đối chiếu tùy chọn.
2. Cho phép IP nguồn thực tế của Manager và các IP/CIDR quản trị trong AWS
   Security Group. Manager cần kết nối trực tiếp tới cùng socket SSH từ
   mạng khôi phục đã phê duyệt. URL Tunnel của dashboard không thay thế
   đường SSH này.
3. Trên endpoint, cấp một khóa SSH chuyên dụng cho tài khoản không có quyền
   sudo. Dùng mục `authorized_keys` giới hạn theo nguồn và buộc chạy lệnh
   kiểm tra. Dùng địa chỉ nguồn mà SSH ghi nhận trên chính endpoint.

   ```text
   from="<manager-egress-cidr>",restrict,command="/usr/bin/printenv SSH_CONNECTION" ssh-ed25519 <probe-public-key>
   ```

4. Trên Manager, cấu hình đích SSH cố định và mount thư mục chứa khóa ở chế
   độ chỉ đọc vào `/run/larp-ssh-probes`. Cổng configured phải trùng với
   cổng sshd trên endpoint. Ghi host key đã xác thực qua console vào
   `known_hosts` với tên `larp-<agent-id>`.

   ```dotenv
   NETWORK_SSH_PROBES='{"aws-debian-01":{"host":"<endpoint-direct-ssh-host>","port":2222,"user":"larp-probe"}}'
   ```

   ```text
   /run/larp-ssh-probes/aws-debian-01/key
   /run/larp-ssh-probes/aws-debian-01/known_hosts
   larp-aws-debian-01 ssh-ed25519 <verified-host-public-key>
   ```

   Khóa riêng cần quyền 0600 và phải được người dùng của Manager đọc được.
   Ví dụ override Compose lưu cục bộ ngoài version control.

   ```yaml
   services:
     manager:
       volumes:
         - /path/to/probe-secrets:/run/larp-ssh-probes:ro
   ```

5. Trên endpoint, đặt các rule bên dưới ở **đầu mỗi chain tương ứng** trong
   `/etc/ufw/before.rules` và `/etc/ufw/before6.rules`, sau khai báo chain.
   Giữ các rule hiện có phía sau. Thêm một dòng SSH cho mỗi CIDR đã duyệt
   thuộc đúng họ địa chỉ, gồm cả CIDR của Manager. Ví dụ IPv4 với SSH
   2222 và Manager HTTPS 443.

   ```text
   -A ufw-before-input -s 192.0.2.9/32 -p tcp --dport 2222 -j ACCEPT
   -A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   -A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   -A ufw-before-output -p udp --dport 53 -j ACCEPT
   -A ufw-before-output -p tcp --dport 53 -j ACCEPT
   -A ufw-before-output -p tcp --dport 443 -j ACCEPT
   ```

   Dùng tiền tố `ufw6-before-` trong tệp IPv6. Chỉ thêm dòng SSH IPv6 khi có
   CIDR IPv6 được duyệt. Dùng cổng HTTPS thực tế của Manager cho dòng cuối.
   Manager có thể thay IP khi DNS thay đổi. Profile yêu cầu iptables-nft,
   `MANAGE_BUILTINS=no`, IPv6 bật và mặc định outbound ACCEPT. Nếu dùng
   sysctl riêng qua UFW, chuyển các giá trị cần giữ vào cấu hình sysctl
   của OS, áp dụng và kiểm chứng qua console, rồi để
   `/etc/ufw/sysctl.conf` chỉ chứa chú thích. Các hook UFW thực thi,
   chain filter độc lập, containment, hoặc rule phức tạp cần quản trị cục bộ.
   Docker NAT độc lập được giữ nguyên. Các thao tác đổi default policy
   thực hiện cục bộ vì UFW sẽ ghi lại cả các tệp after-rules đã duyệt.

6. Sau khi duyệt cấu hình, lấy fingerprint và điền `network.env`.

   ```bash
   sudo /opt/larp-agent/venv/bin/python /opt/larp-agent/firewall_control.py fingerprint
   sudoedit /etc/larp-agent/network.env
   ```

   ```dotenv
   LARP_UFW_CONTROL=1
   LARP_UFW_STATIC_SHA256=<reviewed-static-ufw-fingerprint>
   LARP_UFW_SSH_CIDRS=192.0.2.9/32
   LARP_UFW_ROLLBACK_SECONDS=60
   ```

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable larp-firewall-recover.service
   sudo systemctl enable --now larp-firewall-rollback.timer
   sudo systemctl restart larp-agent.service
   sudo systemctl status larp-firewall-rollback.timer --no-pager
   ```

   Từ thư mục gốc trên Manager, áp dụng override SSH verifier.

   ```bash
   docker compose -f docker-compose.yml -f compose.ssh-probe.yml up -d --build manager frontend
   docker compose logs --tail 50 manager
   ```

### Nghiệm thu giao dịch

1. Đối chiếu **Refresh** với `sudo ufw status verbose`, `ss -H -ltnpe` và
   `ip -j route show table all`. Xác nhận analyst chỉ có quyền đọc và refresh.
2. Dùng token admin để gửi một thay đổi đã duyệt trên endpoint thử nghiệm.
   Trước khi ghi, Agent yêu cầu khôi phục lúc boot, timer độc lập đã chạy
   thành công và SSH xác thực từ Manager. Manager cũng phải thấy WebSocket
   Agent đang mở. Thời hạn commit là **60 giây từ trước thao tác ghi đầu tiên**.
3. Sau khi Agent xác nhận áp dụng, mở phiên SSH mới từ IP/CIDR đã duyệt
   với `ssh -o ControlMaster=no -o ControlPath=none`. Chạy lệnh sau với ID
   giao dịch, sau đó bấm **Commit change** và nhập lý do.

   ```bash
   sudo --preserve-env=SSH_CONNECTION /bin/bash -c 'set -a; . /etc/larp-agent/network.env; set +a; exec /opt/larp-agent/venv/bin/python /opt/larp-agent/firewall_control.py approve "$1"' _ TRANSACTION_ID
   ```

4. Thử hết hạn và mất kết nối trên endpoint thử nghiệm. Khi chưa commit,
   mất WebSocket hoặc mất phiên SSH mới từ Manager kích hoạt rollback.
   Khởi động lại trong lúc đang chờ commit sẽ phục hồi các tệp UFW trước
   khi unit UFW khởi động. Đối chiếu trạng thái và bản ghi Audit History.

### Khôi phục khẩn cấp từ AWS console

Dùng kênh quản trị ngoài băng đã cấu hình nếu SSH thất bại.

```bash
sudo systemctl stop larp-agent.service larp-firewall-apply.service
sudo systemctl start larp-firewall-rollback.service
sudo journalctl -u larp-firewall-apply.service -u larp-firewall-rollback.service -u larp-firewall-recover.service -n 100 --no-pager
sudo ss -H -ltnpe
sudo ufw status verbose
```

Nếu trạng thái là `rollback_failed`, giữ Agent dừng và đặt
`LARP_UFW_CONTROL=0` trong `network.env`. Đối chiếu bản sao root-only tại
`/var/lib/larp-agent/firewall-transaction.json` với cấu hình và journal.
Khôi phục các tệp UFW đã xác nhận từ bản sao phù hợp bằng console, hoặc
sửa duy nhất đường quản trị SSH từ CIDR đã duyệt. Xác nhận một phiên SSH
mới và kết nối Manager trước khi chạy lại Agent. Tránh reset hoặc flush
toàn bộ firewall và giữ nguyên các policy Docker, containment và policy
cấu hình tay.

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
  `set_logging`, `commit` hoặc `rollback`.
- `GET /api/v1/network/agents/{agent_id}/commands/{command_id}`.
- Agent gửi `NETWORK_SNAPSHOT`, `NETWORK_ACK` và `NETWORK_TRANSACTION`
  qua `/ws/agent`. Manager giao `network_command` trong phản hồi heartbeat,
  hạn giao 45 giây và không tự động gửi lại.

Định hướng kết nối được ghi nhận khi quan sát được bắt tay TCP. Socket được
ghép với tiến trình khi xác minh được inode và thời điểm tạo tiến trình.
ASN hiện dùng bảng CIDR tham chiếu cục bộ. Bằng chứng DNS được để trống khi
telemetry chỉ có câu hỏi DNS. Sự kiện DROP/REJECT là dữ liệu quan sát firewall.
