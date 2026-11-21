#!/usr/bin/env bash
# ==============================================================================
# LARP EDR Linux Agent & Vulnerable Web Setup Script for AWS Debian/Ubuntu VPS
# ==============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Vui lòng chạy script với quyền root hoặc sudo: sudo bash $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/larp-agent"

echo "=============================================================================="
echo " [1/5] Cập nhật hệ thống & Cài đặt gói phụ thuộc trên Debian/Ubuntu..."
echo "=============================================================================="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libyara-dev \
    ufw \
    iptables \
    procps \
    net-tools \
    curl \
    sqlite3 \
    tcpdump

echo "=============================================================================="
echo " [2/5] Thiết lập thư mục cài đặt /opt/larp-agent & log telemetry..."
echo "=============================================================================="
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/vulnerable_web"
mkdir -p "$INSTALL_DIR/commands"
mkdir -p /var/log/vulnerable_web

# Đồng bộ file từ thư mục chạy hiện tại vào /opt/larp-agent
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    echo "[*] Sao chép mã nguồn từ $SCRIPT_DIR vào $INSTALL_DIR..."
    cp -r "$SCRIPT_DIR"/*.py "$INSTALL_DIR/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/commands/* "$INSTALL_DIR/commands/" 2>/dev/null || true
    cp -r "$SCRIPT_DIR"/vulnerable_web/* "$INSTALL_DIR/vulnerable_web/" 2>/dev/null || true
    cp "$SCRIPT_DIR"/requirements.txt "$INSTALL_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR"/*.service "$INSTALL_DIR/" 2>/dev/null || true
fi

# Chuẩn bị file log cho web & auth monitoring
touch /var/log/vulnerable_web/auth.log
touch /var/log/vulnerable_web/access.log
touch /tmp/web_auth.log
touch /tmp/web_access.log
chmod -R 777 /var/log/vulnerable_web
chmod 666 /tmp/web_auth.log /tmp/web_access.log

echo "=============================================================================="
echo " [3/5] Khởi tạo Python Virtual Environment & cài đặt thư viện..."
echo "=============================================================================="
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi

"$INSTALL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "=============================================================================="
echo " [4/5] Đăng ký Systemd Services (larp-agent & vulnerable-web)..."
echo "=============================================================================="
cp "$INSTALL_DIR/larp-agent.service" /etc/systemd/system/larp-agent.service
cp "$INSTALL_DIR/vulnerable-web.service" /etc/systemd/system/vulnerable-web.service

systemctl daemon-reload

echo "[*] Kích hoạt và khởi động dịch vụ Vulnerable Web (port 5000)..."
systemctl enable vulnerable-web
systemctl restart vulnerable-web

echo "[*] Kích hoạt và khởi động dịch vụ LARP EDR Linux Agent..."
systemctl enable larp-agent
systemctl restart larp-agent

echo "=============================================================================="
echo " [5/5] Kiểm tra trạng thái dịch vụ..."
echo "=============================================================================="
sleep 2

echo "--- [Trạng thái Vulnerable Web] ---"
systemctl status vulnerable-web --no-pager -n 5 || true

echo ""
echo "--- [Trạng thái LARP Agent] ---"
systemctl status larp-agent --no-pager -n 5 || true

echo ""
echo "=============================================================================="
echo " HOÀN TẤT TRIỂN KHAI TRÊN VPS!"
echo " - Vulnerable Web: Đang lắng nghe trên cổng 0.0.0.0:5000"
echo " - LARP Agent: Kết nối tới Manager: wss://edr.alwayready.id.vn/ws/agent"
echo " - Xem log Agent:         journalctl -u larp-agent -f"
echo " - Xem log Web App:       journalctl -u vulnerable-web -f"
echo " - Xem log HTTP Access:   tail -f /var/log/vulnerable_web/access.log"
echo "=============================================================================="
