#!/usr/bin/env bash
# ==============================================================================
# Helper Script to sync & deploy LARP Agent + Vulnerable Web to AWS VPS
# Usage:
#   bash deploy_to_vps.sh [VPS_PUBLIC_IP]
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${SSH_KEY:-$HOME/.ssh/key-debian-aws.pem}"
VPS_USER="${VPS_USER:-admin}"
VPS_HOST="${1:-16.179.108.233}"

echo "=============================================================================="
echo " LARP EDR VPS DEPLOYMENT TOOL"
echo " Target VPS: $VPS_USER@$VPS_HOST"
echo " Key File:   $KEY_FILE"
echo "=============================================================================="

if [ ! -f "$KEY_FILE" ]; then
    echo "[-] Không tìm thấy file khóa SSH tại: $KEY_FILE"
    echo "    Vui lòng kiểm tra lại đường dẫn file .pem"
    exit 1
fi

chmod 400 "$KEY_FILE" 2>/dev/null || true

echo "[1/3] Kiểm tra kết nối SSH tới $VPS_USER@$VPS_HOST..."
if ! ssh -i "$KEY_FILE" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" "echo '[+] Kết nối SSH thành công!'" ; then
    echo "[-] Không thể kết nối SSH tới $VPS_HOST:22."
    echo "    Gợi ý:"
    echo "    1. Kiểm tra lại IP public hiện tại của máy ảo AWS EC2."
    echo "    2. Kiểm tra AWS Security Group xem cổng 22 đã mở cho IP máy của bạn chưa."
    exit 1
fi

echo "[2/3] Đồng bộ thư mục agent lên $VPS_USER@$VPS_HOST:~/agent/..."
ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" "mkdir -p ~/agent"
rsync -avz --delete \
    --exclude="venv" \
    --exclude="__pycache__" \
    --exclude=".pytest_cache" \
    -e "ssh -i $KEY_FILE -o StrictHostKeyChecking=no" \
    "$SCRIPT_DIR/" "$VPS_USER@$VPS_HOST:~/agent/"

echo "[3/3] Tiến hành cài đặt và kích hoạt systemd service trên VPS..."
ssh -t -i "$KEY_FILE" -o StrictHostKeyChecking=no "$VPS_USER@$VPS_HOST" \
    "cd ~/agent && sudo bash setup_vps.sh"

echo "[✓] Triển khai hoàn tất trên VPS!"

