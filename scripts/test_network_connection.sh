#!/usr/bin/env bash
# ==============================================================================
# Rule: NetworkConnectionRule
# Description: Kích hoạt cảnh báo Network Connection bằng cách mở listener trên cổng bất thường (8080)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
PORT=8080

echo "[+] [NetworkConnectionRule] Bắt đầu mô phỏng kết nối mạng đáng ngờ trên cổng $PORT..."

cleanup() {
    echo -e "\n[+] Đóng socket listener trên cổng $PORT..."
    pkill -f "python3 -m http.server $PORT" 2>/dev/null || true
    pkill -f "nc -l.* $PORT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if command -v python3 >/dev/null 2>&1; then
    echo "[+] Khởi chạy HTTP Server listener trên cổng $PORT..."
    python3 -m http.server $PORT >/dev/null 2>&1 &
elif command -v nc >/dev/null 2>&1; then
    echo "[+] Khởi chạy netcat listener trên cổng $PORT..."
    nc -lvp $PORT >/dev/null 2>&1 &
fi

echo "[+] Listener đang hoạt động trên cổng $PORT trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [NetworkConnectionRule] Mô phỏng kết thúc thành công."
