#!/usr/bin/env bash
# ==============================================================================
# Rule: InjectionRule
# Description: Kích hoạt cảnh báo Process Injection Anomaly bằng mô phỏng tiêm mã / memory tampering
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
PROC_NAME="/tmp/injected_process_sim"

echo "[+] [InjectionRule] Bắt đầu mô phỏng tiêm mã tiến trình (Process Injection)..."

cleanup() {
    echo -e "\n[+] Dọn dẹp tiến trình mô phỏng tiêm mã..."
    pkill -f "$PROC_NAME" 2>/dev/null || true
    rm -f "$PROC_NAME"
}
trap cleanup EXIT INT TERM

# Tạo script mô phỏng tiến trình bị tiêm mã trong ngữ cảnh hệ thống
cat << 'EOF' > "$PROC_NAME"
#!/usr/bin/env bash
# Simulating process with memory injection signature
python3 -c "import time, sys; sys.stdout.write('Injected process running context...\n'); time.sleep(70)"
EOF
chmod +x "$PROC_NAME"

echo "[+] Chạy tiến trình mục tiêu giả lập bị tiêm mã: $PROC_NAME"
"$PROC_NAME" &
PID=$!

echo "[+] Tiến trình (PID: $PID) đang hoạt động trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [InjectionRule] Mô phỏng kết thúc thành công."
