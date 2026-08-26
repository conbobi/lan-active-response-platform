#!/usr/bin/env bash
# ==============================================================================
# Rule: ProcessChainRule
# Description: Kích hoạt cảnh báo Process Chain Anomaly (chrome -> python3 shell)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
PARENT_BIN="/tmp/chrome"

echo "[+] [ProcessChainRule] Bắt đầu mô phỏng chuỗi tiến trình bất thường (chrome -> python3)..."

cleanup() {
    echo -e "\n[+] Dọn dẹp chuỗi tiến trình..."
    pkill -f "$PARENT_BIN" 2>/dev/null || true
    rm -f "$PARENT_BIN"
}
trap cleanup EXIT INT TERM

# Tạo wrapper giả lập ứng dụng 'chrome' sinh tiến trình con python3
cat << 'EOF' > "$PARENT_BIN"
#!/usr/bin/env bash
# Simulating browser parent process spawning python shell
python3 -c "import time; time.sleep(70)"
EOF
chmod +x "$PARENT_BIN"

echo "[+] Thực thi tiến trình cha '$PARENT_BIN'..."
"$PARENT_BIN" &
PARENT_PID=$!

echo "[+] Tiến trình cha '$PARENT_BIN' (PID: $PARENT_PID) đã sinh tiến trình con. Duy trì trong ${DURATION}s..."
sleep $DURATION

echo "[+] [ProcessChainRule] Mô phỏng kết thúc thành công."
