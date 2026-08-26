#!/usr/bin/env bash
# ==============================================================================
# Rule: SuspiciousProcessRule
# Description: Kích hoạt cảnh báo Suspicious Process bằng cách chạy tiến trình có tên độc hại (chisel)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
TARGET_BIN="/tmp/chisel"

echo "[+] [SuspiciousProcessRule] Bắt đầu mô phỏng tiến trình đáng ngờ (chisel)..."

# Tạo binary giả lập tên 'chisel' từ python3 hoặc bash
cp "$(which python3 2>/dev/null || which bash)" "$TARGET_BIN" 2>/dev/null || ln -sf "$(which bash)" "$TARGET_BIN"
chmod +x "$TARGET_BIN"

cleanup() {
    echo -e "\n[+] Dọn dẹp tiến trình đáng ngờ..."
    pkill -f "$TARGET_BIN" 2>/dev/null || true
    rm -f "$TARGET_BIN"
}
trap cleanup EXIT INT TERM

echo "[+] Thực thi tiến trình đáng ngờ: $TARGET_BIN"
"$TARGET_BIN" -c "import time; time.sleep($DURATION)" &
PROC_PID=$!

echo "[+] Tiến trình '$TARGET_BIN' (PID: $PROC_PID) đang chạy trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [SuspiciousProcessRule] Mô phỏng kết thúc thành công."
