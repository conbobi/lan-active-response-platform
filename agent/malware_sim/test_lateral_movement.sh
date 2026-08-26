#!/usr/bin/env bash
# ==============================================================================
# Rule: LateralMovementRule
# Description: Kích hoạt cảnh báo Lateral Movement Activity (dò quét các cổng quản trị nội bộ 445 SMB, 135 RPC, 3389 RDP)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
TARGET_IP="127.0.0.1"

echo "[+] [LateralMovementRule] Bắt đầu mô phỏng di chuyển ngang (Port Sweep trên $TARGET_IP)..."

cleanup() {
    echo -e "\n[+] Dọn dẹp tiến trình di chuyển ngang..."
    pkill -f "nmap.*445" 2>/dev/null || true
    pkill -f "smb_sweep" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(
    end=$((SECONDS + DURATION))
    while [ $SECONDS -lt $end ]; do
        echo "[+] Dò quét các cổng quản trị nội bộ (445 SMB, 135 RPC, 3389 RDP)..."
        if command -v nmap >/dev/null 2>&1; then
            nmap -p 445,135,3389 "$TARGET_IP" >/dev/null 2>&1 || true
        else
            nc -zv -w 1 "$TARGET_IP" 445 2>&1 || true
            nc -zv -w 1 "$TARGET_IP" 135 2>&1 || true
            nc -zv -w 1 "$TARGET_IP" 3389 2>&1 || true
        fi
        sleep 10
    done
) &
SWEEP_PID=$!

echo "[+] Tiến trình quét di chuyển ngang (PID: $SWEEP_PID) đang chạy trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [LateralMovementRule] Mô phỏng kết thúc thành công."
