#!/usr/bin/env bash
# ==============================================================================
# Rule: ShadowCopyRule
# Description: Kích hoạt cảnh báo Shadow Copy Deletion (thực thi lệnh vssadmin delete shadows)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70

echo "[+] [ShadowCopyRule] Bắt đầu mô phỏng xóa Volume Shadow Copy..."

cleanup() {
    echo -e "\n[+] Dọn dẹp tiến trình xóa shadow copy..."
    pkill -f "vssadmin delete shadows" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[+] Thực thi tiến trình chứa câu lệnh xóa Volume Shadow Copies..."
bash -c "exec -a 'vssadmin_sim' python3 -c 'import time; # vssadmin delete shadows /all /quiet; time.sleep(70)'" &

echo "[+] Tiến trình vssadmin giả lập đang chạy trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [ShadowCopyRule] Mô phỏng kết thúc thành công."
