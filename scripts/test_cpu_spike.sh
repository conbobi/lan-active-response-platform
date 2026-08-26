#!/usr/bin/env bash
# ==============================================================================
# Rule: CpuSpikeRule
# Description: Kích hoạt cảnh báo CPU Spike Anomaly bằng cách tải CPU trên 85%
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
echo "[+] [CpuSpikeRule] Bắt đầu mô phỏng CPU spike trong ${DURATION} giây..."

# Tự động kiểm tra và cài đặt 'stress' nếu thiếu (yêu cầu apt-get/sudo nếu có)
if ! command -v stress >/dev/null 2>&1; then
    echo "[!] Không tìm thấy công cụ 'stress'. Đang thử cài đặt tự động..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y >/dev/null 2>&1 && sudo apt-get install -y stress >/dev/null 2>&1
    fi
fi

cleanup() {
    echo -e "\n[+] Dọn dẹp các tiến trình CPU spike..."
    pkill -f "stress --cpu" 2>/dev/null || true
    pkill -f "cpu_burn_worker" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if command -v stress >/dev/null 2>&1; then
    echo "[+] Đang chạy stress trên tất cả các nhân CPU..."
    stress --cpu $(nproc 2>/dev/null || echo 4) --timeout ${DURATION}
else
    echo "[!] Sử dụng Python fallback để đẩy tải CPU lên cao..."
    python3 -c "
import multiprocessing, time
def cpu_burn_worker():
    end = time.time() + ${DURATION}
    while time.time() < end:
        _ = 2 ** 20000

if __name__ == '__main__':
    procs = [multiprocessing.Process(target=cpu_burn_worker) for _ in range(multiprocessing.cpu_count())]
    for p in procs: p.start()
    for p in procs: p.join()
"
fi

echo "[+] [CpuSpikeRule] Mô phỏng kết thúc thành công."
