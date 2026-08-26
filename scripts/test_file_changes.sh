#!/usr/bin/env bash
# ==============================================================================
# Rule: FileChangesRule
# Description: Kích hoạt cảnh báo File Modification Volume Anomaly (tạo 40 file thay đổi trong /tmp)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
FILE_COUNT=40

echo "[+] [FileChangesRule] Bắt đầu mô phỏng lượng thay đổi file gia tăng ($FILE_COUNT files)..."

cleanup() {
    echo -e "\n[+] Dọn dẹp các file thay đổi thử nghiệm trong /tmp..."
    rm -f /tmp/test_change_*.bak
}
trap cleanup EXIT INT TERM

echo "[+] Tạo $FILE_COUNT file mẫu .bak trong /tmp..."
for i in $(seq 1 $FILE_COUNT); do
    echo "Telemetry file modification test line $i" > "/tmp/test_change_$i.bak"
done

echo "[+] Đã tạo $FILE_COUNT file. Duy trì trạng thái trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [FileChangesRule] Mô phỏng kết thúc thành công."
