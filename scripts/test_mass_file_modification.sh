#!/usr/bin/env bash
# ==============================================================================
# Rule: MassFileModificationRule
# Description: Kích hoạt cảnh báo Mass File Modification (tạo 220 file .encrypted trong /tmp)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
FILE_COUNT=220

echo "[+] [MassFileModificationRule] Bắt đầu mô phỏng sửa đổi file hàng loạt ($FILE_COUNT files)..."

cleanup() {
    echo -e "\n[+] Dọn dẹp thư mục và các file mã hóa thử nghiệm..."
    rm -f /tmp/mass_enc_*.encrypted
}
trap cleanup EXIT INT TERM

echo "[+] Đang sinh $FILE_COUNT file đuôi .encrypted trong /tmp..."
for i in $(seq 1 $FILE_COUNT); do
    echo "Ransomware simulation mass file modification data line $i" > "/tmp/mass_enc_$i.encrypted"
done

echo "[+] Đã tạo thành công $FILE_COUNT file. Duy trì trạng thái trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [MassFileModificationRule] Mô phỏng kết thúc thành công."
