#!/usr/bin/env bash
# ==============================================================================
# Rule: RegistryRule
# Description: Kích hoạt cảnh báo Suspicious Registry Modification (tạo thay đổi khóa persistence Run/RunOnce)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
MOCK_REG_FILE="/tmp/mock_registry_persistence.reg"

echo "[+] [RegistryRule] Bắt đầu mô phỏng sửa đổi Registry/cấu hình khởi động..."

cleanup() {
    echo -e "\n[+] Dọn dẹp file registry giả lập..."
    rm -f "$MOCK_REG_FILE"
    pkill -f "currentversion\\\\run" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[+] Ghi file registry giả lập persistence tại $MOCK_REG_FILE..."
cat << 'EOF' > "$MOCK_REG_FILE"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"BackdoorService"="C:\\Windows\\System32\\cmd.exe /c start /b malware.exe"
EOF

# Chạy tiến trình nền mang signature đường dẫn Registry Persistence
bash -c "exec -a 'reg_updater' python3 -c 'import time; # HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; time.sleep(70)'" &

echo "[+] Tiến trình sửa đổi registry giả lập đang duy trì trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [RegistryRule] Mô phỏng kết thúc thành công."
