#!/usr/bin/env bash
# ==============================================================================
# Rule: CredentialDumpingRule
# Description: Kích hoạt cảnh báo Credential Dumping Activity (tạo /tmp/lsass.dump và lệnh sekurlsa/procdump)
# Duration: >= 60 giây (mặc định 70s)
# ==============================================================================

DURATION=70
DUMP_FILE="/tmp/lsass.dump"

echo "[+] [CredentialDumpingRule] Bắt đầu mô phỏng trích xuất thông tin xác thực..."

cleanup() {
    echo -e "\n[+] Dọn dẹp file dump credential và tiến trình liên quan..."
    rm -f "$DUMP_FILE"
    pkill -f "credential_dump" 2>/dev/null || true
    pkill -f "sekurlsa" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[+] Tạo file dump bộ nhớ giả lập: $DUMP_FILE"
cat << 'EOF' > "$DUMP_FILE"
=== MEMORY DUMP: LSASS.EXE (Simulated Mimikatz Output) ===
[00000000] Primary Credential Domain: LARP-NETWORK
[00000001] User: Administrator | NTLM: 32ed870724060c75b29fc2fb1a4e4b63
=== END OF DUMP ===
EOF

echo "[+] Thực thi tiến trình mang chữ ký lệnh credential dump (sekurlsa / procdump)..."
bash -c "exec -a 'credential_dump' python3 -c 'import time; # sekurlsa::logonpasswords lsass; time.sleep(70)'" &

echo "[+] Mô phỏng Credential Dumping đang duy trì trong ${DURATION} giây..."
sleep $DURATION

echo "[+] [CredentialDumpingRule] Mô phỏng kết thúc thành công."
