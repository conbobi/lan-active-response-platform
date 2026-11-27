#!/usr/bin/env bash
# ==============================================================================
# LARP EDR – bring the VPS up from this checkout.
#
#   cd ~/larp && git pull --ff-only && sudo bash vps_up.sh
#
# What it does (idempotent, safe to run again):
#   1. Copies agent/ (Agent + vulnerable_web) into /opt/larp-agent.
#   2. Creates the venv / installs requirements only when requirements.txt changed.
#   3. Installs the systemd units from agent/ (only rewritten when they changed).
#   4. Enables + starts tailscaled, vulnerable-web and larp-agent, restarting the two
#      LARP services so they run the code just pulled.
#   5. Checks each service and prints what is wrong, if anything.
#
# What it never does: change firewall rules or the UFW units' enablement, run
# `tailscale up` over an already-connected node, print secrets from network.env.
#
# Options (environment variables):
#   TS_AUTHKEY=tskey-...        log this node into Tailscale if it is logged out
#   LARP_INSTALL_TAILSCALE=1    install Tailscale from tailscale.com if missing
#   LARP_SKIP_WEB=1             do not start the vulnerable web app
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo -E bash "$0" "$@"
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$REPO/agent"
TARGET=/opt/larp-agent
ENV_FILE=/etc/larp-agent/network.env
UNITS=(larp-agent.service vulnerable-web.service larp-firewall-apply.service
       larp-firewall-recover.service larp-firewall-rollback.service larp-firewall-rollback.timer)

step() { printf '\n\033[1;36m[%s] %s\033[0m\n' "$1" "$2"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
WARNINGS=0
FAILURES=0

[[ -f "$SRC/agent.py" && -f "$SRC/larp-agent.service" ]] || {
    echo "Không thấy $SRC/agent.py: chạy script từ trong repo larp." >&2; exit 1; }

# ------------------------------------------------------------------------------
step 1/6 "Gói hệ thống"
missing=()
for pkg in rsync python3 python3-venv python3-pip curl; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
# yara-python needs headers and a compiler only when it has to build a wheel.
dpkg -s libyara-dev >/dev/null 2>&1 || missing+=(libyara-dev build-essential)
if ((${#missing[@]})); then
    echo "  Cài: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}"
fi
ok "đủ gói cần thiết"

# ------------------------------------------------------------------------------
step 2/6 "Đồng bộ mã nguồn → $TARGET (commit $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo '?'))"
mkdir -p "$TARGET" /var/log/vulnerable_web
rsync -a --checksum --itemize-changes \
    --exclude='venv/' --exclude='__pycache__/' --exclude='*.pyc' --exclude='.pytest_cache/' \
    --exclude='.env' --exclude='.git/' --exclude='testdata/' --exclude='test_*.py' \
    "$SRC/" "$TARGET/" > /tmp/larp-rsync.log
sed 's/^/  /' /tmp/larp-rsync.log | head -40 || true
touch /var/log/vulnerable_web/auth.log /var/log/vulnerable_web/access.log
ok "mã nguồn đã đồng bộ"

# ------------------------------------------------------------------------------
step 3/6 "Python venv"
if [[ ! -x "$TARGET/venv/bin/python" ]]; then
    python3 -m venv "$TARGET/venv"
fi
stamp="$TARGET/venv/.requirements.sha256"
want="$(sha256sum "$TARGET/requirements.txt" | cut -d' ' -f1)"
if [[ "$(cat "$stamp" 2>/dev/null)" != "$want" ]]; then
    "$TARGET/venv/bin/pip" install -q --upgrade pip setuptools wheel
    "$TARGET/venv/bin/pip" install -q -r "$TARGET/requirements.txt"
    echo "$want" > "$stamp"
    ok "đã cài requirements"
else
    ok "requirements không đổi, bỏ qua pip"
fi

# ------------------------------------------------------------------------------
step 4/6 "Systemd units"
changed=0
for unit in "${UNITS[@]}"; do
    if ! cmp -s "$SRC/$unit" "/etc/systemd/system/$unit"; then
        install -m 0644 "$SRC/$unit" "/etc/systemd/system/$unit"
        echo "  cập nhật $unit"
        changed=1
    fi
done
((changed)) && systemctl daemon-reload
ok "units đã cài (firewall units chỉ được cài, không bật/tắt)"

install -d -m 0700 /etc/larp-agent
[[ -e "$ENV_FILE" ]] || install -m 0600 /dev/null "$ENV_FILE"
for key in AGENT_ID LARP_NETWORK_AGENT_TOKEN; do
    grep -q "^${key}=." "$ENV_FILE" || warn "$ENV_FILE thiếu $key (Agent có thể không xác thực được với Manager)"
done

# ------------------------------------------------------------------------------
step 5/6 "Tailscale"
if ! command -v tailscale >/dev/null 2>&1; then
    if [[ "${LARP_INSTALL_TAILSCALE:-0}" == "1" ]]; then
        curl -fsSL https://tailscale.com/install.sh | sh
    else
        fail "chưa cài Tailscale. Chạy lại với LARP_INSTALL_TAILSCALE=1 để cài."
    fi
fi
if command -v tailscale >/dev/null 2>&1; then
    systemctl enable --now tailscaled >/dev/null 2>&1
    backend="$(tailscale status --json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("BackendState",""))' 2>/dev/null || true)"
    if [[ "$backend" == "Running" ]]; then
        ok "tailscale đang chạy, IP $(tailscale ip -4 2>/dev/null | head -1)"
    elif [[ -n "${TS_AUTHKEY:-}" ]]; then
        tailscale up --auth-key="$TS_AUTHKEY" --ssh=false
        ok "tailscale đã đăng nhập, IP $(tailscale ip -4 2>/dev/null | head -1)"
    else
        warn "tailscaled chạy nhưng node chưa đăng nhập (trạng thái: ${backend:-không rõ}). Chạy: sudo tailscale up"
    fi
fi

# ------------------------------------------------------------------------------
step 6/6 "Dịch vụ LARP"
services=(larp-agent)
[[ "${LARP_SKIP_WEB:-0}" == "1" ]] || services=(vulnerable-web larp-agent)
for svc in "${services[@]}"; do
    systemctl enable "$svc" >/dev/null 2>&1
    systemctl restart "$svc"
done
sleep 5
for svc in tailscaled "${services[@]}"; do
    if systemctl is-active --quiet "$svc"; then
        ok "$svc: active (enabled: $(systemctl is-enabled "$svc" 2>/dev/null))"
    else
        fail "$svc: $(systemctl is-active "$svc" 2>/dev/null)"
        journalctl -u "$svc" -n 15 --no-pager | sed 's/^/      /'
    fi
done
if [[ " ${services[*]} " == *" vulnerable-web "* ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:5000/ || true)"
    [[ "$code" =~ ^[23] ]] && ok "web trả HTTP $code trên cổng 5000" || fail "web không trả lời trên cổng 5000 (HTTP ${code:-none})"
fi
echo "  Log Agent gần nhất:"
journalctl -u larp-agent --since "-20s" -n 8 --no-pager -o cat | sed 's/^/      /'

echo
if ((FAILURES)); then
    printf '\033[31mXONG VỚI %d LỖI, %d CẢNH BÁO.\033[0m Xem log ở trên.\n' "$FAILURES" "$WARNINGS"
    exit 1
fi
printf '\033[32mXONG.\033[0m %d cảnh báo. Theo dõi: journalctl -u larp-agent -f\n' "$WARNINGS"
