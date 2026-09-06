#!/usr/bin/env bash
#
# VPNgate Proxy Pool - one-shot VPS deploy for the pool (multi-port SOCKS5) mode.
#
# Architecture agnostic: auto-detects x86_64/amd64 and aarch64/arm64, installs
# the matching Go toolchain and builds with CGO_ENABLED=0, so the same script
# works on both Intel/AMD and ARM VPSes. The compiled binary is NOT portable
# between architectures - it is always built on the target machine.
#
# Usage (as root):
#   git clone https://github.com/shenping1200/VPNgate-proxy.git
#   cd VPNgate-proxy/deploy
#   ./deploy-vps.sh
#
# Everything is overridable through environment variables, e.g.:
#   POOL_START_PORT=39528 POOL_MAX_PORTS=60 PROXY_PASS='s3cret' ./deploy-vps.sh
#
set -euo pipefail

# ---------------------------------------------------------------- configuration
REPO="${REPO:-https://github.com/shenping1200/VPNgate-proxy.git}"
REF="${REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vpngate-proxy}"
BIN="${BIN:-/usr/local/bin/vpngate-proxy}"
DATA_DIR="${DATA_DIR:-/var/lib/vpngate-proxy}"
UNIT_PATH="${UNIT_PATH:-/etc/systemd/system/vpngate-pool.service}"
CREDS_FILE="${CREDS_FILE:-/root/vpngate-pool.creds}"

POOL_START_PORT="${POOL_START_PORT:-39528}"
POOL_MAX_PORTS="${POOL_MAX_PORTS:-200}"
POOL_ROTATE_PORT="${POOL_ROTATE_PORT:-41111}"
POOL_WEB_PORT="${POOL_WEB_PORT:-39527}"
PROXY_USER="${PROXY_USER:-vpnuser}"
PROXY_PASS="${PROXY_PASS:-}"
WEB_USER="${WEB_USER:-admin}"
WEB_PASS="${WEB_PASS:-}"
GO_VER="${GO_VER:-1.23.4}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG="/var/log/vpngate-pool.log"

usage() {
    sed -n '2,17p' "$0" | sed 's/^#\{1,2\} \{0,1\}//'
    exit 0
}
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

gen_pass() {
    head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16
}

# ------------------------------------------------------------------ preconditions
[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"

say "step 1/7 architecture"
case "$(uname -m)" in
    x86_64|amd64)   GOARCH="amd64" ;;
    aarch64|arm64)  GOARCH="arm64" ;;
    *)              die "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
esac
echo "    $(uname -m) -> GOARCH=$GOARCH"

# ------------------------------------------------------------------- dependencies
say "step 2/7 system packages"
install_pkgs() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y openvpn git ca-certificates curl wget >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y openvpn git ca-certificates curl wget >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openvpn git ca-certificates curl wget >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache openvpn git ca-certificates curl wget >/dev/null 2>&1
    else
        die "no supported package manager (need apt-get, dnf, yum or apk)"
    fi
}
install_pkgs
command -v openvpn >/dev/null 2>&1 || die "openvpn did not install"
OPENVPN="$(command -v openvpn)"
echo "    openvpn -> $OPENVPN"

# TUN is required: every pool slot needs its own tun device.
if [ ! -e /dev/net/tun ]; then
    modprobe tun 2>/dev/null || true
fi
if [ ! -e /dev/net/tun ]; then
    warn "/dev/net/tun missing - OpenVPN cannot create tun devices."
    warn "On OpenVZ/LXC containers ask your provider to enable TUN."
else
    echo "    /dev/net/tun ok"
fi

# ----------------------------------------------------------------------------- go
say "step 3/7 go toolchain"
export PATH="/usr/local/go/bin:$PATH"
if ! command -v go >/dev/null 2>&1 || [ "$(go version 2>/dev/null | awk '{print $3}')" != "go${GO_VER}" ]; then
    echo "    installing go${GO_VER}.linux-${GOARCH}"
    curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tgz
    rm -f /tmp/go.tgz
fi
echo "    $(go version)"
# go.mod pins a newer toolchain; GOTOOLCHAIN=auto fetches it on demand.
export GOTOOLCHAIN=auto
export CGO_ENABLED=0

# -------------------------------------------------------------------------- source
say "step 4/7 source"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "    updating $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --quiet origin "$REF" 2>/dev/null || true
    git -C "$INSTALL_DIR" checkout --quiet "$REF" 2>/dev/null || true
    git -C "$INSTALL_DIR" pull --ff-only --quiet 2>/dev/null || true
else
    echo "    cloning $REPO -> $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    git clone --quiet --branch "$REF" "$REPO" "$INSTALL_DIR"
fi
echo "    HEAD: $(git -C "$INSTALL_DIR" log --oneline -1)"

say "step 5/7 build"
( cd "$INSTALL_DIR" && go build -o "$BIN" ./cmd/free-proxy )
echo "    binary: $BIN ($(stat -c %s "$BIN") bytes)"

# -------------------------------------------------------------------------- unit
say "step 6/7 install service"
[ -n "$PROXY_PASS" ] || PROXY_PASS="$(gen_pass)"
[ -n "$WEB_PASS" ]   || WEB_PASS="$(gen_pass)"

TEMPLATE="$SCRIPT_DIR/vpngate-pool.service"
if [ -f "$TEMPLATE" ]; then
    sed -e "s|{{BIN}}|$BIN|g" \
        -e "s|{{DATA_DIR}}|$DATA_DIR|g" \
        -e "s|{{POOL_START_PORT}}|$POOL_START_PORT|g" \
        -e "s|{{POOL_MAX_PORTS}}|$POOL_MAX_PORTS|g" \
        -e "s|{{POOL_ROTATE_PORT}}|$POOL_ROTATE_PORT|g" \
        -e "s|{{POOL_WEB_PORT}}|$POOL_WEB_PORT|g" \
        -e "s|{{PROXY_USER}}|$PROXY_USER|g" \
        -e "s|{{PROXY_PASS}}|$PROXY_PASS|g" \
        -e "s|{{WEB_USER}}|$WEB_USER|g" \
        -e "s|{{WEB_PASS}}|$WEB_PASS|g" \
        -e "s|{{OPENVPN}}|$OPENVPN|g" \
        "$TEMPLATE" > "$UNIT_PATH"
else
    warn "$TEMPLATE not found - writing built-in unit"
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=VPNgate Proxy Pool (multi-port SOCKS5, one port per VPNGate node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN pool
Environment=FREE_PROXY_POOL_ENABLED=true
Environment=FREE_PROXY_POOL_START_PORT=$POOL_START_PORT
Environment=FREE_PROXY_POOL_MAX_PORTS=$POOL_MAX_PORTS
Environment=FREE_PROXY_POOL_ROTATE_ENABLED=true
Environment=FREE_PROXY_POOL_ROTATE_PORT=$POOL_ROTATE_PORT
Environment=FREE_PROXY_PROXY_USERNAME=$PROXY_USER
Environment=FREE_PROXY_PROXY_PASSWORD=$PROXY_PASS
Environment=FREE_PROXY_DATA_DIR=$DATA_DIR
Environment=FREE_PROXY_OPENVPN_COMMAND=$OPENVPN
Environment=FREE_PROXY_POOL_WEB_ENABLED=true
Environment=FREE_PROXY_POOL_WEB_HOST=0.0.0.0
Environment=FREE_PROXY_POOL_WEB_PORT=$POOL_WEB_PORT
Environment=FREE_PROXY_POOL_WEB_USERNAME=$WEB_USER
Environment=FREE_PROXY_POOL_WEB_PASSWORD=$WEB_PASS
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi

mkdir -p "$DATA_DIR"
cat > "$CREDS_FILE" <<EOF
# generated by deploy-vps.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
proxy_socks5_user=$PROXY_USER
proxy_socks5_pass=$PROXY_PASS
web_user=$WEB_USER
web_pass=$WEB_PASS
EOF
chmod 600 "$CREDS_FILE"

HAVE_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAVE_SYSTEMD=1
fi

if [ "$HAVE_SYSTEMD" = "1" ]; then
    systemctl daemon-reload
    systemctl enable vpngate-pool >/dev/null 2>&1
    systemctl restart vpngate-pool
    sleep 3
    echo "    systemctl: $(systemctl is-active vpngate-pool)"
else
    warn "systemd not available - falling back to nohup (no auto-restart, no boot start)"
    pkill -f "vpngate-proxy pool" 2>/dev/null || true
    set -a
    FREE_PROXY_POOL_ENABLED=true
    FREE_PROXY_POOL_START_PORT="$POOL_START_PORT"
    FREE_PROXY_POOL_MAX_PORTS="$POOL_MAX_PORTS"
    FREE_PROXY_POOL_ROTATE_ENABLED=true
    FREE_PROXY_POOL_ROTATE_PORT="$POOL_ROTATE_PORT"
    FREE_PROXY_PROXY_USERNAME="$PROXY_USER"
    FREE_PROXY_PROXY_PASSWORD="$PROXY_PASS"
    FREE_PROXY_DATA_DIR="$DATA_DIR"
    FREE_PROXY_OPENVPN_COMMAND="$OPENVPN"
    FREE_PROXY_POOL_WEB_ENABLED=true
    FREE_PROXY_POOL_WEB_HOST=0.0.0.0
    FREE_PROXY_POOL_WEB_PORT="$POOL_WEB_PORT"
    FREE_PROXY_POOL_WEB_USERNAME="$WEB_USER"
    FREE_PROXY_POOL_WEB_PASSWORD="$WEB_PASS"
    set +a
    nohup "$BIN" pool > "$LOG" 2>&1 &
    sleep 3
    echo "    pid $!"
fi

# ------------------------------------------------------------------------ report
say "step 7/7 summary"
VPS_IP="$(curl -s --max-time 8 https://api.ipify.org || echo '<unknown>')"
cat <<EOF

  architecture ....... $(uname -m) (GOARCH=$GOARCH)
  source ............. $INSTALL_DIR
  binary ............. $BIN
  systemd unit ....... $UNIT_PATH
  credentials ........ $CREDS_FILE

  rotating port ...... socks5://$VPS_IP:$POOL_ROTATE_PORT   (empty username = round-robin)
  fixed pool ports ... socks5://$VPS_IP:$POOL_START_PORT ... (+$POOL_MAX_PORTS)
  web panel .......... http://$VPS_IP:$POOL_WEB_PORT
  proxy auth ......... $PROXY_USER / $PROXY_PASS
  web auth ........... $WEB_USER / $WEB_PASS

  verify egress (IP should change between calls):
    curl -x socks5://$VPS_IP:$POOL_ROTATE_PORT https://api.ipify.org

  live logs:
    journalctl -u vpngate-pool -f

  note: slots take a few minutes to fill; the pool keeps repairing dead
  tunnels on its own. Each device (fpxNNN) gets its own policy routing
  table, so nothing is added to the host's main routing table.
EOF
