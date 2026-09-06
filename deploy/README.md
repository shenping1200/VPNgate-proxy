# deploy/ - pool mode VPS deployment

One-shot deployment of the **pool** (multi-port SOCKS5) mode. Works on both
architectures - `x86_64/amd64` and `aarch64/arm64` - because the binary is
always compiled on the target machine (`CGO_ENABLED=0`, matching Go toolchain
picked automatically).

> `install.sh` in the repository root belongs to the **upstream single-tunnel**
> project: it downloads a prebuilt `free-proxy` binary from
> `masteralanlab/free-proxy` releases and runs `free-proxy install`. It does
> **not** deploy this fork's pool mode. Use the script in this directory.

## Quick start

```bash
git clone https://github.com/shenping1200/VPNgate-proxy.git
cd VPNgate-proxy/deploy
chmod +x deploy-vps.sh
./deploy-vps.sh          # must run as root
```

Requirements: root, `/dev/net/tun` (KVM / dedicated servers have it; OpenVZ or
LXC containers often do not), and outbound internet access.

## What it does

1. Detects architecture and maps it to a Go `GOARCH` (anything else aborts).
2. Installs `openvpn`, `git`, `curl`, `wget` via apt / dnf / yum / apk.
3. Installs Go `1.23.4` for the detected architecture if missing.
4. Clones (or updates) this repo into `/opt/vpngate-proxy`.
5. Builds `./cmd/free-proxy` into `/usr/local/bin/vpngate-proxy`.
6. Renders `vpngate-pool.service` into `/etc/systemd/system/` and starts it
   (`systemctl enable --now`-style, so it survives reboots and crashes).
   Without systemd it falls back to `nohup` and warns you.
7. Saves generated credentials to `/root/vpngate-pool.creds` (mode 600).

## Ports

| Purpose | Default | Override env |
| --- | --- | --- |
| Rotating port (round-robin / sticky per username) | `41111` | `POOL_ROTATE_PORT` |
| Fixed pool ports, one per node | `39528` and up | `POOL_START_PORT` |
| Number of pool ports | `200` | `POOL_MAX_PORTS` |
| Web panel | `39527` | `POOL_WEB_PORT` |

Port `39528 + N` maps to TUN device `fpx${100 + N}`.

## Common overrides

```bash
# smaller pool on a small VPS
POOL_MAX_PORTS=40 ./deploy-vps.sh

# keep known credentials instead of generating new ones
PROXY_USER=vpnuser PROXY_PASS='s3cret' WEB_PASS='panel-pass' ./deploy-vps.sh

# deploy a branch other than main
REF=my-branch ./deploy-vps.sh
```

Re-running the script is safe: it pulls the latest source, rebuilds and
restarts the service. Credentials are preserved only if you pass them
explicitly - otherwise new random ones are generated, so read
`/root/vpngate-pool.creds` again after each run.

## Troubleshooting

```bash
systemctl status vpngate-pool
journalctl -u vpngate-pool -f

# how many tunnels are actually up?
ls /sys/class/net | grep -c '^fpx'

# leftover policy-routing rules should be 0
ip rule show | grep -c detached
```

Each TUN device owns a private policy routing table (`9528` + slot offset);
the host's main routing table is never touched, so other services on the box
(sing-box, docker, ...) keep working.
