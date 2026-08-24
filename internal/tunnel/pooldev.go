package tunnel

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/shenping1200/VPNgate-proxy/internal/domain"
)

// StartDevice brings up an OpenVPN tunnel on the given device for nodeID,
// independent of the manager's single "active" tunnel. It returns the managed
// process so the caller (the multi-port proxy pool) can track and stop it
// without disturbing any other tunnel.
//
// Each device keeps its own TUN interface (e.g. fpx100, fpx101, ...); combined
// with the proxy's per-interface SO_BINDTODEVICE binding this lets every SOCKS5
// port exit through a distinct VPNGate node without a global policy route.
// sanitizePoolConfig strips directives that would hijack the host's default
// route. Pool tunnels must NOT become the machine's default gateway — proxy
// sockets bind to each tunnel via SO_BINDTODEVICE, so the host keeps its own
// routing. VPNGate .ovpn files typically ship `redirect-gateway`, which
// --route-nopull does NOT suppress because it lives in the file, not in a push.
func sanitizePoolConfig(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			out = append(out, ln)
			continue
		}
		fields := strings.Fields(t)
		if len(fields) > 0 && (fields[0] == "redirect-gateway" || fields[0] == "redirect-private") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func (m *Manager) StartDevice(ctx context.Context, nodeID, configText, device string) (domain.TunnelStartResult, *Managed) {
	// Strip route-hijacking directives before anything touches the host table.
	configText = sanitizePoolConfig(configText)
	// detectVersion takes m.mu internally; resolve it before locking here.
	version := m.detectVersion(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureAuthFile(); err != nil {
		return failResult(domain.FailStartFailed, "unable to write auth file: "+err.Error(), time.Now(), nil), nil
	}
	configPath, err := m.writeConfig(configText, "pool")
	if err != nil {
		return failResult(domain.FailStartFailed, "unable to write config: "+err.Error(), time.Now(), nil), nil
	}
	args := BuildArgs(BuildParams{
		Executable: ParseExecutable(m.cfg.OpenVPNCommand), ConfigFile: configPath, AuthFile: m.authFile,
		Device: device, RouteNoPull: true, Version: version,
	})
	res, managed := m.runner.Start(ctx, StartParams{
		Bin: args[0], Args: args[1:], ConfigPath: configPath, Device: device,
		StartupTimeout: m.cfg.OpenVPNConnectTimeout(), KeepAlive: true,
	})
	if !res.Success {
		_ = os.Remove(configPath)
		return res, nil
	}
	return res, managed
}
