package tunnel

import (
	"context"
	"os"
	"time"

	"github.com/masteralanlab/free-proxy/internal/domain"
)

// StartDevice brings up an OpenVPN tunnel on the given device for nodeID,
// independent of the manager's single "active" tunnel. It returns the managed
// process so the caller (the multi-port proxy pool) can track and stop it
// without disturbing any other tunnel.
//
// Each device keeps its own TUN interface (e.g. fpx100, fpx101, ...); combined
// with the proxy's per-interface SO_BINDTODEVICE binding this lets every SOCKS5
// port exit through a distinct VPNGate node without a global policy route.
func (m *Manager) StartDevice(ctx context.Context, nodeID, configText, device string) (domain.TunnelStartResult, *Managed) {
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
