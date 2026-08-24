// Package pool implements the multi-port VPNGate proxy pool: every usable VPN
// node is turned into one independent SOCKS5 port on the host. A client reaches
// a specific exit simply by connecting to VPS_IP:PORT — port N always maps to
// the Nth node in the current candidate set, and when a node dies the slots
// below it shift up so the port range stays contiguous (dynamic mode).
package pool

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/shenping1200/VPNgate-proxy/internal/config"
	"github.com/shenping1200/VPNgate-proxy/internal/domain"
	"github.com/shenping1200/VPNgate-proxy/internal/proxy"
	"github.com/shenping1200/VPNgate-proxy/internal/services"
	"github.com/shenping1200/VPNgate-proxy/internal/store"
	"github.com/shenping1200/VPNgate-proxy/internal/tunnel"
)

// Slot is one SOCKS5 port bound to one VPN node via its own TUN device.
type Slot struct {
	Index     int
	Port      int
	Device    string
	NodeID    string
	Country   string
	Managed   *tunnel.Managed
	Gateway   *proxy.Gateway
	StartedAt time.Time
}

// SlotView is the safe, serialisable view of a Slot for API/CLI output.
type SlotView struct {
	Port    int    `json:"port"`
	Device  string `json:"device"`
	NodeID  string `json:"node_id"`
	Country string `json:"country"`
	Running bool   `json:"running"`
}

// Manager drives the pool: it periodically discovers nodes, then maps the
// current candidate set onto a contiguous block of SOCKS5 ports, one tunnel and
// one listener per node.
type Manager struct {
	cfg       *config.Config
	nodes     *store.NodeRepository
	discovery *services.DiscoveryService
	tunnel    *tunnel.Manager

	mu     sync.Mutex
	slots  []*Slot
	stopCh chan struct{}
}

// NewManager constructs a pool Manager.
func NewManager(cfg *config.Config, nodes *store.NodeRepository, discovery *services.DiscoveryService, tunnelMgr *tunnel.Manager) *Manager {
	return &Manager{
		cfg:       cfg,
		nodes:     nodes,
		discovery: discovery,
		tunnel:    tunnelMgr,
		stopCh:    make(chan struct{}),
	}
}

// Start performs an initial reconcile and launches the background loops.
func (m *Manager) Start(ctx context.Context) error {
	slog.Info("proxy pool starting", "module", "pool",
		"start_port", m.cfg.PoolStartPort,
		"max_ports", m.cfg.PoolMaxPorts,
		"mode", m.cfg.PoolMode,
		"device_base", m.cfg.PoolDeviceBase,
		"discovery_interval_s", m.cfg.PoolDiscoveryIntervalSecs,
		"reconcile_interval_s", m.cfg.PoolReconcileIntervalSecs,
	)
	m.reconcile(ctx)
	go m.loop(ctx)
	return nil
}

// Stop tears the pool down.
func (m *Manager) Stop() {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
	m.teardownAll()
}

func (m *Manager) loop(ctx context.Context) {
	discT := time.NewTicker(time.Duration(m.cfg.PoolDiscoveryIntervalSecs) * time.Second)
	reconT := time.NewTicker(time.Duration(m.cfg.PoolReconcileIntervalSecs) * time.Second)
	defer discT.Stop()
	defer reconT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-discT.C:
			if _, err := m.discovery.Discover(ctx); err != nil {
				slog.Warn("pool discovery failed", "module", "pool", "err", err)
			}
		case <-reconT.C:
			m.reconcile(ctx)
		}
	}
}

// reconcile rebuilds the slot set only when the candidate set changes or a
// running slot has died, so healthy slots are not disturbed on every tick.
func (m *Manager) reconcile(ctx context.Context) {
	candidates, err := m.candidateNodes(ctx)
	if err != nil {
		slog.Warn("pool candidate fetch failed", "module", "pool", "err", err)
		return
	}
	if len(candidates) > m.cfg.PoolMaxPorts {
		candidates = candidates[:m.cfg.PoolMaxPorts]
	}

	m.mu.Lock()
	same := len(candidates) == len(m.slots)
	if same {
		for i, c := range candidates {
			s := m.slots[i]
			if s == nil || s.NodeID != c.ID || !s.Managed.Running() {
				same = false
				break
			}
		}
	}
	m.mu.Unlock()
	if same {
		return
	}

	slog.Info("pool reconciling", "module", "pool",
		"candidates", len(candidates), "current_slots", len(m.slots))
	m.teardownAll()
	m.build(ctx, candidates)
}

// candidateNodes returns the usable nodes, best first, excluding ones already
// known dead/cooling down.
func (m *Manager) candidateNodes(ctx context.Context) ([]domain.ProxyNodeRead, error) {
	all, err := m.nodes.ListNodes(ctx, store.NodeFilter{}, 2000, 0)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ProxyNodeRead, 0, len(all))
	for _, n := range all {
		if n.Status == domain.NodeUnavailable || n.Status == domain.NodeCooldown {
			continue
		}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SourceScore != out[j].SourceScore {
			return out[i].SourceScore > out[j].SourceScore
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// build tears nothing down; it starts a tunnel + SOCKS5 listener per candidate
// and assigns contiguous ports from PoolStartPort.
func (m *Manager) build(ctx context.Context, candidates []domain.ProxyNodeRead) {
	slots := make([]*Slot, 0, len(candidates))
	for i, node := range candidates {
		port := m.cfg.PoolStartPort + i
		device := fmt.Sprintf("%s%d", m.cfg.ProbeDevicePrefix, m.cfg.PoolDeviceBase+i)
		target, err := m.nodes.GetTarget(ctx, node.ID)
		if err != nil {
			slog.Warn("pool get target failed; skipping node", "module", "pool", "node", node.ID, "err", err)
			continue
		}
		res, managed := m.tunnel.StartDevice(ctx, node.ID, target.ConfigText, device)
		if !res.Success || managed == nil {
			slog.Warn("pool tunnel failed; marking node unavailable", "module", "pool",
				"node", node.ID, "device", device, "msg", res.Message)
			_ = m.nodes.MarkUnavailable(ctx, node.ID)
			continue
		}
		connector := proxy.NewSocketConnector(device, m.cfg.ProxyDNSServer, m.cfg.ProxyConnectTimeout())
		gw := proxy.New(proxy.Options{
			Host:            "0.0.0.0",
			Port:            port,
			MaxConnections: m.cfg.ProxyMaxConnections,
			ConnectTimeout:  m.cfg.ProxyConnectTimeout(),
			IdleTimeout:     m.cfg.ProxyIdleTimeout(),
			AuthRequired: func() bool {
				return m.cfg.ProxyUsername != "" && m.cfg.ProxyPassword != ""
			},
			Authenticate: func(username, password string) bool {
				return username == m.cfg.ProxyUsername && password == m.cfg.ProxyPassword
			},
			// Pool ports are meant to be reached from outside, but only behind
			// proxy auth — never as an open relay.
			ExternalAllowed: func() bool {
				return m.cfg.ProxyUsername != "" && m.cfg.ProxyPassword != ""
			},
		}, connector)
		if err := gw.Start(ctx); err != nil {
			slog.Warn("pool gateway start failed; stopping tunnel", "module", "pool", "port", port, "err", err)
			managed.Stop()
			_ = m.nodes.MarkUnavailable(ctx, node.ID)
			continue
		}
		slots = append(slots, &Slot{
			Index:     i,
			Port:      port,
			Device:    device,
			NodeID:    node.ID,
			Country:   node.Country,
			Managed:   managed,
			Gateway:   gw,
			StartedAt: time.Now(),
		})
		slog.Info("pool slot up", "module", "pool",
			"port", port, "device", device, "node", node.ID, "country", node.Country)
	}
	m.mu.Lock()
	m.slots = slots
	m.mu.Unlock()
}

func (m *Manager) teardownAll() {
	m.mu.Lock()
	slots := m.slots
	m.slots = nil
	m.mu.Unlock()
	for _, s := range slots {
		if s.Gateway != nil {
			_ = s.Gateway.Stop()
		}
		if s.Managed != nil {
			s.Managed.Stop()
		}
	}
}

// Slots returns a snapshot of the running pool for API/CLI display.
func (m *Manager) Slots() []SlotView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SlotView, 0, len(m.slots))
	for _, s := range m.slots {
		out = append(out, SlotView{
			Port:    s.Port,
			Device:  s.Device,
			NodeID:  s.NodeID,
			Country: s.Country,
			Running: s.Managed != nil && s.Managed.Running(),
		})
	}
	return out
}

// Size returns the number of currently mapped ports.
func (m *Manager) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.slots)
}
