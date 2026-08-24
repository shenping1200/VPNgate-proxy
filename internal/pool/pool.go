// Package pool implements the multi-port VPNGate proxy pool: every usable VPN
// node is turned into one independent SOCKS5 port on the host. A client reaches
// a specific exit simply by connecting to VPS_IP:PORT. Ports are assigned by the
// number of slots that are successfully up, so a single dead node never leaves a
// gap in the contiguous block: if the first candidate fails, the next working
// node simply fills START_PORT, the next fills START_PORT+1, and so on. Each
// port also retries the next candidate node (up to FREE_PROXY_POOL_BUILD_RETRIES
// extra attempts) before being considered unavailable.
//
// Reconcile is incremental: healthy slots keep their existing port and node,
// only dead slots are replaced and new slots are appended. Candidate-list churn
// (new nodes discovered or old nodes cooling down) no longer tears down the
// whole pool.
package pool

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
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
	Port       int    `json:"port"`
	Device     string `json:"device"`
	NodeID     string `json:"node_id"`
	Country    string `json:"country"`
	ExitIP     string `json:"exit_ip"`
	Running    bool   `json:"running"`
	UptimeSecs int64  `json:"uptime_secs"`
}

// Manager drives the pool: it periodically discovers nodes, then maps the
// current candidate set onto a contiguous block of SOCKS5 ports, one tunnel and
// one listener per node.
type Manager struct {
	cfg       *config.Config
	nodes     *store.NodeRepository
	discovery *services.DiscoveryService
	tunnel    *tunnel.Manager

	mu         sync.Mutex
	slots      []*Slot
	stopCh     chan struct{}
	reconMu    sync.Mutex
	reconciling bool
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

// reconcile performs incremental maintenance on the pool: healthy slots keep
// their port and node; only dead or missing slots are repaired in-place, and
// new slots are appended when more candidates become available. The whole pool
// is no longer torn down when the candidate list changes.
func (m *Manager) reconcile(ctx context.Context) {
	if !m.reconMu.TryLock() {
		slog.Warn("pool reconcile already in progress; skipping tick", "module", "pool")
		return
	}
	defer m.reconMu.Unlock()

	candidates, err := m.candidateNodes(ctx)
	if err != nil {
		slog.Warn("pool candidate fetch failed", "module", "pool", "err", err)
		return
	}
	if len(candidates) > m.cfg.PoolMaxPorts {
		candidates = candidates[:m.cfg.PoolMaxPorts]
	}

	target := len(candidates)
	if target > m.cfg.PoolMaxPorts {
		target = m.cfg.PoolMaxPorts
	}

	slog.Info("pool reconcile tick", "module", "pool",
		"candidates", len(candidates), "live_slots", m.liveCount(),
		"total_ports", m.slotLen(), "target", target)

	// 1. Repair dead / nil slots in-place, keeping their port.
	for i := 0; i < m.slotLen(); i++ {
		if !m.slotHealthy(i) {
			port := m.cfg.PoolStartPort + i
			slog.Info("pool replacing dead slot", "module", "pool", "port", port)
			m.teardownSlotAt(i)
			if slot := m.tryFillPort(ctx, port, candidates); slot != nil {
				m.setSlot(i, slot)
			} else {
				m.setSlot(i, nil)
			}
		}
	}

	// 2. Grow to the target count: fill holes first, then append.
	for m.liveCount() < target {
		hole := m.firstHole()
		if hole >= 0 {
			port := m.cfg.PoolStartPort + hole
			if slot := m.tryFillPort(ctx, port, candidates); slot != nil {
				m.setSlot(hole, slot)
				continue
			}
		}
		port := m.cfg.PoolStartPort + m.slotLen()
		if slot := m.tryFillPort(ctx, port, candidates); slot != nil {
			m.appendSlot(slot)
		} else {
			break
		}
	}

	// 3. Shrink if the candidate pool has shrunk: remove slots from the tail.
	for m.liveCount() > target {
		lastIdx := m.lastLiveIndex()
		if lastIdx < 0 {
			break
		}
		m.teardownSlotAt(lastIdx)
		m.setSlot(lastIdx, nil)
	}
	m.trimTrailingNils()

	slog.Info("pool reconcile done", "module", "pool",
		"live_slots", m.liveCount(), "total_ports", m.slotLen())
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

// build performs a one-shot full build of the pool. It is kept for manual use;
// normal operation relies on reconcile, which is incremental.
func (m *Manager) build(ctx context.Context, candidates []domain.ProxyNodeRead) {
	m.mu.Lock()
	m.slots = make([]*Slot, 0, len(candidates))
	m.mu.Unlock()

	extra := m.cfg.PoolBuildRetries
	if extra < 0 {
		extra = 0
	}

	cursor := 0
	for cursor < len(candidates) {
		m.mu.Lock()
		if len(m.slots) >= m.cfg.PoolMaxPorts {
			m.mu.Unlock()
			break
		}
		m.mu.Unlock()

		var slot *Slot
		triedIDs := make([]string, 0, extra+1)
		for attempt := 0; attempt <= extra && cursor < len(candidates); attempt, cursor = attempt+1, cursor+1 {
			node := candidates[cursor]
			triedIDs = append(triedIDs, node.ID)
			port := m.cfg.PoolStartPort + len(m.slots)
			s := m.startNode(ctx, port, node)
			if s != nil {
				slot = s
				break
			}
		}

		if slot == nil {
			for _, id := range triedIDs {
				_ = m.nodes.MarkUnavailable(ctx, id)
			}
			slog.Warn("pool port unfilled after retries", "module", "pool",
				"tried", triedIDs, "retries", extra)
			continue
		}

		m.mu.Lock()
		m.slots = append(m.slots, slot)
		live := len(m.slots)
		m.mu.Unlock()
		slog.Info("pool slot up", "module", "pool",
			"port", slot.Port, "device", slot.Device, "node", slot.NodeID,
			"country", slot.Country, "live_slots", live)
	}
}

// tryFillPort attempts to start a slot on the requested port using candidates
// that are not already used by another healthy slot. If every unused candidate
// fails, it falls back to any candidate.
func (m *Manager) tryFillPort(ctx context.Context, port int, candidates []domain.ProxyNodeRead) *Slot {
	used := m.usedNodeIDs()
	for _, n := range candidates {
		if _, ok := used[n.ID]; ok {
			continue
		}
		if s := m.startNode(ctx, port, n); s != nil {
			return s
		}
	}
	for _, n := range candidates {
		if s := m.startNode(ctx, port, n); s != nil {
			return s
		}
	}
	return nil
}

// startNode attempts to bring up one tunnel + SOCKS5 gateway for node on the
// requested port. It returns the Slot on success, or nil (after cleaning up the
// half-built tunnel) on failure.
func (m *Manager) startNode(ctx context.Context, port int, node domain.ProxyNodeRead) *Slot {
	offset := port - m.cfg.PoolStartPort
	if offset < 0 {
		offset = 0
	}
	device := fmt.Sprintf("%s%d", m.cfg.ProbeDevicePrefix, m.cfg.PoolDeviceBase+offset)

	target, err := m.nodes.GetTarget(ctx, node.ID)
	if err != nil {
		slog.Warn("pool get target failed; skipping node", "module", "pool", "node", node.ID, "err", err)
		return nil
	}
	res, managed := m.tunnel.StartDevice(ctx, node.ID, target.ConfigText, device)
	if !res.Success || managed == nil {
		slog.Warn("pool tunnel failed", "module", "pool",
			"node", node.ID, "device", device, "msg", res.Message)
		return nil
	}
	connector := proxy.NewSocketConnector(device, m.cfg.ProxyDNSServer, m.cfg.ProxyConnectTimeout())
	// Read proxy credentials directly from the environment. The env-library
	// prefix parsing occasionally fails to populate ProxyPassword, so we
	// resolve them here unconditionally to guarantee auth is configured.
	proxyUser := m.cfg.ProxyUsername
	if proxyUser == "" {
		proxyUser = os.Getenv("FREE_PROXY_PROXY_USERNAME")
	}
	proxyPass := m.cfg.ProxyPassword
	if proxyPass == "" {
		proxyPass = os.Getenv("FREE_PROXY_PROXY_PASSWORD")
	}
	gw := proxy.New(proxy.Options{
		Host:            "0.0.0.0",
		Port:            port,
		MaxConnections: m.cfg.ProxyMaxConnections,
		ConnectTimeout:  m.cfg.ProxyConnectTimeout(),
		IdleTimeout:     m.cfg.ProxyIdleTimeout(),
		Username:        proxyUser,
		Password:        proxyPass,
		AuthRequired: func() bool {
			return proxyUser != "" && proxyPass != ""
		},
		Authenticate: func(username, password string) bool {
			return username == proxyUser && password == proxyPass
		},
		// Pool ports are meant to be reached from outside, but only behind
		// proxy auth — never as an open relay.
		ExternalAllowed: func() bool {
			return proxyUser != "" && proxyPass != ""
		},
	}, connector)
	if err := gw.Start(ctx); err != nil {
		slog.Warn("pool gateway start failed; stopping tunnel", "module", "pool", "port", port, "err", err)
		managed.Stop()
		return nil
	}
	return &Slot{
		Index:     offset,
		Port:      port,
		Device:    device,
		NodeID:    node.ID,
		Country:   node.Country,
		Managed:   managed,
		Gateway:   gw,
		StartedAt: time.Now(),
	}
}

func (m *Manager) teardownAll() {
	m.mu.Lock()
	slots := m.slots
	m.slots = nil
	m.mu.Unlock()
	for _, s := range slots {
		if s == nil {
			continue
		}
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
		if s == nil {
			continue
		}
		uptime := int64(0)
		if !s.StartedAt.IsZero() {
			uptime = int64(time.Since(s.StartedAt).Seconds())
		}
		out = append(out, SlotView{
			Port:       s.Port,
			Device:     s.Device,
			NodeID:     s.NodeID,
			Country:    s.Country,
			ExitIP:     deviceIP(s.Device),
			Running:    s.Managed != nil && s.Managed.Running(),
			UptimeSecs: uptime,
		})
	}
	return out
}

// Size returns the number of currently live slots.
func (m *Manager) Size() int {
	return m.liveCount()
}

// ReconcileNow forces an immediate incremental reconcile of the pool. Healthy
// slots are preserved; only dead slots are repaired and new slots appended.
func (m *Manager) ReconcileNow(ctx context.Context) {
	slog.Info("pool manual reconcile requested", "module", "pool")
	m.reconcile(ctx)
}

// slotLen returns the number of allocated port positions (including nil holes).
func (m *Manager) slotLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.slots)
}

// liveCount returns the number of healthy running slots.
func (m *Manager) liveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.slots {
		if s != nil && s.Managed != nil && s.Managed.Running() {
			n++
		}
	}
	return n
}

// slotHealthy reports whether the slot at index i is running.
func (m *Manager) slotHealthy(i int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.slots) {
		return true
	}
	s := m.slots[i]
	return s != nil && s.Managed != nil && s.Managed.Running()
}

// setSlot writes slot at index i, growing the slice with nils if necessary.
func (m *Manager) setSlot(i int, slot *Slot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.slots) <= i {
		m.slots = append(m.slots, nil)
	}
	m.slots[i] = slot
}

// appendSlot appends a slot at the end of the slice.
func (m *Manager) appendSlot(slot *Slot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots = append(m.slots, slot)
}

// teardownSlotAt stops the components of the slot at index i without modifying
// the slice. It is safe to call on a nil slot.
func (m *Manager) teardownSlotAt(i int) {
	m.mu.Lock()
	if i >= len(m.slots) {
		m.mu.Unlock()
		return
	}
	s := m.slots[i]
	m.mu.Unlock()
	if s == nil {
		return
	}
	if s.Gateway != nil {
		_ = s.Gateway.Stop()
	}
	if s.Managed != nil {
		s.Managed.Stop()
	}
}

// lastLiveIndex returns the highest index that holds a non-nil slot, or -1.
func (m *Manager) lastLiveIndex() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.slots) - 1; i >= 0; i-- {
		if m.slots[i] != nil {
			return i
		}
	}
	return -1
}

// firstHole returns the lowest index holding a nil slot, or -1 if none.
func (m *Manager) firstHole() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.slots {
		if s == nil {
			return i
		}
	}
	return -1
}

// trimTrailingNils removes nil slots from the tail of the slice.
func (m *Manager) trimTrailingNils() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.slots) > 0 && m.slots[len(m.slots)-1] == nil {
		m.slots = m.slots[:len(m.slots)-1]
	}
}

// usedNodeIDs returns the set of node IDs currently served by healthy slots.
func (m *Manager) usedNodeIDs() map[string]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	used := make(map[string]struct{})
	for _, s := range m.slots {
		if s != nil && s.Managed != nil && s.Managed.Running() {
			used[s.NodeID] = struct{}{}
		}
	}
	return used
}

// deviceIP returns the first non-loopback IPv4 address assigned to a TUN device,
// used to surface the egress IP a slot's traffic exits through.
func deviceIP(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}
