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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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

	// Proxy credentials for the SOCKS5 listeners. They are mutable at runtime so
	// the web panel can rotate them without a restart; the gateway closures read
	// them through getProxyCreds() on every connection.
	proxyCredsMu sync.RWMutex
	proxyUser    string
	proxyPass    string

	// Rotation (backconnect) port: one shared listener that spreads connections
	// across the pool. Each client username is a session key bound to a stable
	// node; an empty username falls back to per-connection round-robin.
	rotateMu       sync.Mutex
	rotateSessions map[string]int
	rotateRR       int
	rotateGW       *proxy.Gateway
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
	if err := m.loadProxyCredentials(); err != nil {
		slog.Warn("pool load proxy credentials failed; using env defaults", "module", "pool", "err", err)
	}
	// Bring the rotating port up first so it is reachable immediately; it serves
	// connections as soon as the first slots appear (pickConnector waits for a
	// healthy pool), without blocking on the initial reconcile below.
	if err := m.startRotateGateway(ctx); err != nil {
		slog.Warn("pool rotate gateway failed to start", "module", "pool", "err", err)
	}
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
	if m.rotateGW != nil {
		_ = m.rotateGW.Stop()
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
	// Credentials are read live from the manager on every connection so a
	// runtime rotation (via the web panel) applies immediately to all ports,
	// including ones already listening.
	initUser, initPass := m.getProxyCreds()
	gw := proxy.New(proxy.Options{
		Host:            "0.0.0.0",
		Port:            port,
		MaxConnections: m.cfg.ProxyMaxConnections,
		ConnectTimeout:  m.cfg.ProxyConnectTimeout(),
		IdleTimeout:     m.cfg.ProxyIdleTimeout(),
		Username:        initUser,
		Password:        initPass,
		AuthRequired: func() bool {
			u, p := m.getProxyCreds()
			return u != "" && p != ""
		},
		Authenticate: func(username, password string) bool {
			u, p := m.getProxyCreds()
			return subtle.ConstantTimeCompare([]byte(username), []byte(u)) == 1 &&
				subtle.ConstantTimeCompare([]byte(password), []byte(p)) == 1
		},
		// Pool ports are reachable from outside. When credentials are
		// configured they are required; when blank the port is open (unified
		// blank=open rule), which is the operator's deliberate choice.
		ExternalAllowed: func() bool {
			return true
		},
		OpenExternalNoAuth: true,
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

// startRotateGateway brings up the shared rotating (backconnect) port when
// enabled. The gateway reads the live proxy credentials for auth and selects a
// per-connection connector via pickConnector, so each client username (session
// key) is bound to a stable pool node.
func (m *Manager) startRotateGateway(ctx context.Context) error {
	if !m.cfg.PoolRotateEnabled {
		slog.Info("pool rotate gateway disabled", "module", "pool")
		return nil
	}
	m.rotateMu.Lock()
	m.rotateSessions = make(map[string]int)
	m.rotateMu.Unlock()

	// Base connector is unused because ConnectorFor is set, but New requires one.
	base := proxy.NewSocketConnector("", m.cfg.ProxyDNSServer, m.cfg.ProxyConnectTimeout())
	gw := proxy.New(proxy.Options{
		Host:            "0.0.0.0",
		Port:            m.cfg.PoolRotatePort,
		MaxConnections: m.cfg.ProxyMaxConnections,
		ConnectTimeout:  m.cfg.ProxyConnectTimeout(),
		IdleTimeout:     m.cfg.ProxyIdleTimeout(),
		AuthRequired: func() bool {
			u, p := m.getProxyCreds()
			return u != "" && p != ""
		},
		Authenticate: func(username, password string) bool {
			u, p := m.getProxyCreds()
			return subtle.ConstantTimeCompare([]byte(username), []byte(u)) == 1 &&
				subtle.ConstantTimeCompare([]byte(password), []byte(p)) == 1
		},
		// The rotating port is intentionally reachable from outside. When no
		// credentials are configured it is open (unified blank=open rule);
		// when credentials are set, auth is enforced.
		ExternalAllowed:    func() bool { return true },
		OpenExternalNoAuth: true,
		ConnectorFor: func(username string) (proxy.OutboundConnector, error) {
			return m.pickConnector(username)
		},
	}, base)
	if err := gw.Start(ctx); err != nil {
		return err
	}
	m.rotateMu.Lock()
	m.rotateGW = gw
	m.rotateMu.Unlock()
	slog.Info("pool rotate gateway up", "module", "pool", "port", m.cfg.PoolRotatePort)
	return nil
}

// pickConnector returns a connector for the given session key. A non-empty
// username is bound to a stable node (sticky) until that node dies; an empty
// username gets a fresh per-connection node via round-robin.
func (m *Manager) pickConnector(username string) (proxy.OutboundConnector, error) {
	m.rotateMu.Lock()
	defer m.rotateMu.Unlock()

	healthy := m.healthySlotIndices()
	if len(healthy) == 0 {
		return nil, errors.New("pool has no healthy slots")
	}

	if username != "" {
		if idx, ok := m.rotateSessions[username]; ok && m.slotIndexHealthy(idx) {
			return m.connectorForSlot(idx)
		}
		// Assign a healthy slot, spreading sessions across the pool.
		pick := healthy[m.rotateRR%len(healthy)]
		m.rotateRR++
		m.rotateSessions[username] = pick
		return m.connectorForSlot(pick)
	}

	// Empty username: per-connection round-robin.
	pick := healthy[m.rotateRR%len(healthy)]
	m.rotateRR++
	return m.connectorForSlot(pick)
}

// healthySlotIndices returns the indices of currently-running slots. Callers
// must not hold m.rotateMu; this only takes m.mu, which is safe because rotateMu
// is always acquired before m.mu in this file.
func (m *Manager) healthySlotIndices() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int, 0, len(m.slots))
	for i, s := range m.slots {
		if s != nil && s.Managed != nil && s.Managed.Running() {
			out = append(out, i)
		}
	}
	return out
}

func (m *Manager) slotIndexHealthy(i int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i < 0 || i >= len(m.slots) {
		return false
	}
	s := m.slots[i]
	return s != nil && s.Managed != nil && s.Managed.Running()
}

// connectorForSlot builds a connector bound to the device of the slot at index
// i. It returns nil (without panicking) if the slot is missing or out of range.
func (m *Manager) connectorForSlot(i int) (proxy.OutboundConnector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i < 0 || i >= len(m.slots) {
		return nil, errors.New("slot index out of range")
	}
	s := m.slots[i]
	if s == nil {
		return nil, errors.New("slot not allocated")
	}
	return proxy.NewSocketConnector(s.Device, m.cfg.ProxyDNSServer, m.cfg.ProxyConnectTimeout()), nil
}

// RotateSessionView is the serialisable view of a rotation session mapping.
type RotateSessionView struct {
	Session string `json:"session"`
	Port    int    `json:"port"`
	Device  string `json:"device"`
	NodeID  string `json:"node_id"`
	Country string `json:"country"`
	ExitIP  string `json:"exit_ip"`
	Running bool   `json:"running"`
}

// RotateSessions returns the current session -> node mapping for the rotating
// port.
func (m *Manager) RotateSessions() []RotateSessionView {
	m.rotateMu.Lock()
	keys := make([]string, 0, len(m.rotateSessions))
	sess := make(map[string]int, len(m.rotateSessions))
	for k, v := range m.rotateSessions {
		keys = append(keys, k)
		sess[k] = v
	}
	m.rotateMu.Unlock()

	out := make([]RotateSessionView, 0, len(keys))
	for _, k := range keys {
		idx := sess[k]
		m.mu.Lock()
		sv := RotateSessionView{Session: k}
		if idx >= 0 && idx < len(m.slots) && m.slots[idx] != nil {
			s := m.slots[idx]
			sv.Port = s.Port
			sv.Device = s.Device
			sv.NodeID = s.NodeID
			sv.Country = s.Country
			sv.ExitIP = deviceIP(s.Device)
			sv.Running = s.Managed != nil && s.Managed.Running()
		}
		m.mu.Unlock()
		out = append(out, sv)
	}
	return out
}

// RecycleSession drops the binding for one session (or all, when key is empty)
// so the next connection re-selects a node.
func (m *Manager) RecycleSession(key string) {
	m.rotateMu.Lock()
	defer m.rotateMu.Unlock()
	if key == "" {
		for k := range m.rotateSessions {
			delete(m.rotateSessions, k)
		}
		return
	}
	delete(m.rotateSessions, key)
}

// RotatePort reports the configured rotating port (0 if disabled).
func (m *Manager) RotatePort() int {
	if !m.cfg.PoolRotateEnabled {
		return 0
	}
	return m.cfg.PoolRotatePort
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

// getProxyCreds returns the current SOCKS5 credentials in a race-safe way.
func (m *Manager) getProxyCreds() (string, string) {
	m.proxyCredsMu.RLock()
	defer m.proxyCredsMu.RUnlock()
	return m.proxyUser, m.proxyPass
}

// ProxyCredentials returns the configured username (password is intentionally
// not exposed over the API in clear text).
func (m *Manager) ProxyCredentials() (string, bool) {
	u, p := m.getProxyCreds()
	return u, u != "" && p != ""
}

// SetProxyCredentials updates the SOCKS5 credentials at runtime and persists
// them to disk so they survive a restart. Already-listening ports pick up the
// new values on the next connection because their auth closures read live state.
func (m *Manager) SetProxyCredentials(user, pass string) error {
	m.proxyCredsMu.Lock()
	m.proxyUser = user
	m.proxyPass = pass
	m.proxyCredsMu.Unlock()
	return m.saveProxyCredentials()
}

func (m *Manager) credsPath() string {
	return filepath.Join(m.cfg.DataDir, "proxy-credentials.json")
}

// loadProxyCredentials seeds the in-memory credentials from the environment
// (which is the service default) and then overrides them with any persisted
// file. If no file exists yet, the env defaults are written out so the file is
// created and future rotations have a backing store.
func (m *Manager) loadProxyCredentials() error {
	user := m.cfg.ProxyUsername
	if user == "" {
		user = os.Getenv("FREE_PROXY_PROXY_USERNAME")
	}
	pass := m.cfg.ProxyPassword
	if pass == "" {
		pass = os.Getenv("FREE_PROXY_PROXY_PASSWORD")
	}
	m.proxyCredsMu.Lock()
	m.proxyUser = user
	m.proxyPass = pass
	m.proxyCredsMu.Unlock()

	data, err := os.ReadFile(m.credsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return m.saveProxyCredentials()
		}
		return err
	}
	var saved struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	m.proxyCredsMu.Lock()
	if saved.Username != "" {
		m.proxyUser = saved.Username
	}
	if saved.Password != "" {
		m.proxyPass = saved.Password
	}
	m.proxyCredsMu.Unlock()
	return nil
}

func (m *Manager) saveProxyCredentials() error {
	m.proxyCredsMu.RLock()
	saved := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{m.proxyUser, m.proxyPass}
	m.proxyCredsMu.RUnlock()
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.DataDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.credsPath(), data, 0o600)
}
