// Package poolui serves the embedded management dashboard for `pool` mode: a
// live view of every SOCKS5 slot (port -> VPNGate exit) plus a small JSON API.
// It is intentionally dependency-free (net/http only) so the pool binary stays
// a single static file with no external assets.
package poolui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/shenping1200/VPNgate-proxy/internal/config"
	"github.com/shenping1200/VPNgate-proxy/internal/pool"
)

//go:embed all:assets
var assets embed.FS

// Server bundles the pool state needed by the dashboard handlers.
type Server struct {
	cfg     *config.Config
	mgr     *pool.Manager
	version string
	user    string
	pass    string
}

// Start launches the pool management web server. It blocks until ctx is done,
// then gracefully shuts down. Call it in its own goroutine from pool mode.
func Start(ctx context.Context, cfg *config.Config, mgr *pool.Manager, version string) error {
	user := cfg.PoolWebUsername
	if user == "" {
		user = "admin"
	}
	pass := cfg.PoolWebPassword
	if pass == "" {
		pass = cfg.ProxyPassword
	}

	s := &Server{cfg: cfg, mgr: mgr, version: version, user: user, pass: pass}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.basicAuth(s.handleIndex))
	mux.HandleFunc("/api/v1/pool/statistics", s.basicAuth(s.handleStatistics))
	mux.HandleFunc("/api/v1/pool/slots", s.basicAuth(s.handleSlots))
	mux.HandleFunc("/api/v1/pool/reconcile", s.basicAuth(s.handleReconcile))

	addr := net.JoinHostPort(cfg.PoolWebHost, itoa(cfg.PoolWebPort))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("pool web panel starting", "module", "poolui", "addr", addr, "user", user)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		uOK := subtle.ConstantTimeCompare([]byte(u), []byte(s.user)) == 1
		pOK := subtle.ConstantTimeCompare([]byte(p), []byte(s.pass)) == 1
		if !ok || !uOK || !pOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="VPNGate Pool"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := assets.ReadFile("assets/dashboard.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

type statistics struct {
	Version    string `json:"version"`
	Hostname   string `json:"hostname"`
	StartPort  int    `json:"start_port"`
	MaxPorts   int    `json:"max_ports"`
	Mode       string `json:"mode"`
	TotalSlots int    `json:"total_slots"`
	LiveSlots  int    `json:"live_slots"`
	Countries  int    `json:"countries"`
	WebUser    string `json:"web_user"`
}

func (s *Server) handleStatistics(w http.ResponseWriter, _ *http.Request) {
	slots := s.mgr.Slots()
	live := 0
	countries := map[string]struct{}{}
	for _, sl := range slots {
		if sl.Running {
			live++
		}
		if sl.Country != "" {
			countries[sl.Country] = struct{}{}
		}
	}
	host, _ := os.Hostname()
	writeJSON(w, statistics{
		Version:    s.version,
		Hostname:   host,
		StartPort:  s.cfg.PoolStartPort,
		MaxPorts:   s.cfg.PoolMaxPorts,
		Mode:       s.cfg.PoolMode,
		TotalSlots: len(slots),
		LiveSlots:  live,
		Countries:  len(countries),
		WebUser:    s.user,
	})
}

func (s *Server) handleSlots(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.mgr.Slots())
}

func (s *Server) handleReconcile(w http.ResponseWriter, _ *http.Request) {
	s.mgr.ReconcileNow(context.Background())
	writeJSON(w, map[string]any{"ok": true, "reconciling": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
