package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/shenping1200/VPNgate-proxy/internal/logging"
	"github.com/shenping1200/VPNgate-proxy/internal/pool"
	"github.com/shenping1200/VPNgate-proxy/internal/poolui"
	"github.com/shenping1200/VPNgate-proxy/internal/providers/vpngate"
	"github.com/shenping1200/VPNgate-proxy/internal/services"
	"github.com/shenping1200/VPNgate-proxy/internal/tunnel"
	"github.com/spf13/cobra"
)

// poolCmd runs the multi-port VPNGate proxy pool: one SOCKS5 port per node,
// mapped contiguously from FREE_PROXY_POOL_START_PORT.
func poolCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pool",
		Short: "Run the multi-port VPNGate proxy pool (one SOCKS5 port per node)",
		Long: "Discover VPNGate nodes and expose each as an independent SOCKS5 port.\n" +
			"Ports start at FREE_PROXY_POOL_START_PORT and stay contiguous: when a node\n" +
			"dies the slots below it shift up, so VPS_IP:PORT always reaches a live exit.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if !cfg.PoolEnabled {
				return fmt.Errorf("proxy pool is disabled; set FREE_PROXY_POOL_ENABLED=true")
			}
			if err := cfg.EnsureDirectories(); err != nil {
				return err
			}
			if _, err := logging.Configure(cfg.LogsDir()); err != nil {
				return err
			}
			db, repos, err := openAppStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer db.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			provider := vpngate.NewProvider(cfg)
			discovery := services.NewDiscoveryService(provider, repos.Nodes)
			tunnelMgr := tunnel.NewManager(cfg)
			tunnelMgr.CleanupStaleProcesses()

			// Seed the node table so the first reconcile has candidates.
			if _, derr := discovery.Discover(ctx); derr != nil {
				fmt.Fprintf(os.Stderr, "warn: initial discovery failed: %v\n", derr)
			}

			mgr := pool.NewManager(cfg, repos.Nodes, discovery, tunnelMgr)
			slog.Info("pool cfg check", "proxy_username", cfg.ProxyUsername, "proxy_password_set", cfg.ProxyPassword != "", "env_user", os.Getenv("FREE_PROXY_PROXY_USERNAME") != "", "env_pass", os.Getenv("FREE_PROXY_PROXY_PASSWORD") != "")

			// Start the management web panel BEFORE the (blocking) pool
			// reconcile so the dashboard is reachable immediately and shows
			// slots filling in live, instead of waiting on the first
			// reconcile (which can take tens of seconds for many tunnels).
			if cfg.PoolWebEnabled {
				go func() {
					if err := poolui.Start(ctx, cfg, mgr, version); err != nil {
						fmt.Fprintf(os.Stderr, "pool web panel error: %v\n", err)
					}
				}()
			}

			if err := mgr.Start(ctx); err != nil {
				return err
			}
			fmt.Printf("proxy pool active: %d ports from %d\n", mgr.Size(), cfg.PoolStartPort)

			<-ctx.Done()
			mgr.Stop()
			return nil
		},
	}
	return cmd
}
