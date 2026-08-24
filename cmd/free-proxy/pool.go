package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/masteralanlab/free-proxy/internal/config"
	"github.com/masteralanlab/free-proxy/internal/logging"
	"github.com/masteralanlab/free-proxy/internal/pool"
	"github.com/masteralanlab/free-proxy/internal/providers/vpngate"
	"github.com/masteralanlab/free-proxy/internal/services"
	"github.com/masteralanlab/free-proxy/internal/tunnel"
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
			if cfg.ProxyUsername == "" || cfg.ProxyPassword == "" {
				return fmt.Errorf("proxy pool requires FREE_PROXY_PROXY_USERNAME and FREE_PROXY_PROXY_PASSWORD (open relay protection)")
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
