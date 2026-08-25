// Package proxy implements the local SOCKS5/HTTP proxy gateway served on a
// single port. It sniffs the first byte to dispatch protocols, forwards through
// an OutboundConnector (bound to the tunnel), and enforces optional auth and a
// connection cap. It depends only on config values passed via Options.
package proxy

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

// Options configures a Gateway.
type Options struct {
	Host     string
	Port     int
	Username string
	Password string
	// AuthRequired and Authenticate support database-backed credentials without
	// retaining a recoverable proxy password. When auth is configured, every
	// client authenticates regardless of whether it connects via loopback or a
	// non-loopback address.
	AuthRequired func() bool
	Authenticate func(username, password string) bool
	// InternalAuthenticate is an optional second credential verifier restricted
	// to loopback connections. It lets in-process monitoring authenticate without
	// storing or recovering the user's plaintext password.
	InternalAuthenticate func(username, password string) bool
	MaxConnections       int
	ConnectTimeout       time.Duration
	IdleTimeout          time.Duration
	// ExternalAllowed reports (at call time) whether non-loopback clients may use
	// the proxy. nil denies external access. Loopback clients always reach protocol
	// handling, where the same configured authentication policy is enforced.
	ExternalAllowed func() bool
	// ConnectorFor, when set, overrides the static connector with a per-connection
	// connector chosen by the client's SOCKS5 username. It powers the rotating
	// pool port: one listener spreads connections across the pool, binding each
	// session (username) to a stable node.
	ConnectorFor func(username string) (OutboundConnector, error)
	// OpenExternalNoAuth allows non-loopback clients even when no credentials are
	// configured. Use only for deliberate open modes (e.g. the rotating port, or a
	// pool the operator has chosen to leave unauthenticated).
	OpenExternalNoAuth bool
}

// Gateway is the unified SOCKS5/HTTP proxy server.
type Gateway struct {
	opts      Options
	connector OutboundConnector
	sem       chan struct{}

	mu sync.Mutex
	ln net.Listener
}

// New creates a Gateway. MaxConnections defaults to 256 when unset.
func New(opts Options, connector OutboundConnector) *Gateway {
	max := opts.MaxConnections
	if max <= 0 {
		max = 256
	}
	return &Gateway{opts: opts, connector: connector, sem: make(chan struct{}, max)}
}

func (g *Gateway) authEnabled() bool {
	if g.opts.AuthRequired != nil {
		return g.opts.AuthRequired()
	}
	return g.opts.Username != "" || g.opts.Password != ""
}

func (g *Gateway) authenticate(conn net.Conn, username, password string) bool {
	if isLoopbackAddr(conn.RemoteAddr().String()) && g.opts.InternalAuthenticate != nil &&
		g.opts.InternalAuthenticate(username, password) {
		return true
	}
	if g.opts.Authenticate != nil {
		return g.opts.Authenticate(username, password)
	}
	return subtle.ConstantTimeCompare([]byte(username), []byte(g.opts.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(g.opts.Password)) == 1
}

func (g *Gateway) requireProtocolAuth() bool { return g.authEnabled() }

// allowClient decides whether to admit a freshly accepted connection to protocol
// handling. Loopback clients are admitted regardless of the exposure toggle but
// still authenticate when credentials are configured. External clients require
// the toggle to be on AND proxy auth to be configured, preventing an open relay.
func (g *Gateway) allowClient(conn net.Conn) bool {
	remote := conn.RemoteAddr().String()
	loop := isLoopbackAddr(remote)
	if loop {
		return true
	}
	extOK := g.opts.ExternalAllowed != nil && g.opts.ExternalAllowed()
	auth := g.authEnabled()
	allowed := extOK && (auth || g.opts.OpenExternalNoAuth)
	slog.Info("allowClient decision", "remote", remote, "loopback", loop, "external_allowed", extOK, "auth_enabled", auth, "open_no_auth", g.opts.OpenExternalNoAuth, "allowed", allowed)
	return allowed
}

// connectorFor returns the connector to use for a connection. When ConnectorFor
// is configured it is consulted with the client username so the rotating port
// can bind each session to its own node; otherwise the static connector is used.
func (g *Gateway) connectorFor(username string) (OutboundConnector, error) {
	if g.opts.ConnectorFor != nil {
		return g.opts.ConnectorFor(username)
	}
	return g.connector, nil
}

func isLoopbackAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Start binds the listener and serves accepted connections in the background.
// It returns once the listener is bound so callers can read Addr.
func (g *Gateway) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(g.opts.Host, strconv.Itoa(g.opts.Port)))
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.ln = ln
	g.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go g.acceptLoop(ctx, ln)
	return nil
}

func (g *Gateway) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go g.handle(ctx, conn)
	}
}

// Addr returns the bound listener address (or the configured one before Start).
func (g *Gateway) Addr() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ln != nil {
		return g.ln.Addr().String()
	}
	return net.JoinHostPort(g.opts.Host, strconv.Itoa(g.opts.Port))
}

// Running reports whether the listener is bound.
func (g *Gateway) Running() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ln != nil
}

// Stop closes the listener.
func (g *Gateway) Stop() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ln != nil {
		err := g.ln.Close()
		g.ln = nil
		return err
	}
	return nil
}
