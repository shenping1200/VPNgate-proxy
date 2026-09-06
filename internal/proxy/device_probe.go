package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// probeTarget is a public, anycast IP used purely to confirm the tunnel
// forwards packets. We use literal IPs (not hostnames) so the check has zero
// DNS dependency: a black-hole VPN tunnel answers the OpenVPN handshake and
// brings the TUN up, but drops every forwarded packet, so a TCP connect to one
// of these simply times out instead of completing. That timeout is exactly the
// signal we want — it proves the tunnel does not actually carry traffic.
var probeTargets = []string{
	"1.1.1.1:80",     // Cloudflare
	"1.0.0.1:80",     // Cloudflare secondary
	"8.8.8.8:80",     // Google
	"208.67.222.222:80", // OpenDNS
}

// ProbeDeviceForwarding verifies that traffic bound to iface actually reaches
// the internet. It dials through a SocketConnector bound to the tunnel
// interface, so the connection takes the device's dedicated policy-route
// egress — the same path real proxy traffic uses. A successful TCP connect to
// any public IP proves the tunnel forwards; a tunnel that accepts the handshake
// but black-holes packets fails every connect (the SYN goes out, no SYN-ACK
// comes back) and is reported as not forwarding.
//
// The public exit IP is recovered on a best-effort basis via an HTTP echo that
// needs DNS through the tunnel; a DNS hiccup there is non-fatal because the
// forwarding verdict is already decided by the raw connect.
func ProbeDeviceForwarding(ctx context.Context, iface, dnsServer string, timeout time.Duration) (ok bool, exitIP string, latencyMS int, err error) {
	start := time.Now()
	connector := NewSocketConnector(iface, dnsServer, timeout)

	var lastErr error
	for _, t := range probeTargets {
		host, portStr, splitErr := net.SplitHostPort(t)
		if splitErr != nil {
			lastErr = splitErr
			continue
		}
		port, _ := strconv.Atoi(portStr)
		conn, derr := connector.Dial(ctx, host, port)
		if derr != nil {
			lastErr = derr
			continue
		}
		_ = conn.Close()
		ok = true
		break
	}
	if !ok {
		if lastErr == nil {
			lastErr = fmt.Errorf("all probe targets unreachable")
		}
		return false, "", 0, lastErr
	}

	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	// Best-effort exit IP via an HTTP echo (requires DNS resolution through the
	// tunnel). Not required for the forwarding verdict, so a failure here does
	// not downgrade the slot.
	if ip, eerr := probeExitIP(connector, timeout); eerr == nil {
		exitIP = ip
	}
	return true, exitIP, ms, nil
}

// probeExitIP performs a minimal HTTP GET to a public echo service and returns
// the IP it reports. It is best-effort: callers treat any error as "no exit IP
// available" and keep the forwarding verdict.
func probeExitIP(connector *SocketConnector, timeout time.Duration) (string, error) {
	conn, err := connector.Dial(context.Background(), "ip.sb", 80)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: ip.sb\r\nConnection: close\r\nAccept: */*\r\n\r\n"); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(bufio.NewReader(conn), 64*1024))
	if err != nil {
		return "", err
	}
	head, body, ok := cutStatus(raw)
	if !ok {
		return "", fmt.Errorf("no HTTP response from echo")
	}
	if !strings.Contains(head, " 200 ") {
		return "", fmt.Errorf("echo returned %q", head)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if ip := net.ParseIP(line); ip != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("echo returned no parseable IP")
}

// cutStatus splits an HTTP response into its status line and body.
func cutStatus(raw []byte) (statusLine, body string, ok bool) {
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			return string(raw[:i]), string(raw[i+4:]), true
		}
	}
	return "", "", false
}
