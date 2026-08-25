package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
)

// SOCKS5 constants (RFC 1928 / RFC 1929).
const (
	socksVersion   = 0x05
	authNone       = 0x00
	authUserPass   = 0x02
	authNoAccept   = 0xFF
	cmdConnect     = 0x01
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04
	repSuccess     = 0x00
	repGeneralFail = 0x01
	repRefused     = 0x05
	repCmdNotSup   = 0x07
)

func (g *Gateway) serveSOCKS5(ctx context.Context, conn net.Conn, br *bufio.Reader, requireAuth bool) {
	// Greeting: VER, NMETHODS, METHODS...
	ver, err := br.ReadByte()
	if err != nil || ver != socksVersion {
		return
	}
	nMethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// Negotiate the auth method and, when applicable, capture the client
	// username. The username doubles as the routing key for the rotating port.
	username := ""
	switch {
	case requireAuth:
		if !containsByte(methods, authUserPass) {
			_, _ = conn.Write([]byte{socksVersion, authNoAccept})
			return
		}
		if _, err := conn.Write([]byte{socksVersion, authUserPass}); err != nil {
			return
		}
		u, ok := g.socksAuth(br, conn)
		if !ok {
			return
		}
		username = u
	case g.opts.ConnectorFor != nil:
		// Rotating mode: prefer the user/pass method so the client can send a
		// session key in the username field; fall back to no-auth (empty key).
		if containsByte(methods, authUserPass) {
			if _, err := conn.Write([]byte{socksVersion, authUserPass}); err != nil {
				return
			}
			username = g.socksAuthCapture(br, conn)
		} else if containsByte(methods, authNone) {
			if _, err := conn.Write([]byte{socksVersion, authNone}); err != nil {
				return
			}
		} else {
			_, _ = conn.Write([]byte{socksVersion, authNoAccept})
			return
		}
	default:
		if !containsByte(methods, authNone) {
			_, _ = conn.Write([]byte{socksVersion, authNoAccept})
			return
		}
		if _, err := conn.Write([]byte{socksVersion, authNone}); err != nil {
			return
		}
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != socksVersion {
		return
	}
	if header[1] != cmdConnect {
		g.socksReply(conn, repCmdNotSup)
		return
	}

	host, err := readSocksAddr(br, header[3])
	if err != nil {
		g.socksReply(conn, repGeneralFail)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	connector, err := g.connectorFor(username)
	if err != nil {
		g.socksReply(conn, repGeneralFail)
		return
	}
	targetConn, err := connector.Dial(ctx, host, port)
	if err != nil {
		g.socksReply(conn, socksErrCode(err))
		return
	}
	if err := g.socksReply(conn, repSuccess); err != nil {
		_ = targetConn.Close()
		return
	}
	relay(conn, targetConn, g.opts.IdleTimeout)
}

// socksAuth reads the user/pass sub-negotiation and verifies the credentials.
// It returns the supplied username on success (used as a routing key) or an
// empty string on failure.
func (g *Gateway) socksAuth(br *bufio.Reader, conn net.Conn) (string, bool) {
	// Sub-negotiation: VER(0x01), ULEN, UNAME, PLEN, PASSWD
	ver, err := br.ReadByte()
	if err != nil || ver != 0x01 {
		return "", false
	}
	uLen, err := br.ReadByte()
	if err != nil {
		return "", false
	}
	user := make([]byte, uLen)
	if _, err := io.ReadFull(br, user); err != nil {
		return "", false
	}
	pLen, err := br.ReadByte()
	if err != nil {
		return "", false
	}
	pass := make([]byte, pLen)
	if _, err := io.ReadFull(br, pass); err != nil {
		return "", false
	}
	ok := g.authenticate(conn, string(user), string(pass))
	if ok {
		_, _ = conn.Write([]byte{0x01, 0x00})
		return string(user), true
	}
	_, _ = conn.Write([]byte{0x01, 0x01})
	return "", false
}

// socksAuthCapture reads the user/pass sub-negotiation and always accepts. It is
// used when authentication is disabled but we still want the username as a
// routing key for the rotating port. It returns the supplied username.
func (g *Gateway) socksAuthCapture(br *bufio.Reader, conn net.Conn) string {
	ver, err := br.ReadByte()
	if err != nil || ver != 0x01 {
		return ""
	}
	uLen, err := br.ReadByte()
	if err != nil {
		return ""
	}
	user := make([]byte, uLen)
	if _, err := io.ReadFull(br, user); err != nil {
		return ""
	}
	pLen, err := br.ReadByte()
	if err != nil {
		return ""
	}
	pass := make([]byte, pLen)
	if _, err := io.ReadFull(br, pass); err != nil {
		return ""
	}
	_, _ = conn.Write([]byte{0x01, 0x00}) // accept unconditionally
	return string(user)
}

func (g *Gateway) socksReply(conn net.Conn, rep byte) error {
	// VER REP RSV ATYP(IPv4) 0.0.0.0 :0
	_, err := conn.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func readSocksAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypDomain:
		n, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", strconvErr(atyp)
	}
}

func containsByte(bs []byte, target byte) bool {
	return slices.Contains(bs, target)
}

func socksErrCode(err error) byte {
	if err != nil && strings.Contains(err.Error(), "refused") {
		return repRefused
	}
	return repGeneralFail
}

func strconvErr(atyp byte) error {
	return &net.AddrError{Err: "unsupported SOCKS address type " + strconv.Itoa(int(atyp))}
}
