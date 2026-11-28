package dataplane

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type requestConnKey struct{}

// net/http sends HTTP/1.x parser errors directly to the connection. Observe
// only their status line, before a request has reached the handler.
type requestConn struct {
	net.Conn

	plane   *Plane
	port    uint16
	handled bool
}

type tlsRequestConn struct {
	*requestConn

	secure *tls.Conn
}

func (c *tlsRequestConn) ConnectionState() tls.ConnectionState {
	return c.secure.ConnectionState()
}

func wrapRequestConn(c net.Conn, p *Plane, port uint16) net.Conn {
	tracked := &requestConn{Conn: c, plane: p, port: port}
	if secure, ok := c.(*tls.Conn); ok {
		if secure.ConnectionState().NegotiatedProtocol == "h2" {
			return c
		}
		return &tlsRequestConn{requestConn: tracked, secure: secure}
	}
	return tracked
}

func http1Conn(c net.Conn) *requestConn {
	switch c := c.(type) {
	case *requestConn:
		return c
	case *tlsRequestConn:
		return c.requestConn
	default:
		return nil
	}
}

func requestConnState(c net.Conn, state http.ConnState) {
	if state == http.StateIdle {
		if tracked := http1Conn(c); tracked != nil {
			tracked.handled = false
		}
	}
}

func (c *requestConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}

func (c *requestConn) Write(data []byte) (int, error) {
	status := 0
	if !c.handled && len(data) >= len("HTTP/1.1 400 ") &&
		bytes.HasPrefix(data, []byte("HTTP/1.1 ")) {
		switch string(data[9:12]) {
		case "400":
			status = http.StatusBadRequest
		case "417":
			status = http.StatusExpectationFailed
		case "431":
			status = http.StatusRequestHeaderFieldsTooLarge
		case "501":
			status = http.StatusNotImplemented
		case "505":
			status = http.StatusHTTPVersionNotSupported
		}
	}
	if status != 0 {
		c.handled = true
		c.observeFailure(status)
	}
	return c.Conn.Write(data)
}

func (c *requestConn) observeFailure(status int) {
	const reason = "http_parse_error"
	c.plane.metrics.request(requestRecord{listener: c.port, deny: reason}, status, "", 0, 0, 0)
	entry := accessEntry{Time: time.Now().UTC(), Listener: c.port, Status: status, Deny: reason}
	peer := addrPort(c.RemoteAddr()).Addr()
	if peer.IsValid() {
		entry.ClientIP = peer.String()
	}
	if secure, ok := c.Conn.(*tls.Conn); ok {
		state := secure.ConnectionState()
		entry.TLSVersion, entry.SNI = state.Version, state.ServerName
	}
	c.plane.writeAccess(entry)
}
