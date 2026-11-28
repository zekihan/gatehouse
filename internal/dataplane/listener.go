package dataplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const handshakeTimeout = 10 * time.Second

var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

type sourceConn struct {
	net.Conn

	source       *net.TCPAddr
	replay       *bytes.Reader
	socket       netip.Addr
	identity     string
	trustKey     [32]byte
	verifyMu     sync.Mutex
	verifyDigest string
	verifyKey    [32]byte
	verified     [][]*x509.Certificate
}

func (c *sourceConn) RemoteAddr() net.Addr { return c.source }
func (c *sourceConn) Read(p []byte) (int, error) {
	if c.replay != nil && c.replay.Len() > 0 {
		return c.replay.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *sourceConn) CloseWrite() error {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return c.Close()
}

func readProxyV2(r io.Reader) (netip.AddrPort, error) {
	var header [16]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return netip.AddrPort{}, err
	}
	if !bytes.Equal(header[:12], proxySignature) || header[12] != 0x21 {
		return netip.AddrPort{}, errors.New("expected PROXY v2 PROXY command")
	}
	size := int(binary.BigEndian.Uint16(header[14:]))
	addrSize := 0
	switch header[13] {
	case 0x11:
		addrSize = 4
	case 0x21:
		addrSize = 16
	}
	fields := 2*addrSize + 4
	if addrSize == 0 || size < fields {
		return netip.AddrPort{}, errors.New("invalid PROXY v2 TCP address")
	}
	var address [36]byte
	if _, err := io.ReadFull(r, address[:fields]); err != nil {
		return netip.AddrPort{}, err
	}
	if size > fields {
		if _, err := io.CopyN(io.Discard, r, int64(size-fields)); err != nil {
			return netip.AddrPort{}, err
		}
	}
	ip, _ := netip.AddrFromSlice(address[:addrSize])
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(address[2*addrSize:])), nil
}

func writeProxyV2(w io.Writer, src, dst netip.AddrPort) error {
	var data [52]byte
	copy(data[:], proxySignature)
	data[12] = 0x21
	var ports int
	switch {
	case !src.IsValid() || !dst.IsValid():
		return errors.New("missing source or destination")
	case src.Addr().Is4() && dst.Addr().Is4():
		data[13], data[15], ports = 0x11, 12, 24
		a, b := src.Addr().As4(), dst.Addr().As4()
		copy(data[16:], a[:])
		copy(data[20:], b[:])
	default:
		data[13], data[15], ports = 0x21, 36, 48
		a, b := src.Addr().As16(), dst.Addr().As16()
		copy(data[16:], a[:])
		copy(data[32:], b[:])
	}
	binary.BigEndian.PutUint16(data[ports:], src.Port())
	binary.BigEndian.PutUint16(data[ports+2:], dst.Port())
	_, err := w.Write(data[:ports+4])
	return err
}

// peekHello collects the entire initial handshake message across TLS records.
// The original records, including any bytes following the Hello, are replayed.
func peekHello(r io.Reader) (string, []byte, error) {
	const maxHello = 1 << 16
	var wire, handshake []byte
	var header [5]byte
	for len(wire) < 2*maxHello {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return "", nil, err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || length == 0 || length > 16384 {
			break
		}
		wire = append(wire, header[:]...)
		start := len(wire)
		wire = append(wire, make([]byte, length)...)
		if _, err := io.ReadFull(r, wire[start:]); err != nil {
			return "", nil, err
		}
		handshake = append(handshake, wire[start:]...)
		if len(handshake) < 4 {
			continue
		}
		size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || size > maxHello {
			break
		}
		if len(handshake) >= 4+size {
			name, err := helloName(cryptobyte.String(handshake[4 : 4+size]))
			return name, wire, err
		}
	}
	return "", nil, errors.New("invalid TLS ClientHello record")
}

func helloName(body cryptobyte.String) (string, error) {
	invalid := errors.New("invalid TLS ClientHello")
	var field, extensions cryptobyte.String
	if !body.Skip(34) || !body.ReadUint8LengthPrefixed(&field) ||
		!body.ReadUint16LengthPrefixed(&field) || !body.ReadUint8LengthPrefixed(&field) {
		return "", invalid
	}
	if body.Empty() {
		return "", nil
	}
	if !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return "", invalid
	}
	return nameExtension(extensions)
}

func nameExtension(extensions cryptobyte.String) (string, error) {
	invalid := errors.New("invalid TLS server_name extension")
	var field cryptobyte.String
	var name string
	var seen bool
	for !extensions.Empty() {
		var kind uint16
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&field) {
			return "", invalid
		}
		if kind != 0 {
			continue
		}
		var names cryptobyte.String
		if seen || !field.ReadUint16LengthPrefixed(&names) || names.Empty() || !field.Empty() {
			return "", invalid
		}
		seen = true
		var err error
		name, err = parseNameList(names, invalid)
		if err != nil {
			return "", err
		}
	}
	return name, nil
}

func parseNameList(names cryptobyte.String, invalid error) (string, error) {
	var field cryptobyte.String
	var name string
	for !names.Empty() {
		var typ uint8
		if !names.ReadUint8(&typ) || !names.ReadUint16LengthPrefixed(&field) || field.Empty() {
			return "", invalid
		}
		if typ == 0 {
			if name != "" {
				return "", invalid
			}
			name = strings.ToLower(string(field))
		}
	}
	return name, nil
}

type edgeListener struct {
	net.Listener

	port    uint16
	mode    string
	proxy   *Plane
	done    <-chan struct{}
	cancel  context.CancelFunc
	ready   chan net.Conn
	slots   chan struct{}
	stopped chan struct{}
	err     error
}

func wrapListener(
	parent context.Context,
	listener net.Listener,
	plane *Plane,
	port uint16,
	mode string,
) *edgeListener {
	ctx, cancel := context.WithCancel(parent)
	l := &edgeListener{
		Listener: listener, port: port, mode: mode, proxy: plane, done: ctx.Done(), cancel: cancel,
		ready: make(chan net.Conn), slots: make(chan struct{}, 128), stopped: make(chan struct{}),
	}
	go l.run(ctx)
	return l
}

func (l *edgeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.stopped:
		return nil, l.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *edgeListener) Close() error {
	l.cancel()
	return l.Listener.Close()
}

func (l *edgeListener) run(ctx context.Context) {
	var workers sync.WaitGroup
	defer close(l.stopped)
	defer workers.Wait()
	defer l.cancel()
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.err = err
			return
		}
		select {
		case l.slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		workers.Go(func() {
			ready, upstream, fence := l.prepare(ctx, c)
			<-l.slots
			if upstream != nil {
				streamCtx, finish := fence.track(ctx)
				defer finish()
				splice(streamCtx, ready, upstream, defaultDeadline)
			} else if ready != nil {
				select {
				case l.ready <- ready:
				case <-l.done:
					_ = ready.Close()
				}
			} else {
				_ = c.Close()
			}
		})
	}
}

func (l *edgeListener) prepare(ctx context.Context, c net.Conn) (net.Conn, net.Conn, *hostFence) {
	state := l.proxy.state.Load()
	port := state.ports[l.port]
	if port == nil || port.mode != l.mode {
		return nil, nil, nil
	}
	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, nil, nil
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	client := prepareSource(c, port)
	if client == nil {
		return nil, nil, nil
	}
	if port.mode == redirectMode {
		if err := client.SetDeadline(time.Time{}); err != nil {
			return nil, nil, nil
		}
		return client, nil, nil
	}
	sni, replay, err := peekHello(client)
	if err != nil {
		l.proxy.metrics.handshake("malformed")
		return nil, nil, nil
	}
	host := port.hosts[sni]
	if host == nil || (!host.tlsAvailable(time.Now()) && host.passthrough == nil) {
		l.proxy.metrics.handshake("unrecognized_name")
		if _, err := client.Write([]byte{21, 3, 3, 0, 2, 2, 112}); err != nil {
			l.proxy.metrics.handshake("alert_write_failed")
		}
		return nil, nil, nil
	}
	client.replay = bytes.NewReader(replay)
	return l.establish(ctx, c, client, host)
}

func (l *edgeListener) establish(
	ctx context.Context,
	c net.Conn,
	client *sourceConn,
	host *edgeHost,
) (net.Conn, net.Conn, *hostFence) {
	if host.passthrough != nil {
		upstream, err := host.passthrough.dialStream(
			ctx,
			client.source.AddrPort(),
			addrPort(c.LocalAddr()),
		)
		if err != nil {
			l.proxy.metrics.handshake("passthrough_error")
			return nil, nil, nil
		}
		l.proxy.metrics.handshake("passthrough")
		return client, upstream, host.fence
	}
	client.trustKey = host.authKey
	secure := tls.Server(client, host.tls)
	if err := secure.HandshakeContext(ctx); err != nil {
		l.proxy.metrics.handshake("failed")
		return nil, nil, nil
	}
	l.proxy.metrics.handshake("ok")
	if err := secure.SetDeadline(time.Time{}); err != nil {
		return nil, nil, nil
	}
	return secure, nil, nil
}

func prepareSource(c net.Conn, port *edgePort) *sourceConn {
	socket := addrPort(c.RemoteAddr())
	source := socket
	proxy := port.identity == "proxyProtocol"
	if proxy {
		if !port.trusts(socket.Addr()) {
			return nil
		}
		var err error
		source, err = readProxyV2(c)
		if err != nil {
			return nil
		}
	}
	return &sourceConn{
		Conn:     c,
		source:   net.TCPAddrFromAddrPort(source),
		socket:   socket.Addr(),
		identity: port.identity,
	}
}

func addrPort(addr net.Addr) netip.AddrPort {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		return netip.AddrPortFrom(ap.Addr().WithZone("").Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func splice(ctx context.Context, a, b net.Conn, idle time.Duration) {
	defer a.Close()
	defer b.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = a.Close()
		_ = b.Close()
	})
	defer stop()
	done := make(chan struct{})
	copyHalf := func(dst, src net.Conn) {
		_, err := io.Copy(idleConn{dst, idle}, idleConn{src, idle})
		if half, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			if err := half.CloseWrite(); err != nil {
				_ = dst.Close()
			}
		} else {
			_ = dst.Close()
		}
	}
	go func() {
		copyHalf(b, a)
		close(done)
	}()
	copyHalf(a, b)
	<-done
}

type idleConn struct {
	net.Conn

	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
