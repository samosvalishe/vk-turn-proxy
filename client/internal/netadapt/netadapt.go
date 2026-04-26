// Package netadapt contains thin net.Conn / transport.Net adapters used by
// the TURN/DTLS code paths: direct net wiring for pion/turn, a connected-UDP
// shim that ignores WriteTo addrs, byte-counters, and a relay PacketConn that
// forces all writes to a fixed TURN peer.
package netadapt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/transport/v4"
)

type directNet struct{}

type directDialer struct {
	*net.Dialer
}

type directListenConfig struct {
	*net.ListenConfig
}

// NewDirectNet returns a transport.Net implementation that delegates straight
// to the stdlib net package without any wrapping.
func NewDirectNet() transport.Net {
	return directNet{}
}

func (directNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (directNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}

func (directNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	return directTCPListener{listener}, nil
}

func (directNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (directNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func (directNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}

func (directNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}

func (directNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (directNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}

func (directNet) Interfaces() ([]*transport.Interface, error) {
	return nil, transport.ErrNotSupported
}

func (directNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

func (directNet) InterfaceByName(name string) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (directNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return directDialer{Dialer: dialer}
}

func (directNet) CreateListenConfig(listenerConfig *net.ListenConfig) transport.ListenConfig {
	return directListenConfig{ListenConfig: listenerConfig}
}

func (d directDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}

func (d directListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}

func (d directListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.ListenConfig.ListenPacket(ctx, network, address)
}

type directTCPListener struct {
	*net.TCPListener
}

func (l directTCPListener) AcceptTCP() (transport.TCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

// ConnectedUDPConn wraps a connected *net.UDPConn so WriteTo ignores the
// caller-supplied address and writes via the connected fd.
type ConnectedUDPConn struct {
	*net.UDPConn
}

func (c *ConnectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

// CountingConn tallies bytes read/written through an embedded net.Conn.
type CountingConn struct {
	net.Conn
	BytesWritten atomic.Int64
	BytesRead    atomic.Int64
}

func (c *CountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.BytesRead.Add(int64(n))
	}
	return n, err
}

func (c *CountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.BytesWritten.Add(int64(n))
	}
	return n, err
}

// ClassifyNetErr returns a short tag for common network error classes, used
// to keep log lines compact. Returns "nil" for nil err.
func ClassifyNetErr(err error) string {
	if err == nil {
		return "nil"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "ctx-deadline"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "rst"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if errors.Is(err, syscall.EPIPE) {
		return "broken-pipe"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "net-timeout"
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return "op:" + oe.Op
	}
	return "other"
}

// RelayPacketConn wraps a TURN relay PacketConn so all writes go to a fixed peer.
type RelayPacketConn struct {
	Relay net.PacketConn
	Peer  net.Addr
}

func (r *RelayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return r.Relay.ReadFrom(b)
}

func (r *RelayPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return r.Relay.WriteTo(b, r.Peer)
}

func (r *RelayPacketConn) Close() error                       { return r.Relay.Close() }
func (r *RelayPacketConn) LocalAddr() net.Addr                { return r.Relay.LocalAddr() }
func (r *RelayPacketConn) SetDeadline(t time.Time) error      { return r.Relay.SetDeadline(t) }
func (r *RelayPacketConn) SetReadDeadline(t time.Time) error  { return r.Relay.SetReadDeadline(t) }
func (r *RelayPacketConn) SetWriteDeadline(t time.Time) error { return r.Relay.SetWriteDeadline(t) }
