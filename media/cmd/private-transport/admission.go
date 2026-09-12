package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type admissionKey struct{}
type admissionLease struct {
	started time.Time
	release func()
	conn    *quic.Conn
	extra   uint64
	closed  bool
}
type admissionGate struct {
	pending, active chan struct{}
	mu              sync.Mutex
	extra           uint64
	connections     map[*quic.Conn]*admissionLease
}

func newAdmissionGate() *admissionGate {
	return &admissionGate{pending: make(chan struct{}, 256), active: make(chan struct{}, 256), connections: make(map[*quic.Conn]*admissionLease)}
}
func (g *admissionGate) retry(net.Addr) bool { return len(g.pending) >= 64 }
func (g *admissionGate) admit(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	select {
	case g.active <- struct{}{}:
	default:
		return nil, errors.New("connection capacity")
	}
	select {
	case g.pending <- struct{}{}:
	default:
		<-g.active
		return nil, errors.New("pending capacity")
	}
	var once sync.Once
	release := func() { once.Do(func() { <-g.pending }) }
	lease := &admissionLease{started: time.Now(), release: release}
	context.AfterFunc(ctx, func() {
		g.mu.Lock()
		lease.closed = true
		g.extra -= lease.extra
		delete(g.connections, lease.conn)
		g.mu.Unlock()
		release()
		<-g.active
	})
	return context.WithValue(ctx, admissionKey{}, lease), nil
}
func (g *admissionGate) bind(conn *quic.Conn) {
	lease := conn.Context().Value(admissionKey{}).(*admissionLease)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !lease.closed {
		lease.conn = conn
		g.connections[conn] = lease
	}
}
func (g *admissionGate) grow(conn *quic.Conn, delta uint64) bool {
	// No connection methods here: quic-go invokes this inside flow control.
	g.mu.Lock()
	defer g.mu.Unlock()
	lease := g.connections[conn]
	// 256 MiB growth + at most 256 initial 1 MiB windows = 512 MiB.
	const growthBudget = 256 * 1024 * 1024
	if lease == nil || lease.closed || delta > growthBudget-g.extra {
		return false
	}
	g.extra += delta
	lease.extra += delta
	return true
}
func guardAttachment(ctx context.Context, lease *admissionLease, closeConn func()) func() bool {
	deadline := lease.started.Add(10 * time.Second)
	var mu sync.Mutex
	expired := false
	timer := time.AfterFunc(time.Until(deadline), func() { mu.Lock(); defer mu.Unlock(); expired = true; closeConn() })
	context.AfterFunc(ctx, func() { timer.Stop() })
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if expired || ctx.Err() != nil || !time.Now().Before(deadline) || !timer.Stop() {
			return false
		}
		lease.release()
		return true
	}
}

func privateQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 120 * time.Second, KeepAlivePeriod: 20 * time.Second,
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true,
		MaxIncomingStreams: 33, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 512 * 1024, MaxStreamReceiveWindow: 8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 1024 * 1024, MaxConnectionReceiveWindow: 8 * 1024 * 1024,
	}
}
