package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const maxPendingConnections = 256
const attachDeadline = 10 * time.Second

type admissionKey struct{}
type admissionLease struct {
	once        sync.Once
	started     time.Time
	releaseSlot func()
}

func (l *admissionLease) release() { l.once.Do(l.releaseSlot) }

// A global pending budget, not an IP budget: a relay represents many users.
type admissionGate struct{ slots chan struct{} }

func newAdmissionGate() *admissionGate {
	return &admissionGate{slots: make(chan struct{}, maxPendingConnections)}
}
func (g *admissionGate) admit(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	select {
	case g.slots <- struct{}{}:
	default:
		return nil, errors.New("unauthenticated connection capacity reached")
	}
	l := &admissionLease{started: time.Now(), releaseSlot: func() { <-g.slots }}
	context.AfterFunc(ctx, l.release)
	return context.WithValue(ctx, admissionKey{}, l), nil
}
func (g *admissionGate) retry(net.Addr) bool { return len(g.slots) >= 64 }

// Start before MOQT setup; activity cannot extend the absolute deadline.
func guardAttachment(conn *quic.Conn) func() bool {
	l, _ := conn.Context().Value(admissionKey{}).(*admissionLease)
	remaining := attachDeadline
	if l != nil {
		remaining = time.Until(l.started.Add(attachDeadline))
	}
	deadline := time.Now().Add(remaining)
	var mu sync.Mutex
	expired := false
	timer := time.AfterFunc(remaining, func() {
		mu.Lock()
		defer mu.Unlock()
		expired = true
		_ = conn.CloseWithError(2, "authentication deadline exceeded")
	})
	context.AfterFunc(conn.Context(), func() { timer.Stop() })
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if expired || !time.Now().Before(deadline) || !timer.Stop() {
			return false
		}
		if l != nil {
			l.release()
		}
		return true
	}
}
