package main

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestPendingAdmissionBudget(t *testing.T) {
	g := newAdmissionGate()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var first context.Context
	for i := 0; i < maxPendingConnections; i++ {
		admitted, err := g.admit(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = admitted
		}
	}
	if _, err := g.admit(ctx, nil); err == nil {
		t.Fatal("admitted beyond capacity")
	}
	if !g.retry(nil) {
		t.Fatal("expected address validation under load")
	}
	l := first.Value(admissionKey{}).(*admissionLease)
	l.release() // Authentication frees a slot while the connection stays alive.
	l.release() // Later connection teardown must not release another slot.
	if len(g.slots) != maxPendingConnections-1 {
		t.Fatal("incorrect release")
	}
	if _, err := g.admit(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for len(g.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(g.slots) != 0 {
		t.Fatal("failed handshakes leaked admission slots")
	}
}

func TestAttachmentDeadlineAndAuthenticatedSurvival(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "authenticated"}[authenticated], func(t *testing.T) {
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			gate := newAdmissionGate()
			transport := &quic.Transport{Conn: udp, ConnContext: gate.admit}
			defer transport.Close()
			listener, err := transport.Listen(&tls.Config{
				Certificates: []tls.Certificate{testTLSCertificate(t)}, NextProtos: []string{"admission-test"},
			}, mediaServerQUICConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
				InsecureSkipVerify: true, NextProtos: []string{"admission-test"},
			}, &quic.Config{KeepAlivePeriod: 10 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(0, "test finished")
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			lease := server.Context().Value(admissionKey{}).(*admissionLease)
			lease.started = time.Now().Add(-attachDeadline + 100*time.Millisecond)
			markAuthenticated := guardAttachment(server)
			if authenticated {
				if !markAuthenticated() {
					t.Fatal("authentication rejected")
				}
				time.Sleep(200 * time.Millisecond)
				if server.Context().Err() != nil {
					t.Fatal("authenticated connection expired")
				}
				if len(gate.slots) != 0 {
					t.Fatal("authenticated connection still uses pending budget")
				}
			} else {
				select {
				case <-client.Context().Done():
				case <-ctx.Done():
					t.Fatal("unauthenticated connection survived deadline")
				}
				if markAuthenticated() {
					t.Fatal("late authentication accepted")
				}
			}
		})
	}
}
