package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type diagnosticBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *diagnosticBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *diagnosticBuffer) text() string { b.Lock(); defer b.Unlock(); return b.Buffer.String() }

func TestSetupErrorCodesExcludePeerText(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{&quic.ApplicationError{ErrorCode: 7, Remote: true, ErrorMessage: "secret-token"}, "QUIC_APPLICATION_7_REMOTE_true"},
		{&quic.TransportError{ErrorCode: quic.ProtocolViolation, ErrorMessage: "secret-token"}, "QUIC_TRANSPORT_a_REMOTE_false"},
		{&quic.HandshakeTimeoutError{}, "QUIC_HANDSHAKE_TIMEOUT"},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), "DEADLINE_EXCEEDED"},
		{io.ErrUnexpectedEOF, "UNEXPECTED_EOF"},
		{errors.New("BACKEND_ACCESS_DENIED"), "BACKEND_ACCESS_DENIED"},
		{errors.New("secret-token"), "INTERNAL_ERROR"},
	} {
		if got := setupErrorCode(tc.err); got != tc.code {
			t.Errorf("got %q, want %q", got, tc.code)
		}
	}
}

func TestDiagnosticsRateLimitAndSuppressionAccounting(t *testing.T) {
	var output diagnosticBuffer
	d := newTransportDiagnostics(&output)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.record("private_transport_setup_failed", "", "quic_handshake", "CANCELLED", time.Now())
		}()
	}
	wg.Wait()
	if got := strings.Count(output.text(), "\n"); got != 120 {
		t.Fatalf("unbounded logging: %d", got)
	}
	d.mu.Lock()
	d.window = time.Now().Add(-time.Minute)
	d.mu.Unlock()
	d.record("private_transport_setup_failed", "", "quic_handshake", "CANCELLED", time.Now())
	var last map[string]any
	lines := strings.Split(strings.TrimSpace(output.text()), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	if last["suppressed_since_last_log"] != float64(80) {
		t.Fatalf("lost suppression count: %v", last)
	}
}

func diagnosticTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestConnectionSetupDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, stage, code string }{
		{"handshake_rejected", "quic_handshake", "QUIC_TRANSPORT_"},
		{"invalid_header", "read_attach_header", "INVALID_FRAME"},
		{"rejected_token", "authorize_attach", "BACKEND_ACCESS_DENIED"},
		{"expired_grant", "validate_attach_grant", "EXPIRED_ATTACH_GRANT"},
		{"success", "ready", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output diagnosticBuffer
			d := newTransportDiagnostics(&output)
			gate := newAdmissionGate()
			gate.diagnostics = d
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			transport := &quic.Transport{Conn: udp, ConnContext: gate.admit}
			defer transport.Close()
			listener, err := transport.Listen(&tls.Config{Certificates: []tls.Certificate{diagnosticTLS(t)}, NextProtos: []string{"qortal-private/1"}}, privateQUICConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			parent, child := net.Pipe()
			defer child.Close()
			control := newControl(parent)
			defer parent.Close()
			repliesDone := make(chan struct{})
			go func() {
				defer close(repliesDone)
				scanner := bufio.NewScanner(child)
				for scanner.Scan() {
					var req controlMessage
					if json.Unmarshal(scanner.Bytes(), &req) != nil {
						return
					}
					if req.Op != "attach" {
						continue
					}
					reply := controlMessage{ID: req.ID, OK: true, Result: json.RawMessage(fmt.Sprintf(`{"logicalSessionId":"test-session","expiresAt":%d}`, time.Now().Add(time.Minute).UnixMilli()))}
					if tc.name == "rejected_token" {
						reply.OK = false
						reply.Error = "BACKEND_ACCESS_DENIED"
					}
					if tc.name == "expired_grant" {
						reply.Result = json.RawMessage(`{"expiresAt":1}`)
					}
					if json.NewEncoder(child).Encode(reply) != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			served := make(chan struct{})
			go func() {
				defer close(served)
				conn, e := listener.Accept(ctx)
				if e == nil {
					gate.bind(conn)
					(&server{control: control, frames: make(chan struct{}, 32), diagnostics: d}).serve(conn)
				}
			}()
			protocol := "qortal-private/1"
			if tc.name == "handshake_rejected" {
				protocol = "wrong-protocol"
			}
			client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{protocol}}, &quic.Config{EnableDatagrams: true}) // Ephemeral loopback test certificate.
			if tc.name != "handshake_rejected" {
				if err != nil {
					t.Fatal(err)
				}
				stream, e := client.OpenStreamSync(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if tc.name == "invalid_header" {
					_, err = stream.Write([]byte("bad-header!!"))
				} else {
					err = writeFrame(stream, 1, []byte(`{"attachToken":"secret-token"}`), nil)
				}
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				client.CloseWithError(0, "")
				t.Fatal("bad ALPN accepted")
			}
			deadline := time.Now().Add(3 * time.Second)
			for output.text() == "" && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if client != nil {
				client.CloseWithError(0, "")
			}
			cancel()
			listener.Close()
			select {
			case <-served:
			case <-time.After(time.Second):
				t.Fatal("server did not exit")
			}
			child.Close()
			parent.Close()
			<-repliesDone
			text := output.text()
			if strings.Contains(text, "secret-token") {
				t.Fatal("token leaked into diagnostics")
			}
			lines := strings.Split(strings.TrimSpace(text), "\n")
			if len(lines) != 1 {
				t.Fatalf("expected one terminal setup record, got %q", text)
			}
			var row map[string]any
			if err = json.Unmarshal([]byte(lines[0]), &row); err != nil {
				t.Fatal(err)
			}
			if row["stage"] != tc.stage || !strings.HasPrefix(fmt.Sprint(row["error_code"]), tc.code) {
				t.Fatalf("wrong diagnosis: %v", row)
			}
			want := "private_transport_setup_failed"
			if tc.name == "success" {
				want = "private_transport_setup_complete"
			}
			if row["event"] != want {
				t.Fatalf("wrong event: %v", row)
			}
		})
	}
}
