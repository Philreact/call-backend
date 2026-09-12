// Native private transport. Application control stays in Python; encrypted
// file bytes go directly between QUIC streams and bounded disk workers.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/quic-go/quic-go"
)

const maxPayload = 1024 * 1024

type frame struct {
	kind              byte
	metadata, payload []byte
}
type server struct {
	control *control
	files   string
	frames  chan struct{}
}

func acquire(ctx context.Context, slots chan struct{}) error {
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func readHeader(r io.Reader) (frame, int, error) {
	var h [12]byte
	_, err := io.ReadFull(r, h[:])
	if err != nil {
		return frame{}, 0, err
	}
	m, n := int(binary.BigEndian.Uint16(h[6:8])), int(binary.BigEndian.Uint32(h[8:12]))
	if string(h[:4]) != "QP3F" || h[4] != 1 || m > 4096 || n > maxPayload {
		return frame{}, 0, errors.New("invalid frame")
	}
	return frame{kind: h[5], metadata: make([]byte, m)}, n, nil
}
func writeFrame(stream *quic.Stream, kind byte, metadata, payload []byte) error {
	if len(metadata) > 4096 || len(payload) > maxPayload {
		return errors.New("frame too large")
	}
	h := make([]byte, 12)
	copy(h, "QP3F")
	h[4] = 1
	h[5] = kind
	binary.BigEndian.PutUint16(h[6:8], uint16(len(metadata)))
	binary.BigEndian.PutUint32(h[8:12], uint32(len(payload)))
	_ = stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
	for _, part := range [][]byte{h, metadata, payload} {
		if _, err := stream.Write(part); err != nil {
			return err
		}
	}
	return nil
}
func (s *server) application(ctx context.Context, connection, lane, messageID string, payload []byte) []byte {
	if len(payload) == 0 {
		return applicationResult(nil, errors.New("INVALID_REQUEST"))
	}
	if payload[0] == 1 {
		if lane != "reliable" {
			return applicationResult(nil, errors.New("INVALID_REQUEST"))
		}
		r, err := parseBatch(payload[1:])
		if err != nil {
			return applicationResult(nil, err)
		}
		result, err := fileOperation(ctx, s.control, connection, s.files, r)
		return applicationResult(result, err)
	}
	if payload[0] != 0 || len(payload) > 64*1024 || !json.Valid(payload[1:]) {
		return applicationResult(nil, errors.New("INVALID_REQUEST"))
	}
	var r fileRequest
	if json.Unmarshal(payload[1:], &r) != nil {
		return applicationResult(nil, errors.New("INVALID_REQUEST"))
	}
	if r.Type == "file_request" && (r.Op == "get" || r.Op == "put") {
		if lane != "reliable" {
			return applicationResult(nil, errors.New("INVALID_REQUEST"))
		}
		if r.Op == "put" {
			data, err := base64.StdEncoding.Strict().DecodeString(r.Chunk)
			if err != nil || len(data) < 28 || len(data) > chunkSize+28 {
				return applicationResult(nil, errors.New("INVALID_CHUNK"))
			}
			hash := sha256.Sum256(data)
			r.Chunks = []chunk{{Index: r.Index, Length: len(data), Digest: hex.EncodeToString(hash[:]), data: data}}
			r.Chunk = "" // Ciphertext must never be serialized to the control plane.
		}
		result, err := fileOperation(ctx, s.control, connection, s.files, r)
		return applicationResult(result, err)
	}
	// Reject bulk encodings not handled above instead of accidentally forwarding
	// their bytes through Python. Ordinary control is deliberately bounded JSON.
	if r.Type == "file_request" && r.Op == "put_batch" {
		return applicationResult(nil, errors.New("INVALID_REQUEST"))
	}
	result, err := s.control.call(ctx, controlMessage{Op: "message", Connection: connection, Lane: lane, MessageID: messageID, Metadata: json.RawMessage(payload[1:])})
	if err != nil {
		return applicationResult(nil, err)
	}
	return append([]byte{0}, result...)
}
func (s *server) serve(conn *quic.Conn) {
	ctx := conn.Context()
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return
	}
	id := hex.EncodeToString(idBytes)
	closeConn := func() { _ = conn.CloseWithError(0x102, "application session unavailable") }
	s.control.mu.Lock()
	s.control.closers[id] = closeConn
	s.control.mu.Unlock()
	defer func() {
		closeConn()
		s.control.mu.Lock()
		delete(s.control.closers, id)
		s.control.mu.Unlock()
		_ = s.control.send(controlMessage{Op: "detach", Connection: id})
	}()
	lease := ctx.Value(admissionKey{}).(*admissionLease)
	attached := guardAttachment(ctx, lease, closeConn)
	primary, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	_ = primary.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, n, err := readHeader(primary)
	if err != nil || first.kind != 1 || n != 0 {
		return
	}
	if _, err = io.ReadFull(primary, first.metadata); err != nil {
		return
	}
	result, err := s.control.call(ctx, controlMessage{Op: "attach", Connection: id, Peer: conn.RemoteAddr().String(), Metadata: json.RawMessage(first.metadata)})
	if err != nil {
		_ = writeFrame(primary, 2, []byte(`{"ok":false,"code":"ATTACH_TOKEN_REJECTED","transportGeneration":1,"reliable":true,"datagrams":true}`), nil)
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
		}
		return
	}
	var grant struct {
		LogicalSessionID string `json:"logicalSessionId"`
		ExpiresAt        int64  `json:"expiresAt"`
	}
	if json.Unmarshal(result, &grant) != nil || grant.ExpiresAt <= time.Now().UnixMilli() || !attached() {
		return
	}
	go s.watchSession(ctx, id, grant.ExpiresAt, closeConn)
	metadata, _ := json.Marshal(map[string]any{"ok": true, "logicalSessionId": grant.LogicalSessionID, "transportGeneration": 1, "reliable": true, "datagrams": true, "reliableStreams": true, "maxReliablePayloadBytes": maxPayload})
	if writeFrame(primary, 2, metadata, nil) != nil {
		return
	}
	_ = primary.SetReadDeadline(time.Time{})
	slots := make(chan struct{}, 8)
	var workers sync.WaitGroup
	var routes sync.Map
	runStream := func(stream *quic.Stream, isPrimary bool) {
		workers.Add(1)
		go func() { defer workers.Done(); s.stream(conn, id, stream, isPrimary, slots, &routes) }()
	}
	runStream(primary, true)
	workers.Add(1)
	go func() { defer workers.Done(); s.datagrams(conn, id, slots) }()
	var streamCount atomic.Int32
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			break
		}
		if streamCount.Add(1) > 32 {
			streamCount.Add(-1)
			stream.CancelRead(0x100)
			stream.CancelWrite(0x100)
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer streamCount.Add(-1)
			s.stream(conn, id, stream, false, slots, &routes)
		}()
	}
	workers.Wait()
}

// Session activity may legitimately extend Python's session expiry. Revalidate
// only at the known deadline; logout/revocation still closes immediately via IPC.
func (s *server) watchSession(ctx context.Context, id string, expiry int64, closeConn func()) {
	for {
		timer := time.NewTimer(time.Until(time.UnixMilli(expiry)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		result, err := s.control.call(ctx, controlMessage{Op: "validate", Connection: id})
		var lease struct {
			ExpiresAt int64 `json:"expiresAt"`
		}
		if err != nil || json.Unmarshal(result, &lease) != nil || lease.ExpiresAt <= time.Now().UnixMilli() {
			closeConn()
			return
		}
		expiry = lease.ExpiresAt
	}
}
func (s *server) stream(conn *quic.Conn, id string, stream *quic.Stream, primary bool, slots chan struct{}, routes *sync.Map) {
	ctx, cancel := context.WithCancel(conn.Context())
	defer cancel()
	var writes sync.Mutex
	var work sync.WaitGroup
	graceful := false
	defer func() {
		if !graceful || primary {
			cancel()
			stream.CancelRead(0x100)
			stream.CancelWrite(0x100)
			if primary {
				_ = conn.CloseWithError(0x100, "primary stream ended")
			}
		}
		work.Wait()
		if graceful && !primary {
			_ = stream.Close()
		}
	}()
	for {
		f, n, err := readHeader(stream)
		if err != nil {
			graceful = err == io.EOF
			return
		}
		if f.kind != 3 {
			return
		}
		if err = acquire(ctx, slots); err != nil {
			return
		}
		if err = acquire(ctx, s.frames); err != nil {
			<-slots
			return
		}
		release := func() { <-s.frames; <-slots }
		_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
		f.payload = make([]byte, n)
		_, err = io.ReadFull(stream, f.metadata)
		if err == nil {
			_, err = io.ReadFull(stream, f.payload)
		}
		_ = stream.SetReadDeadline(time.Time{})
		if err != nil {
			release()
			return
		}
		var meta struct {
			MessageID string `json:"messageId"`
		}
		if json.Unmarshal(f.metadata, &meta) != nil || len(meta.MessageID) < 1 || len(meta.MessageID) > 128 {
			release()
			return
		}
		if _, loaded := routes.LoadOrStore(meta.MessageID, true); loaded {
			release()
			return
		}
		work.Add(1)
		go func(f frame, messageID string) {
			defer work.Done()
			defer release()
			defer routes.Delete(messageID)
			result := s.application(ctx, id, "reliable", messageID, f.payload)
			if ctx.Err() != nil {
				return
			}
			writes.Lock()
			defer writes.Unlock()
			if writeFrame(stream, 3, f.metadata, result) != nil {
				cancel()
				stream.CancelRead(0x100)
				stream.CancelWrite(0x100)
			}
		}(f, meta.MessageID)
	}
}
func (s *server) datagrams(conn *quic.Conn, id string, slots chan struct{}) {
	for {
		data, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		if len(data) < 7 || string(data[:4]) != "QP3D" || data[4] != 1 {
			continue
		}
		n := int(binary.BigEndian.Uint16(data[5:7]))
		if n < 1 || n > 128 || len(data) < 7+n || len(data)-7-n > 1024 || !utf8.Valid(data[7:7+n]) {
			continue
		}
		// Diagnostics are low-volume; serial handling prevents unbounded datagram work.
		result := s.application(conn.Context(), id, "datagram", string(data[7:7+n]), data[7+n:])
		if len(result) <= 1024 {
			_ = conn.SendDatagram(append(data[:7+n:7+n], result...))
		}
	}
}
func main() {
	listen := flag.String("listen", "127.0.0.1:4445", "UDP listen endpoint")
	certificate := flag.String("certificate", "", "certificate path")
	key := flag.String("key", "", "private key path")
	fd := flag.Int("control-fd", 3, "inherited private control socket")
	files := flag.String("files", "", "ciphertext directory")
	flag.Parse()
	if *files == "" {
		log.Fatal("file directory required")
	}
	pair, err := tls.LoadX509KeyPair(*certificate, *key)
	if err != nil {
		log.Fatal(err)
	}
	inherited := os.NewFile(uintptr(*fd), "control")
	socket, err := net.FileConn(inherited)
	inherited.Close()
	if err != nil {
		log.Fatal(err)
	}
	c := newControl(socket)
	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	// quic-go configures large kernel buffers and batched packet I/O itself.
	gate := newAdmissionGate()
	transport := quic.Transport{Conn: udp, VerifySourceAddress: gate.retry, ConnContext: gate.admit}
	defer transport.Close()
	configuration := privateQUICConfig()
	configuration.AllowConnectionWindowIncrease = gate.grow
	listener, err := transport.Listen(&tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"qortal-private/1"}, MinVersion: tls.VersionTLS13}, configuration)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("{\"port\":%d}\n", udp.LocalAddr().(*net.UDPAddr).Port)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go func() {
		select {
		case <-c.done:
		case <-ctx.Done():
		}
		cancel()
		listener.Close()
		transport.Close()
	}()
	srv := server{control: c, files: *files, frames: make(chan struct{}, 32)}
	var workers sync.WaitGroup
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			break
		}
		gate.bind(conn)
		workers.Add(1)
		go func() {
			defer workers.Done()
			srv.serve(conn)
		}()
	}
	workers.Wait()
}
