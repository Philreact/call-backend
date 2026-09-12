package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestAdmissionBoundAndDeadline(t *testing.T) {
	g := newAdmissionGate()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var leases []*admissionLease
	for i := 0; i < 256; i++ {
		c, err := g.admit(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, c.Value(admissionKey{}).(*admissionLease))
	}
	if !g.retry(nil) {
		t.Fatal("Retry not enabled under load")
	}
	if _, err := g.admit(ctx, nil); err == nil {
		t.Fatal("unbounded admission")
	}
	for _, l := range leases {
		l.release()
		l.release()
	}
	if len(g.pending) != 0 || len(g.active) != 256 {
		t.Fatal("incorrect lease accounting")
	}
	if _, err := g.admit(ctx, nil); err == nil {
		t.Fatal("active capacity bypass")
	}
	var closed atomic.Bool
	old := &admissionLease{started: time.Now().Add(-11 * time.Second), release: func() { t.Error("expired attach released as authenticated") }}
	if guardAttachment(ctx, old, func() { closed.Store(true) })() {
		t.Fatal("expired authentication accepted")
	}
	deadline := time.Now().Add(time.Second)
	for !closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !closed.Load() {
		t.Fatal("expired connection not closed")
	}
	cancel()
	deadline = time.Now().Add(time.Second)
	for len(g.active) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(g.active) != 0 {
		t.Fatal("active slots leaked")
	}
}
func TestTunnelConfiguration(t *testing.T) {
	c := privateQUICConfig()
	if c.InitialPacketSize != 1200 || !c.DisablePathMTUDiscovery || c.MaxIncomingStreams != 33 || c.MaxIncomingUniStreams != -1 || c.KeepAlivePeriod <= 0 {
		t.Fatal("tunnel safety regression")
	}
}
func TestAggregateWindowBudget(t *testing.T) {
	g := newAdmissionGate()
	conn := new(quic.Conn)
	lease := &admissionLease{}
	g.connections[conn] = lease
	if !g.grow(conn, 256*1024*1024) || g.grow(conn, 1) {
		t.Fatal("window budget bypass")
	}
	if lease.extra != g.extra {
		t.Fatal("lease window accounting mismatch")
	}
	lease.closed = true
	if g.grow(conn, 0) || g.grow(new(quic.Conn), 1) {
		t.Fatal("closed/unregistered connection grew")
	}
}
func TestBatchBoundsAndNoCiphertextInMetadata(t *testing.T) {
	data := make([]byte, 22+8+28)
	copy(data, "QFB1")
	binary.BigEndian.PutUint16(data[20:22], 1)
	binary.BigEndian.PutUint32(data[26:30], 28)
	copy(data[30:], bytes.Repeat([]byte{0xaa}, 28))
	r, err := parseBatch(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(r)
	if bytes.Contains(encoded, []byte("qqqq")) || bytes.Contains(encoded, []byte(`"data"`)) {
		t.Fatal("ciphertext crossed IPC")
	}
	for _, bad := range [][]byte{nil, data[:len(data)-1], append(append([]byte{}, data...), 0)} {
		if _, err := parseBatch(bad); err == nil {
			t.Fatal("malformed batch accepted")
		}
	}
	header := make([]byte, 12)
	copy(header, "QP3F")
	header[4] = 1
	binary.BigEndian.PutUint32(header[8:], maxPayload+1)
	if _, _, err := readHeader(bytes.NewReader(header)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}
func TestNativeDiskBeforeCommitAndFailures(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable", true: "missing-blob"}[missing], func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, "locks"), 0700); err != nil {
				t.Fatal(err)
			}
			id := "abababababababababababababababab"
			path := filepath.Join(directory, id+".bin")
			if !missing {
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			data := bytes.Repeat([]byte{42}, chunkSize+28)
			hash := sha256.Sum256(data)
			r := fileRequest{ID: id, Chunks: []chunk{{Index: 0, Length: len(data), Digest: hex.EncodeToString(hash[:]), data: data}}}
			left, right := net.Pipe()
			c := newControl(left)
			defer left.Close()
			defer right.Close()
			var commits atomic.Int32
			go func() {
				scanner := bufio.NewScanner(right)
				for scanner.Scan() {
					var message controlMessage
					_ = json.Unmarshal(scanner.Bytes(), &message)
					encoded, _ := json.Marshal(message.Metadata)
					var query fileRequest
					_ = json.Unmarshal(encoded, &query)
					if query.Op == "commit" {
						stored, err := os.ReadFile(path)
						if err != nil || !bytes.Equal(stored, data) {
							t.Error("commit before bytes reached file")
						}
						commits.Add(1)
					}
					response := controlMessage{ID: message.ID, OK: true, Result: json.RawMessage(`{"write":[0],"received":[0],"lease":"0123456789abcdef0123456789abcdef"}`)}
					b, _ := json.Marshal(response)
					_, _ = right.Write(append(b, '\n'))
				}
			}()
			_, err := fileOperation(context.Background(), c, "test", directory, r)
			if missing {
				if err == nil || commits.Load() != 0 {
					t.Fatal("failed write committed")
				}
			} else if err != nil || commits.Load() != 1 {
				t.Fatalf("write failed: %v", err)
			}
		})
	}
}
func TestControlEOFUnblocksRequests(t *testing.T) {
	left, right := net.Pipe()
	c := newControl(left)
	go func() { bufio.NewReader(right).ReadBytes('\n'); right.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.call(ctx, controlMessage{Op: "test"}); err == nil {
		t.Fatal("control disconnect ignored")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) != 0 {
		t.Fatal("request leaked")
	}
}

func TestDownloadsShareLocksButBlockDeletion(t *testing.T) {
	directory := t.TempDir()
	_ = os.Mkdir(filepath.Join(directory, "locks"), 0700)
	id := "abababababababababababababababab"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := lockFile(ctx, directory, id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := lockFile(ctx, directory, id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	blocked, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if lock, err := lockFile(blocked, directory, id, true); err == nil {
		lock.Close()
		t.Fatal("write bypassed active readers")
	}
	first.Close()
	second.Close()
	writer, err := lockFile(ctx, directory, id, true)
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
}

func TestBatchDownloadReadsOrderedCiphertext(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "locks"), 0700); err != nil {
		t.Fatal(err)
	}
	id := "abababababababababababababababab"
	first := bytes.Repeat([]byte{1}, chunkSize+28)
	second := bytes.Repeat([]byte{2}, chunkSize+28)
	if err := os.WriteFile(filepath.Join(directory, id+".bin"), append(first, second...), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	c := newControl(left)
	defer left.Close()
	defer right.Close()
	go func() {
		scanner := bufio.NewScanner(right)
		if scanner.Scan() {
			var message controlMessage
			_ = json.Unmarshal(scanner.Bytes(), &message)
			response := controlMessage{ID: message.ID, OK: true,
				Result: json.RawMessage(`{"indices":[1,0],"lengths":[32796,32796]}`)}
			encoded, _ := json.Marshal(response)
			_, _ = right.Write(append(encoded, '\n'))
		}
	}()
	result, err := fileDownloadBatch(context.Background(), c, "test", directory,
		fileRequest{ID: id, Indices: []int{1, 0}})
	if err != nil {
		t.Fatal(err)
	}
	if string(result[:4]) != "QFD1" || binary.BigEndian.Uint16(result[4:6]) != 2 {
		t.Fatal("invalid batch header")
	}
	offset := 6
	for position, expected := range [][]byte{second, first} {
		if int(binary.BigEndian.Uint32(result[offset:offset+4])) != 1-position ||
			int(binary.BigEndian.Uint32(result[offset+4:offset+8])) != len(expected) {
			t.Fatal("invalid chunk descriptor")
		}
		offset += 8
		if !bytes.Equal(result[offset:offset+len(expected)], expected) {
			t.Fatal("wrong ciphertext")
		}
		offset += len(expected)
	}
	if offset != len(result) {
		t.Fatal("trailing batch data")
	}
}
