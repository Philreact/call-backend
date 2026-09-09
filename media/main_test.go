package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mengelbart/moqtransport"
	"github.com/mengelbart/moqtransport/quicmoq"
	"github.com/quic-go/quic-go"
)

func writeGrant(t *testing.T, directory, token string, expiresAt int64) {
	t.Helper()
	digest := sha256.Sum256([]byte(token))
	digestHex := hex.EncodeToString(digest[:])
	value := grant{
		Version: 1, TokenSHA256: digestHex,
		LogicalSessionID: "logical-session", AuthenticatedUser: "Qparticipant123",
		QAppName: "qapp-ui-call", QAppService: "APP", Purpose: "realtime",
		RoomID: "proof-room", ParticipantID: "Qparticipant123", ExpiresAt: expiresAt,
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, digestHex+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGrantIsValidatedAndConsumedOnce(t *testing.T) {
	directory := t.TempDir()
	store := grantStore{directory: directory}
	token := "one-time-call-media-token-000000000000"
	now := time.Unix(1_800_000_000, 0)
	writeGrant(t, directory, token, now.Add(time.Minute).UnixMilli())
	value, err := store.consume(token, now)
	if err != nil || value.RoomID != "proof-room" {
		t.Fatalf("valid grant rejected: %#v, %v", value, err)
	}
	if _, err = store.consume(token, now); err == nil {
		t.Fatal("one-time grant was accepted twice")
	}
}

func TestGrantUsesAuthenticatedCanonicalQAppNameInsteadOfCompiledName(t *testing.T) {
	directory := t.TempDir()
	store := grantStore{directory: directory}
	token := "development-qapp-media-token-000000000000"
	now := time.Unix(1_800_000_000, 0)
	writeGrant(t, directory, token, now.Add(time.Minute).UnixMilli())
	digest := sha256.Sum256([]byte(token))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value grant
	if err = json.Unmarshal(contents, &value); err != nil {
		t.Fatal(err)
	}
	value.QAppName = "a-test-2"
	contents, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.consume(token, now); err != nil {
		t.Fatalf("authenticated development Q-App name was rejected: %v", err)
	}
}

func TestQAppNameMustRemainCanonical(t *testing.T) {
	for _, value := range []string{"", " Uppercase", "Uppercase", "trailing ", strings.Repeat("a", 129)} {
		if validQAppName(value) {
			t.Fatalf("invalid Q-App name accepted: %q", value)
		}
	}
	if !validQAppName("development-call-app") {
		t.Fatal("canonical Q-App name rejected")
	}
}

func TestMediaServerKeepsSilentCallsAlive(t *testing.T) {
	config := mediaServerQUICConfig()
	if !config.EnableDatagrams || config.KeepAlivePeriod != keepAlivePeriod ||
		config.MaxIdleTimeout != connectionMaxIdle {
		t.Fatalf("unexpected idle media config: %#v", config)
	}
}

func TestExpiredAndMismatchedGrantsAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		token   string
		expires int64
		consume string
	}{
		{"expired", "expired-call-media-token-000000000000", 1, "expired-call-media-token-000000000000"},
		{"wrong token", "issued-call-media-token-00000000000000", 1_900_000_000_000, "other-call-media-token-00000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			writeGrant(t, directory, tc.token, tc.expires)
			if _, err := (grantStore{directory: directory}).consume(tc.consume, time.Unix(1_800_000_000, 0)); err == nil {
				t.Fatal("invalid grant was accepted")
			}
		})
	}
}

func TestGrantStorePurgesExpiredFilesOnly(t *testing.T) {
	directory := t.TempDir()
	store := grantStore{directory: directory}
	now := time.Unix(500, 0)
	writeGrant(t, directory, "expired-token", now.Add(-time.Second).UnixMilli())
	writeGrant(t, directory, "valid-token", now.Add(time.Second).UnixMilli())
	temporary := filepath.Join(directory, ".grant.tmp")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.purgeExpired(now)
	assertGrantFile := func(token string, exists bool) {
		t.Helper()
		digest := sha256.Sum256([]byte(token))
		_, err := os.Stat(filepath.Join(directory, hex.EncodeToString(digest[:])+".json"))
		if exists && err != nil {
			t.Fatalf("expected grant to remain: %v", err)
		}
		if !exists && !os.IsNotExist(err) {
			t.Fatalf("expected grant to be removed, got: %v", err)
		}
	}
	assertGrantFile("expired-token", false)
	assertGrantFile("valid-token", true)
	if _, err := os.Stat(temporary); err != nil {
		t.Fatalf("temporary file was unexpectedly removed: %v", err)
	}
}

type testMediaHandler struct {
	publication chan *moqtransport.IncomingSubscribeRequest
}

func (h *testMediaHandler) HandleGoAway(string) {}

func (h *testMediaHandler) HandleSubscribe(request *moqtransport.IncomingSubscribeRequest) {
	if string(request.Name()) != "audio" {
		request.Reject(moqtransport.RequestErrorCodeUnauthorized, "legacy audio-only test client")
		return
	}
	request.Accept(1)
	h.publication <- request
}

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "call-media-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func connectTestMediaClient(
	t *testing.T, address, directory, token, participant string,
) (*moqtransport.Session, *moqtransport.IncomingSubscribeRequest) {
	t.Helper()
	writeGrant(t, directory, token, time.Now().Add(time.Minute).UnixMilli())
	digest := sha256.Sum256([]byte(token))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value grant
	if err = json.Unmarshal(contents, &value); err != nil {
		t.Fatal(err)
	}
	value.ParticipantID = participant
	value.AuthenticatedUser = participant
	contents, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(ctx, address, &tls.Config{
		InsecureSkipVerify: true, // Test-only ephemeral certificate.
		NextProtos:         []string{moqtransport.MOQT18.String()},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := &testMediaHandler{publication: make(chan *moqtransport.IncomingSubscribeRequest, 1)}
	session, err := moqtransport.NewSession(
		quicmoq.NewClient(connection), "attach/"+token, moqtransport.WithHandler(handler),
	)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case publication := <-handler.publication:
		return session, publication
	case <-ctx.Done():
		t.Fatal("backend did not subscribe to the authenticated publication")
		return nil, nil
	}
}

func TestTwoAuthenticatedClientsBlindForwardDatagram(t *testing.T) {
	directory := t.TempDir()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testTLSCertificate(t)},
		NextProtos:   []string{moqtransport.MOQT18.String()},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	media := newBroker()
	acceptErrors := make(chan error, 2)
	go func() {
		for range 2 {
			connection, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				acceptErrors <- acceptErr
				return
			}
			go handleConnection(connection, grantStore{directory: directory}, revocationStore{directory: t.TempDir()}, media)
		}
	}()

	alice, alicePublication := connectTestMediaClient(
		t, listener.Addr().String(), directory,
		"alice-one-time-media-token-000000000000", "Alice123",
	)
	defer alice.CloseWithError(0, "test complete")
	bob, _ := connectTestMediaClient(
		t, listener.Addr().String(), directory,
		"bob-one-time-media-token-00000000000000", "Bob123",
	)
	defer bob.CloseWithError(0, "test complete")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bobSubscription, err := bob.Subscribe(ctx, [][]byte{
		[]byte("qortal"), []byte("call"), []byte("proof-room"), []byte("Alice123"),
	}, mediaTrackName)
	if err != nil {
		t.Fatal(err)
	}
	for {
		media.mu.RLock()
		count := len(media.subscriptions[trackKey("proof-room", "Alice123")])
		media.mu.RUnlock()
		if count == 1 {
			break
		}
		select {
		case err = <-acceptErrors:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal("subscriber was not authorized")
		case <-time.After(5 * time.Millisecond):
		}
	}
	ciphertext := []byte("opaque-protected-audio-frame")
	if err = alicePublication.SendDatagram(moqtransport.Object{
		GroupID: 4, ObjectID: 9, ForwardingPreference: moqtransport.ObjectForwardingPreferenceDatagram,
		Payload: ciphertext,
	}); err != nil {
		t.Fatal(err)
	}
	object, err := bobSubscription.ReadObject(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(object.Payload) != string(ciphertext) ||
		object.ForwardingPreference != moqtransport.ObjectForwardingPreferenceDatagram {
		t.Fatalf("unexpected forwarded object: %#v", object)
	}
	for _, track := range []string{"screen", "feedback"} {
		sub, subscribeErr := bob.Subscribe(ctx, namespace(grant{RoomID: "proof-room", ParticipantID: "Alice123"}), track)
		if subscribeErr != nil {
			t.Fatal(subscribeErr)
		}
		for {
			media.mu.RLock()
			count := len(media.subscriptions[trackKey("proof-room", "Alice123", track)])
			media.mu.RUnlock()
			if count == 1 {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("track subscription timed out")
			case <-time.After(time.Millisecond):
			}
		}
		media.publish(grant{RoomID: "proof-room", ParticipantID: "Alice123"}, &moqtransport.Object{
			GroupID: 1, ObjectID: 1, ForwardingPreference: moqtransport.ObjectForwardingPreferenceDatagram,
			Payload: []byte(track),
		}, track)
		delivered, readErr := sub.ReadObject(ctx)
		if readErr != nil || string(delivered.Payload) != track {
			t.Fatalf("track not isolated: %s %v", track, readErr)
		}
	}
}

func TestFanoutDoesNotBlockOtherRecipientsOrTracks(t *testing.T) {
	media := newBroker()
	slow := &subscription{queue: make(chan *moqtransport.Object, 1), done: make(chan struct{})}
	fast := &subscription{queue: make(chan *moqtransport.Object, 1), done: make(chan struct{})}
	otherTrack := &subscription{queue: make(chan *moqtransport.Object, 1), done: make(chan struct{})}
	media.subscriptions[trackKey("room", "sender", "screen")] = map[*subscription]struct{}{slow: {}, fast: {}}
	media.subscriptions[trackKey("room", "sender", "audio")] = map[*subscription]struct{}{otherTrack: {}}
	slow.queue <- &moqtransport.Object{Payload: []byte("old")}
	done := make(chan struct{})
	go func() {
		media.publish(grant{RoomID: "room", ParticipantID: "sender"}, &moqtransport.Object{Payload: []byte("new")}, "screen")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow recipient blocked publication")
	}
	if string((<-fast.queue).Payload) != "new" || len(otherTrack.queue) != 0 {
		t.Fatal("cross-track delivery")
	}
	if string((<-slow.queue).Payload) != "new" {
		t.Fatal("unbounded stale queue")
	}
}

func TestRevocationStoreRejectsActiveMarkerAndExpiresIt(t *testing.T) {
	directory := t.TempDir()
	sessionID := "logical-session"
	digest := sha256.Sum256([]byte(sessionID))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	value := revocation{
		Version: 1, LogicalSessionID: sessionID,
		ExpiresAt: time.Now().Add(time.Minute).UnixMilli(),
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store := revocationStore{directory: directory}
	if !store.revoked(sessionID, time.Now()) {
		t.Fatal("active revocation was ignored")
	}
	if store.revoked(sessionID, time.Now().Add(2*time.Minute)) {
		t.Fatal("expired revocation remained active")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired revocation was not removed")
	}
}

func TestMalformedRevocationFailsClosed(t *testing.T) {
	directory := t.TempDir()
	sessionID := "logical-session"
	digest := sha256.Sum256([]byte(sessionID))
	path := filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !((revocationStore{directory: directory}).revoked(sessionID, time.Now())) {
		t.Fatal("malformed revocation failed open")
	}
}
