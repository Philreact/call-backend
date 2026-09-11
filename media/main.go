package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mengelbart/moqtransport"
	"github.com/mengelbart/moqtransport/quicmoq"
	"github.com/quic-go/quic-go"
)

const (
	mediaTrackName       = "audio"
	maxGrantBytes        = 4096
	maxObjectBytes       = 1024
	keepAlivePeriod      = 15 * time.Second
	connectionMaxIdle    = 2 * time.Minute
	maxRevocationBytes   = 1024
	revocationPollPeriod = time.Second
)

func mediaServerQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:         true,
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: true,
		KeepAlivePeriod:         keepAlivePeriod,
		MaxIdleTimeout:          connectionMaxIdle,
	}
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{3,128}$`)

func validQAppName(value string) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 128 &&
		strings.TrimSpace(value) == value && strings.ToLower(value) == value
}

type grant struct {
	Version           int    `json:"version"`
	TokenSHA256       string `json:"tokenSha256"`
	LogicalSessionID  string `json:"logicalSessionId"`
	AuthenticatedUser string `json:"authenticatedUser"`
	QAppName          string `json:"qappName"`
	QAppService       string `json:"qappService"`
	Purpose           string `json:"purpose"`
	RoomID            string `json:"roomId"`
	ParticipantID     string `json:"participantId"`
	ExpiresAt         int64  `json:"expiresAt"`
}

type grantStore struct{ directory string }

type revocation struct {
	Version          int    `json:"version"`
	LogicalSessionID string `json:"logicalSessionId"`
	ExpiresAt        int64  `json:"expiresAt"`
}

type revocationStore struct{ directory string }

func (s revocationStore) revoked(sessionID string, now time.Time) bool {
	digest := sha256.Sum256([]byte(sessionID))
	path := filepath.Join(s.directory, hex.EncodeToString(digest[:])+".json")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxRevocationBytes+1))
	decoder.DisallowUnknownFields()
	var value revocation
	if err = decoder.Decode(&value); err != nil {
		return true
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || value.Version != 1 ||
		value.LogicalSessionID != sessionID {
		return true
	}
	if value.ExpiresAt <= now.UnixMilli() {
		_ = os.Remove(path)
		return false
	}
	return true
}

func (s grantStore) purgeExpired(now time.Time) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.directory, entry.Name())
		contents, readErr := os.ReadFile(path)
		var value grant
		if readErr != nil || len(contents) > maxGrantBytes ||
			json.Unmarshal(contents, &value) != nil || value.ExpiresAt <= now.UnixMilli() {
			_ = os.Remove(path)
		}
	}
}

func (s grantStore) consume(token string, now time.Time) (grant, error) {
	if len(token) < 32 || len(token) > 128 {
		return grant{}, errors.New("invalid attachment credential")
	}
	digest := sha256.Sum256([]byte(token))
	digestHex := hex.EncodeToString(digest[:])
	path := filepath.Join(s.directory, digestHex+".json")
	claimed := filepath.Join(
		s.directory,
		fmt.Sprintf(".%s.consuming-%d", digestHex, os.Getpid()),
	)
	if err := os.Rename(path, claimed); err != nil {
		return grant{}, errors.New("attachment credential unavailable")
	}
	defer os.Remove(claimed)
	file, err := os.Open(claimed)
	if err != nil {
		return grant{}, errors.New("attachment credential unavailable")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxGrantBytes+1))
	decoder.DisallowUnknownFields()
	var value grant
	if err = decoder.Decode(&value); err != nil {
		return grant{}, errors.New("invalid attachment credential")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return grant{}, errors.New("invalid attachment credential")
	}
	if value.Version != 1 || value.TokenSHA256 != digestHex ||
		value.Purpose != "realtime" || !validQAppName(value.QAppName) ||
		value.QAppService != "APP" || value.ExpiresAt <= now.UnixMilli() ||
		!safeID.MatchString(value.RoomID) ||
		!safeID.MatchString(value.ParticipantID) ||
		value.LogicalSessionID == "" || value.AuthenticatedUser != value.ParticipantID {
		return grant{}, errors.New("invalid attachment credential")
	}
	return value, nil
}

type subscription struct {
	request *moqtransport.IncomingSubscribeRequest
	owner   *connectionHandler
	queue   chan *moqtransport.Object
	policy  moqtransport.DeliveryPolicy
	done    chan struct{}
}

type broker struct {
	policies      *roomPolicyStore
	mu            sync.RWMutex
	subscriptions map[string]map[*subscription]struct{}
	nextAlias     atomic.Uint64
}

func newBroker() *broker {
	return &broker{subscriptions: make(map[string]map[*subscription]struct{})}
}

func trackKey(room, participant string, tracks ...string) string {
	track := mediaTrackName
	if len(tracks) > 0 {
		track = tracks[0]
	}
	return room + "\x00" + participant + "\x00" + track
}

func allowedTrack(track string) bool {
	return track == "audio" || track == "screen" || track == "feedback"
}

func (b *broker) add(room, participant string, value *subscription, tracks ...string) {
	track := mediaTrackName
	if len(tracks) > 0 {
		track = tracks[0]
	}
	value.policy = deliveryPolicy(track)
	value.request.Accept(b.nextAlias.Add(1))
	b.mu.Lock()
	key := trackKey(room, participant, tracks...)
	set := b.subscriptions[key]
	if set == nil {
		set = make(map[*subscription]struct{})
		b.subscriptions[key] = set
	}
	set[value] = struct{}{}
	value.queue = make(chan *moqtransport.Object, 64)
	value.done = make(chan struct{})
	b.mu.Unlock()
	go value.forward()
}

func (b *broker) removeOwner(owner *connectionHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, set := range b.subscriptions {
		for value := range set {
			if value.owner == owner {
				close(value.done)
				delete(set, value)
			}
		}
		if len(set) == 0 {
			delete(b.subscriptions, key)
		}
	}
}

func (b *broker) publish(source grant, object *moqtransport.Object, tracks ...string) {
	if b.policies != nil {
		allowed, muted := b.policies.access(source, time.Now())
		track := mediaTrackName
		if len(tracks) > 0 {
			track = tracks[0]
		}
		if !allowed || (muted && track == "audio") {
			return
		}
	}
	if len(object.Payload) == 0 || len(object.Payload) > maxObjectBytes {
		return
	}
	b.mu.RLock()
	values := make([]*subscription, 0, len(b.subscriptions))
	for value := range b.subscriptions[trackKey(source.RoomID, source.ParticipantID, tracks...)] {
		values = append(values, value)
	}
	b.mu.RUnlock()
	for _, value := range values {
		if b.policies != nil {
			allowed, _ := b.policies.access(value.owner.principal, time.Now())
			if !allowed {
				continue
			}
		}
		select {
		case <-value.done:
			continue
		default:
		}
		if object.ForwardingPreference == moqtransport.ObjectForwardingPreferenceDatagram {
			// One bounded scheduler per recipient connection owns all datagram
			// queues. Do not hide another FIFO in front of its deadlines/priorities.
			_ = value.request.ScheduleDatagram(*object, value.policy)
			continue
		}
		copyObject := *object
		copyObject.Payload = append([]byte(nil), object.Payload...)
		select {
		case value.queue <- &copyObject:
		default:
			// Bound each recipient/track independently. A slow recipient cannot
			// stall another recipient or a different track.
			select {
			case <-value.queue:
			default:
			}
			select {
			case value.queue <- &copyObject:
			default:
			}
		}
	}
}

func (value *subscription) forward() {
	for {
		var object *moqtransport.Object
		select {
		case <-value.done:
			return
		case object = <-value.queue:
		}
		var err error
		if object.ForwardingPreference == moqtransport.ObjectForwardingPreferenceDatagram {
			err = value.request.ScheduleDatagram(*object, value.policy)
		} else {
			var subgroup *moqtransport.Subgroup
			subgroup, err = value.request.OpenSubgroup(object.GroupID, object.SubGroupID, 0)
			if err == nil {
				_, err = subgroup.WriteObject(object.ObjectID, object.Payload)
				_ = subgroup.Close()
			}
		}
		if err != nil && !errors.Is(err, moqtransport.ErrDeliveryQueueFull) {
			log.Printf("media subscriber send failed: %v", err)
		}
	}
}

// Application policy belongs here, not in Hub, the relay, or the MoQ library.
func deliveryPolicy(track string) moqtransport.DeliveryPolicy {
	switch track {
	case "audio":
		return moqtransport.DeliveryPolicy{Priority: 0, MaxQueueAgeMillis: 120}
	case "feedback":
		return moqtransport.DeliveryPolicy{Priority: 0, MaxQueueAgeMillis: 500}
	default:
		return moqtransport.DeliveryPolicy{Priority: 1, MaxQueueAgeMillis: 200}
	}
}

type connectionHandler struct {
	broker            *broker
	principal         grant
	ready             atomic.Bool
	subscriptionCount atomic.Uint32
}

func (h *connectionHandler) HandleGoAway(string) {}

func (h *connectionHandler) HandleSubscribe(request *moqtransport.IncomingSubscribeRequest) {
	if !h.ready.Load() {
		request.Reject(moqtransport.RequestErrorCodeUnauthorized, "authentication required")
		return
	}
	namespace := request.Namespace()
	if len(namespace) != 4 || string(namespace[0]) != "qortal" ||
		string(namespace[1]) != "call" || string(namespace[2]) != h.principal.RoomID ||
		!safeID.Match(namespace[3]) || !allowedTrack(string(request.Name())) {
		request.Reject(moqtransport.RequestErrorCodeUnauthorized, "track is not available")
		return
	}
	if h.subscriptionCount.Add(1) > 128 {
		request.Reject(moqtransport.RequestErrorCodeUnauthorized, "subscription limit")
		return
	}
	h.broker.add(h.principal.RoomID, string(namespace[3]), &subscription{
		request: request,
		owner:   h,
	}, string(request.Name()))
}

func namespace(value grant) [][]byte {
	return [][]byte{
		[]byte("qortal"), []byte("call"), []byte(value.RoomID), []byte(value.ParticipantID),
	}
}

func waitForPath(ctx context.Context, session *moqtransport.Session) (string, error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if path := session.Path(); path != "" {
			return path, nil
		}
		select {
		case <-ctx.Done():
			return "", context.Cause(ctx)
		case <-session.Context().Done():
			return "", context.Cause(session.Context())
		case <-ticker.C:
		}
	}
}

func handleConnection(conn *quic.Conn, grants grantStore, revocations revocationStore, media *broker) {
	authenticated := guardAttachment(conn)
	handler := &connectionHandler{broker: media}
	session, err := moqtransport.NewSession(
		quicmoq.NewServer(conn), "", moqtransport.WithHandler(handler),
	)
	if err != nil {
		_ = conn.CloseWithError(1, "session setup failed")
		return
	}
	defer func() {
		media.removeOwner(handler)
		session.CloseWithError(0, "closed")
	}()
	authContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	path, err := waitForPath(authContext, session)
	cancel()
	if err != nil || !strings.HasPrefix(path, "attach/") {
		return
	}
	principal, err := grants.consume(strings.TrimPrefix(path, "attach/"), time.Now())
	if err != nil {
		return
	}
	if revocations.revoked(principal.LogicalSessionID, time.Now()) {
		_ = conn.CloseWithError(2, "session revoked")
		return
	}
	allowed, _ := media.policies.access(principal, time.Now())
	if !allowed {
		return
	}
	if !authenticated() {
		return
	}
	handler.principal = principal
	handler.ready.Store(true)
	var readers sync.WaitGroup
	for _, track := range []string{"audio", "screen", "feedback"} {
		readers.Add(1)
		go func(track string) {
			defer readers.Done()
			source, err := session.Subscribe(session.Context(), namespace(principal), track)
			if err != nil {
				return
			} // Legacy clients may publish only audio.
			for {
				object, readErr := source.ReadObject(session.Context())
				if readErr != nil {
					return
				}
				media.publish(principal, object, track)
			}
		}(track)
	}
	revocationTicker := time.NewTicker(revocationPollPeriod)
	defer revocationTicker.Stop()
	for {
		select {
		case <-session.Context().Done():
			readers.Wait()
			return
		case <-revocationTicker.C:
			allowed, _ := media.policies.access(principal, time.Now())
			if !allowed || revocations.revoked(principal.LogicalSessionID, time.Now()) {
				handler.ready.Store(false)
				_ = conn.CloseWithError(2, "session revoked")
				readers.Wait()
				return
			}
		}
	}
}

func waitForFiles(paths ...string) error {
	deadline := time.Now().Add(time.Minute)
	for {
		all := true
		for _, path := range paths {
			if _, err := os.Stat(path); err != nil {
				all = false
				break
			}
		}
		if all {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("media certificate was not created by the control service")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:4446", "literal UDP listen endpoint")
	certificate := flag.String("certificate", "/data/backend/private-transport-cert.pem", "TLS certificate")
	key := flag.String("key", "/data/backend/private-transport-key.pem", "TLS private key")
	grants := flag.String("grants", "/data/backend/call-media-grants", "one-time grant directory")
	revocations := flag.String("revocations", "/data/backend/call-media-revocations", "session revocation directory")
	flag.Parse()
	if err := waitForFiles(*certificate, *key); err != nil {
		log.Fatal(err)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{moqtransport.MOQT18.String()},
	}
	var err error
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(*certificate, *key)
	if err != nil {
		log.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	gate := newAdmissionGate()
	transport := &quic.Transport{Conn: udp, ConnContext: gate.admit, VerifySourceAddress: gate.retry}
	defer transport.Close()
	listener, err := transport.Listen(tlsConfig, mediaServerQUICConfig())
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	if err = os.MkdirAll(*grants, 0o700); err != nil {
		log.Fatal(err)
	}
	if err = os.MkdirAll(*revocations, 0o700); err != nil {
		log.Fatal(err)
	}
	log.Printf("call media listener started on %s", *listen)
	media := newBroker()
	media.policies = &roomPolicyStore{directory: *revocations}
	store := grantStore{directory: *grants}
	revocationFiles := revocationStore{directory: *revocations}
	store.purgeExpired(time.Now())
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for now := range ticker.C {
			store.purgeExpired(now)
		}
	}()
	for {
		connection, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			log.Fatal(acceptErr)
		}
		go handleConnection(connection, store, revocationFiles, media)
	}
}
