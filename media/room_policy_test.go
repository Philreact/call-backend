package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/mengelbart/moqtransport"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRoomPolicyEnforcedOnFanout(t *testing.T) {
	source := grant{RoomID: "room-123", ParticipantID: "QHost123", LogicalSessionID: "host-session"}
	guest := grant{RoomID: "room-123", ParticipantID: "QGuest123", LogicalSessionID: "guest-session"}
	media := newBroker()
	media.policies = &roomPolicyStore{directory: t.TempDir(), cached: make(map[string]cachedRoomPolicy)}
	audio := &subscription{owner: &connectionHandler{principal: guest}, queue: make(chan *moqtransport.Object, 1), done: make(chan struct{})}
	screen := &subscription{owner: &connectionHandler{principal: guest}, queue: make(chan *moqtransport.Object, 1), done: make(chan struct{})}
	media.subscriptions[trackKey(source.RoomID, source.ParticipantID, "audio")] = map[*subscription]struct{}{audio: {}}
	media.subscriptions[trackKey(source.RoomID, source.ParticipantID, "screen")] = map[*subscription]struct{}{screen: {}}
	value := roomPolicy{RoomID: source.RoomID, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(), Members: map[string]string{source.ParticipantID: source.LogicalSessionID, guest.ParticipantID: guest.LogicalSessionID}, Muted: []string{source.ParticipantID}}
	set := func() { media.policies.cached[source.RoomID] = cachedRoomPolicy{value, time.Now()} }
	object := &moqtransport.Object{Payload: []byte("encrypted")}
	set()
	media.publish(source, object, "audio")
	media.publish(source, object, "screen")
	if len(audio.queue) != 0 || len(screen.queue) != 1 {
		t.Fatal("host mute did not isolate audio from screen")
	}
	<-screen.queue
	delete(value.Members, guest.ParticipantID)
	set()
	media.publish(source, object, "screen")
	if len(screen.queue) != 0 {
		t.Fatal("removed subscriber received media")
	}
	value.Members[guest.ParticipantID] = guest.LogicalSessionID
	delete(value.Members, source.ParticipantID)
	set()
	media.publish(source, object, "screen")
	if len(screen.queue) != 0 {
		t.Fatal("removed publisher sent media")
	}
}

func TestRoomPolicyModeration(t *testing.T) {
	dir := t.TempDir()
	store := &roomPolicyStore{directory: dir}
	now := time.Now()
	principal := grant{RoomID: "room-123", ParticipantID: "QGuest123", LogicalSessionID: "session-guest"}
	if allowed, _ := store.access(principal, now); allowed {
		t.Fatal("missing policy allowed")
	}
	digest := sha256.Sum256([]byte(principal.RoomID))
	if err := os.Mkdir(filepath.Join(dir, "rooms"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rooms", hex.EncodeToString(digest[:])+".json")
	write := func(value roomPolicy) {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	value := roomPolicy{RoomID: principal.RoomID, ExpiresAt: now.Add(time.Hour).UnixMilli(), Members: map[string]string{principal.ParticipantID: principal.LogicalSessionID}}
	write(value)
	if allowed, muted := store.access(principal, now); !allowed || muted {
		t.Fatal("active participant rejected")
	}
	value.Muted = []string{principal.ParticipantID}
	write(value)
	if allowed, muted := store.access(principal, now); !allowed || !muted {
		t.Fatal("host mute missing")
	}
	delete(value.Members, principal.ParticipantID)
	write(value)
	if allowed, _ := store.access(principal, now); allowed {
		t.Fatal("removed participant allowed")
	}
	value.Members[principal.ParticipantID] = "new-session"
	write(value)
	if allowed, _ := store.access(principal, now); allowed {
		t.Fatal("old session regained access")
	}
	principal.LogicalSessionID = "new-session"
	if allowed, _ := store.access(principal, now); !allowed {
		t.Fatal("readmitted participant rejected")
	}
	if err := os.WriteFile(path, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := store.access(principal, now.Add(time.Second)); allowed {
		t.Fatal("corrupt policy allowed")
	}
}
