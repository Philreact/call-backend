package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type roomPolicy struct {
	RoomID    string            `json:"roomId"`
	ExpiresAt int64             `json:"expiresAt"`
	Members   map[string]string `json:"members"`
	Muted     []string          `json:"muted"`
}
type cachedRoomPolicy struct {
	value   roomPolicy
	checked time.Time
}
type roomPolicyStore struct {
	directory string
	mu        sync.Mutex
	cached    map[string]cachedRoomPolicy
}

// Shared, bounded room-level cache. Missing/unreadable policy denies access.
func (s *roomPolicyStore) access(principal grant, now time.Time) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil {
		s.cached = make(map[string]cachedRoomPolicy)
	}
	cached, exists := s.cached[principal.RoomID]
	if !exists || now.Sub(cached.checked) >= 250*time.Millisecond {
		digest := sha256.Sum256([]byte(principal.RoomID))
		value := roomPolicy{}
		file, err := os.Open(filepath.Join(s.directory, "rooms", hex.EncodeToString(digest[:])+".json"))
		if err == nil {
			decoder := json.NewDecoder(io.LimitReader(file, 32769))
			decoder.DisallowUnknownFields()
			var trailing any
			if decoder.Decode(&value) != nil || decoder.Decode(&trailing) != io.EOF {
				value = roomPolicy{}
			}
			file.Close()
		}
		cached = cachedRoomPolicy{value, now}
		if len(s.cached) >= 1024 {
			clear(s.cached)
		}
		s.cached[principal.RoomID] = cached
	}
	value := cached.value
	if value.RoomID != principal.RoomID || value.ExpiresAt <= now.UnixMilli() || value.Members[principal.ParticipantID] != principal.LogicalSessionID {
		return false, false
	}
	for _, id := range value.Muted {
		if id == principal.ParticipantID {
			return true, true
		}
	}
	return true, false
}
