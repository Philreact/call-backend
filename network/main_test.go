package main

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicAddressClassification(t *testing.T) {
	for _, value := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !isPublicInternetAddress(netip.MustParseAddr(value)) {
			t.Fatalf("public address %s rejected", value)
		}
	}
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "198.51.100.1", "203.0.113.1", "::1", "2001:db8::1", "fe80::1"} {
		if isPublicInternetAddress(netip.MustParseAddr(value)) {
			t.Fatalf("non-public address %s accepted", value)
		}
	}
}

func TestStateRoundTripAndFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reachability.json")
	if err := writeState(path, netip.MustParseAddr("8.8.8.8"), portList{4445, 4446}, "direct"); err != nil {
		t.Fatal(err)
	}
	if err := checkState(path, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := checkState(path, time.Now().Add(stateMaxAge+time.Minute)); err == nil {
		t.Fatal("stale state accepted")
	}
}

func TestPortsAreSortedAndDeduplicated(t *testing.T) {
	got := normalizedPorts(portList{4446, 4445, 4446})
	if got.String() != "4445,4446" {
		t.Fatalf("ports = %s", got.String())
	}
}
