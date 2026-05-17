// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"net/netip"
	"testing"
)

func TestIsPubliclyRoutableIPRejectsReserved(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"172.16.5.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"fe80::1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
	}
	for _, c := range cases {
		ip, err := netip.ParseAddr(c.in)
		if err != nil {
			t.Fatalf("parse %q: %v", c.in, err)
		}
		if got := isPubliclyRoutableIP(ip); got != c.want {
			t.Errorf("isPubliclyRoutableIP(%s) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsPubliclyRoutableIPRejectsInvalid(t *testing.T) {
	if isPubliclyRoutableIP(netip.Addr{}) {
		t.Fatal("expected invalid IP to be rejected")
	}
}
