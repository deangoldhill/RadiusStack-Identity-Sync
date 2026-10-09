package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func wgResponse(req []byte, secret string) []byte {
	resp := []byte{5, req[1], 0, 20}
	resp = append(resp, make([]byte, 16)...)
	h := md5.New()
	h.Write(resp[:4])
	h.Write(req[4:20])
	h.Write([]byte(secret))
	copy(resp[4:], h.Sum(nil))
	return resp
}

func wgAttributes(t *testing.T, p []byte) map[byte][]byte {
	t.Helper()
	if len(p) < 20 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || p[0] != 4 {
		t.Fatalf("invalid accounting request header: %x", p)
	}
	attrs := make(map[byte][]byte)
	for b := p[20:]; len(b) > 0; {
		if len(b) < 2 || int(b[1]) < 2 || int(b[1]) > len(b) {
			t.Fatalf("invalid RADIUS attribute: %x", b)
		}
		if _, ok := attrs[b[0]]; ok {
			t.Fatalf("duplicate attribute %d", b[0])
		}
		attrs[b[0]] = bytes.Clone(b[2:b[1]])
		b = b[b[1]:]
	}
	return attrs
}

func TestWatchguardAccountingLifecycle(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil { t.Fatal(err) }
	defer server.Close()
	const secret = "test-radius-shared-secret"
	f := Firewall{ID: 91, Address: server.LocalAddr().String(), Secret: secret}
	i := Identity{Username: "domain\\alex", IP: "192.0.2.25"}
	packets := make(chan []byte, 3)
	go func() {
		for n := 0; n < 3; n++ {
			buf := make([]byte, 4096)
			server.SetReadDeadline(time.Now().Add(3 * time.Second))
			count, peer, readErr := server.ReadFromUDP(buf)
			if readErr != nil { return }
			p := bytes.Clone(buf[:count])
			packets <- p
			server.WriteToUDP(wgResponse(p, secret), peer)
		}
	}()
	var firstSID []byte
	for _, tc := range []struct{ action string; status uint32 }{{"add", 1}, {"refresh", 3}, {"delete", 2}} {
		if err := (*App)(nil).watchguardUpdate(f, tc.action, i); err != nil { t.Fatalf("%s: %v", tc.action, err) }
		var p []byte
		select { case p = <-packets: case <-time.After(3*time.Second): t.Fatal("no request") }
		attrs := wgAttributes(t, p)
		if len(attrs) != 4 { t.Fatalf("unexpected attributes: %v", attrs) }
		if !bytes.Equal(attrs[1], []byte(i.Username)) || !bytes.Equal(attrs[8], net.ParseIP(i.IP).To4()) || !bytes.Equal(attrs[40], []byte{0, 0, 0, byte(tc.status)}) {
			t.Fatalf("%s: incorrect RFC 2866 attributes: %v", tc.action, attrs)
		}
		if len(attrs[44]) != 64 || strings.Contains(string(attrs[44]), i.Username) { t.Fatalf("unexpected mapping session ID: %q", attrs[44]) }
		if firstSID == nil { firstSID = attrs[44] } else if !bytes.Equal(firstSID, attrs[44]) { t.Fatal("session ID changed across lifecycle") }
		zeroed := bytes.Clone(p)
		clear(zeroed[4:20])
		h := md5.New(); h.Write(zeroed); h.Write([]byte(secret))
		if !bytes.Equal(p[4:20], h.Sum(nil)) { t.Fatal("invalid Accounting-Request authenticator") }
	}
	if watchguardSessionID(f.ID+1, i) == string(firstSID) || watchguardSessionID(f.ID, Identity{Username: "other", IP: i.IP}) == string(firstSID) || watchguardSessionID(f.ID, Identity{Username: i.Username, IP: "192.0.2.26"}) == string(firstSID) {
		t.Fatal("mapping-specific session ID collision")
	}
}

func TestWatchguardRejectsUnauthenticatedResponse(t *testing.T) {
	for _, corrupt := range []func([]byte){
		func(p []byte) { p[4] ^= 1 },
		func(p []byte) { p[0] = 2 },
		func(p []byte) { p[1] ^= 1 },
		func(p []byte) { p[3]++ },
	} {
		server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil { t.Fatal(err) }
		go func() {
			buf := make([]byte, 4096)
			server.SetReadDeadline(time.Now().Add(3*time.Second))
			n, peer, err := server.ReadFromUDP(buf)
			if err == nil { r := wgResponse(buf[:n], "shared"); corrupt(r); server.WriteToUDP(r, peer) }
		}()
		err = (*App)(nil).watchguardUpdate(Firewall{ID: 1, Address: server.LocalAddr().String(), Secret: "shared"}, "add", Identity{Username: "alex", IP: "192.0.2.1"})
		server.Close()
		if err == nil { t.Fatal("accepted invalid response") }
	}
}

func TestWatchguardInvalidInputSendsNothing(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil { t.Fatal(err) }
	defer server.Close()
	f := Firewall{ID: 1, Address: server.LocalAddr().String(), Secret: "shared"}
	i := Identity{Username: "alex", IP: "192.0.2.1"}
	cases := []struct{ f Firewall; action string; i Identity }{
		{f, "login", i}, {f, "add", Identity{Username: "", IP: i.IP}},
		{f, "add", Identity{Username: strings.Repeat("x", 254), IP: i.IP}},
		{f, "add", Identity{Username: "evil\nuser", IP: i.IP}},
		{f, "add", Identity{Username: i.Username, IP: "2001:db8::1"}},
		{f, "add", Identity{Username: i.Username, IP: "not-ip"}},
		{Firewall{ID: 0, Address: f.Address, Secret: f.Secret}, "add", i},
		{Firewall{ID: 1, Address: f.Address}, "add", i},
		{Firewall{ID: 1, Address: "127.0.0.1", Secret: f.Secret}, "add", i},
		{Firewall{ID: 1, Address: "127.0.0.1:0", Secret: f.Secret}, "add", i},
	}
	for n, c := range cases {
		if err := (*App)(nil).watchguardUpdate(c.f, c.action, c.i); err == nil { t.Errorf("case %d unexpectedly succeeded", n) }
	}
	buf := make([]byte, 4096)
	server.SetReadDeadline(time.Now().Add(30*time.Millisecond))
	if n, _, err := server.ReadFromUDP(buf); err == nil { t.Fatalf("unexpected request: %s", fmt.Sprintf("%x", buf[:n])) }
}
