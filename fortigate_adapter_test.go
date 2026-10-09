package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFortigateRSSOAccounting(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	const secret = "unit-test-secret"
	f := Firewall{ID: 3, Address: server.LocalAddr().String(), Secret: `{"shared_secret":"unit-test-secret","group":"RSSO-Users"}`, Vendor: "fortigate"}
	i := Identity{Username: "alice", IP: "192.0.2.4"}
	packets := make(chan []byte, 3)
	go func() {
		for n := 0; n < 3; n++ {
			buf := make([]byte, 4096)
			server.SetReadDeadline(time.Now().Add(3 * time.Second))
			size, peer, e := server.ReadFromUDP(buf)
			if e != nil {
				return
			}
			p := bytes.Clone(buf[:size])
			packets <- p
			server.WriteToUDP(wgResponse(p, secret), peer)
		}
	}()
	var sessionID []byte
	for _, tc := range []struct {
		action string
		status byte
	}{{"add", 1}, {"refresh", 3}, {"delete", 2}} {
		if err := (*App)(nil).fortigateUpdate(f, tc.action, i); err != nil {
			t.Fatal(err)
		}
		p := <-packets
		attrs := wgAttributes(t, p)
		if len(attrs) != 5 || !bytes.Equal(attrs[1], []byte("alice")) || !bytes.Equal(attrs[8], net.ParseIP(i.IP).To4()) || !bytes.Equal(attrs[25], []byte("RSSO-Users")) || !bytes.Equal(attrs[40], []byte{0, 0, 0, tc.status}) {
			t.Fatalf("bad %s packet: %v", tc.action, attrs)
		}
		if sessionID == nil {
			sessionID = attrs[44]
		} else if !bytes.Equal(sessionID, attrs[44]) {
			t.Fatal("session ID drift")
		}
	}
	if err := (*App)(nil).fortigateUpdate(Firewall{ID: 3, Address: f.Address, Secret: `{"shared_secret":"x"}`}, "add", i); err == nil {
		t.Fatal("missing group accepted")
	}
}
