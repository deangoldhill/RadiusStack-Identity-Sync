package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSonicwallUpdateAndProbe(t *testing.T) {
	const secret = "sso-secret"
	calls := 0
	var previous uint32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		encoded := strings.TrimPrefix(r.Header.Get("Authorization"), "SNWL-API-Auth ")
		auth, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(auth) != 64 {
			t.Errorf("invalid authenticator: %v (%d bytes)", err, len(auth))
			w.WriteHeader(400)
			return
		}
		seq := binary.BigEndian.Uint32(auth[4:8])
		if calls > 1 && seq != previous+1 {
			t.Errorf("sequence %d after %d", seq, previous)
		}
		previous = seq
		if binary.BigEndian.Uint32(auth[:4]) != 0 {
			t.Error("unexpected reply authentication flag")
		}
		body, _ := io.ReadAll(r.Body)
		h := sha256.New()
		h.Write(auth[:32])
		h.Write([]byte(secret))
		if len(body) > 0 {
			h.Write(body)
		} else {
			h.Write([]byte(r.URL.RequestURI()))
		}
		if string(h.Sum(nil)) != string(auth[32:]) {
			t.Errorf("invalid body/URI-bound SHA256 for %s %s", r.Method, r.URL.Path)
		}
		switch calls {
		case 1:
			if r.Method != "POST" || r.URL.Path != "/api/sso/user" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("bad login request: %s %s", r.Method, r.URL)
			}
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil || v["ip"] != "192.0.2.42" || v["name"] != `corp\\a&b` || len(v) != 2 {
				t.Errorf("bad login payload: %s (%v)", body, err)
			}
		case 2:
			if r.Method != "DELETE" || r.URL.Path != "/api/sso/user/192.0.2.42" || len(body) != 0 {
				t.Errorf("bad logout request %s %s %s", r.Method, r.URL, body)
			}
		case 3:
			if r.Method != "OPTIONS" || r.URL.Path != "/api/sso/user" || len(body) != 0 {
				t.Errorf("bad probe request %s %s", r.Method, r.URL)
			}
			w.Header().Set("Allow", "POST,DELETE,OPTIONS")
		}
		w.WriteHeader(200)
	}))
	defer s.Close()
	a := &App{httpc: s.Client()}
	f := Firewall{ID: 100, Address: s.URL, Secret: secret, VerifyTLS: true}
	i := Identity{IP: "192.0.2.42", Username: `corp\\a&b`}
	if err := a.sonicwallUpdate(f, "add", i); err != nil {
		t.Fatal(err)
	}
	if err := a.sonicwallUpdate(f, "delete", i); err != nil {
		t.Fatal(err)
	}
	if msg, err := a.sonicwallProbe(f); err != nil || !strings.Contains(msg, "no mappings changed") {
		t.Fatalf("probe: %q %v", msg, err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestSonicwallSequenceReset(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		encoded := strings.TrimPrefix(r.Header.Get("Authorization"), "SNWL-API-Auth ")
		auth, _ := base64.StdEncoding.DecodeString(encoded)
		if calls == 1 {
			w.Header().Set("WWW-Authenticate", "SNWL-API-Auth Reset:4711")
			w.WriteHeader(401)
			return
		}
		if binary.BigEndian.Uint32(auth[4:8]) != 4711 {
			t.Error("failed to apply reset")
		}
		w.WriteHeader(200)
	}))
	defer s.Close()
	err := (&App{httpc: s.Client()}).sonicwallUpdate(Firewall{ID: 101, Address: s.URL, Secret: "key", VerifyTLS: true}, "add", Identity{IP: "192.0.2.1", Username: "alice"})
	if err != nil || calls != 2 {
		t.Fatalf("reset: %v (%d calls)", err, calls)
	}
}

func TestSonicwallRejectsUnsafeInputsAndErrors(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(207)
		io.WriteString(w, "shared-secret")
	}))
	defer s.Close()
	a := &App{httpc: s.Client()}
	f := Firewall{ID: 102, Address: s.URL, Secret: "shared-secret", VerifyTLS: true}
	i := Identity{IP: "192.0.2.1", Username: "alice"}
	for _, tc := range []struct{ name, action, address, user, ip string }{
		{"bad action", "update", s.URL, "alice", "192.0.2.1"},
		{"bad host", "add", "http://example.com", "alice", "192.0.2.1"},
		{"url credentials", "add", "https://user:pass@example.com", "alice", "192.0.2.1"},
		{"url query", "add", s.URL + "/?leak=yes", "alice", "192.0.2.1"},
		{"bad IP", "add", s.URL, "alice", "not-an-ip"},
		{"bad username", "add", s.URL, "alice\nother", "192.0.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.Address = tc.address
			err := a.sonicwallUpdate(f, tc.action, Identity{IP: tc.ip, Username: tc.user})
			if err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("made %d invalid calls", calls)
	}
	f.Address = s.URL
	if err := a.sonicwallUpdate(f, "add", i); err == nil || !strings.Contains(err.Error(), "207") || strings.Contains(err.Error(), f.Secret) {
		t.Fatalf("partial failure mishandled: %v", err)
	}
}

func TestSonicwallTLSOptOutIsScopedAndRedirectBlocked(t *testing.T) {
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked = true }))
	defer destination.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(307)
	}))
	defer s.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	a := &App{httpc: &http.Client{Transport: transport}}
	f := Firewall{ID: 103, Address: s.URL, Secret: "key", VerifyTLS: true}
	i := Identity{IP: "192.0.2.1", Username: "alice"}
	if err := a.sonicwallUpdate(f, "add", i); err == nil {
		t.Fatal("trusted TLS accepted self-signed certificate")
	}
	f.VerifyTLS = false
	if err := a.sonicwallUpdate(f, "add", i); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect accepted: %v", err)
	}
	if leaked || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("redirect followed or shared transport mutated")
	}
}
