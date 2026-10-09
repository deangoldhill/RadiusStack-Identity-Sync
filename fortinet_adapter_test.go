package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFortinetUpdate(t *testing.T) {
	for _, tc := range []struct{ action, event string }{{"add", "1"}, {"delete", "0"}} {
		t.Run(tc.action, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/ssoauth/" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("unexpected request %s %s, content type %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
				}
				u, k, ok := r.BasicAuth()
				if !ok || u != "service" || k != "api-secret" {
					t.Error("wrong HTTP Basic API credentials")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if len(payload) != 3 || payload["event"] != tc.event || payload["username"] != "alice" || payload["user_ip"] != "192.0.2.1" {
					t.Errorf("wrong payload: %v", payload)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer s.Close()
			secret := `{"username":"service","api_key":"api-secret"}`
			a := &App{httpc: s.Client()}
			if err := a.fortinetUpdate(Firewall{Address: s.URL, Secret: secret, VerifyTLS: true}, tc.action, Identity{Username: "alice", IP: "192.0.2.1"}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("calls = %d", calls)
			}
		})
	}
}

func TestFortinetFailures(t *testing.T) {
	calls := 0
	status := http.StatusOK
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
	defer s.Close()
	f := Firewall{Address: s.URL, Secret: `{"username":"service","api_key":"private-key"}`, VerifyTLS: true}
	a := &App{httpc: s.Client()}
	id := Identity{Username: "alice", IP: "192.0.2.1"}
	for _, tc := range []struct {
		name   string
		f      Firewall
		action string
		id     Identity
	}{
		{"unknown action", f, "logout", id},
		{"bad credentials", Firewall{Address: s.URL, Secret: "private-key", VerifyTLS: true}, "add", id},
		{"missing key", Firewall{Address: s.URL, Secret: `{"username":"service"}`, VerifyTLS: true}, "add", id},
		{"plaintext endpoint", Firewall{Address: "http://example.com", Secret: f.Secret, VerifyTLS: true}, "add", id},
		{"path endpoint", Firewall{Address: s.URL + "/api/v1/", Secret: f.Secret, VerifyTLS: true}, "add", id},
		{"userinfo endpoint", Firewall{Address: "https://user:password@example.com", Secret: f.Secret, VerifyTLS: true}, "add", id},
		{"bad IP", f, "add", Identity{Username: "alice", IP: "garbage"}},
		{"IPv6", f, "add", Identity{Username: "alice", IP: "2001:db8::1"}},
		{"blank user", f, "add", Identity{Username: " ", IP: id.IP}},
		{"control user", f, "add", Identity{Username: "alice\nfoo", IP: id.IP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := a.fortinetUpdate(tc.f, tc.action, tc.id); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid input made %d calls", calls)
	}
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusInternalServerError, http.StatusFound} {
		status = code
		err := a.fortinetUpdate(f, "add", id)
		if err == nil || !strings.Contains(err.Error(), "HTTP ") || strings.Contains(err.Error(), "private-key") {
			t.Fatalf("status %d: %v", code, err)
		}
	}
}

func TestFortinetExternalGroups(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload["user_groups"] != "staff+vpn" || payload["event"] != "0" {
			t.Errorf("unexpected external group payload: %v", payload)
		}
	}))
	defer s.Close()
	a := &App{httpc: s.Client()}
	f := Firewall{Address: s.URL, Secret: `{"username":"service","api_key":"secret","user_groups":"staff+vpn"}`, VerifyTLS: true}
	if err := a.fortinetUpdate(f, "delete", Identity{Username: "alice", IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	f.Secret = `{"username":"service","api_key":"secret","user_groups":"staff++vpn"}`
	if err := a.fortinetUpdate(f, "add", Identity{Username: "alice", IP: "192.0.2.1"}); err == nil {
		t.Fatal("expected empty group rejection")
	}
}

func TestFortinetTLSOptOutAndProbe(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer s.Close()
	f := Firewall{Address: s.URL, Secret: `{"username":"service","api_key":"private-key"}`, VerifyTLS: true}
	id := Identity{Username: "alice", IP: "192.0.2.1"}
	a := &App{httpc: &http.Client{}}
	if err := a.fortinetUpdate(f, "add", id); err == nil || strings.Contains(err.Error(), "private-key") {
		t.Fatalf("expected sanitized TLS error: %v", err)
	}
	f.VerifyTLS = false
	if err := a.fortinetUpdate(f, "add", id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.fortinetProbe(f); err == nil {
		t.Fatal("probe must not write identities")
	}
}
