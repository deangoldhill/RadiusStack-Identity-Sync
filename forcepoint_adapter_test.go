package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const forcepointSecret = `{"username":"api-user","password":"p:a:ss"}`

var forcepointID = Identity{Username: `EXAMPLE\alice`, IP: "192.0.2.12"}

func TestForcepointUpdatePreservesOtherIPsAndGroups(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		exists       bool
		conflict     bool
		wantMethods  string
	}{
		{"new user", "add", false, false, "GET,POST"},
		{"existing user add", "add", true, false, "GET,PUT"},
		{"existing user delete", "delete", true, false, "GET,PUT"},
		{"missing user delete", "delete", false, false, "GET"},
		{"creation race", "add", false, true, "GET,POST,GET,PUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var methods []string
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				methods = append(methods, r.Method)
				if r.URL.EscapedPath() != `/api/uid/v1.0/user/ntlm-identity/EXAMPLE%5Calice` {
					t.Errorf("wrong URL %q", r.URL.EscapedPath())
				}
				if r.Method == http.MethodGet {
					if _, _, ok := r.BasicAuth(); ok {
						t.Error("GET should remain anonymous")
					}
					if !tc.exists && len(methods) == 1 {
						w.WriteHeader(404)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"NTLMIdentity":"EXAMPLE\\alice","objectGUID":"some-guid","groups":["other-group"],"ipv4_addresses":["192.0.2.99","192.0.2.12"]}`)
					return
				}
				user, pass, ok := r.BasicAuth()
				if !ok || user != "api-user" || pass != "p:a:ss" {
					t.Error("incorrect Basic auth")
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Error("incorrect content type")
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if len(payload) != 2 {
					t.Errorf("unexpected properties: %v", payload)
				}
				ips, ok := payload["ipv4_addresses"].([]any)
				if !ok || len(ips) != 1 || ips[0] != forcepointID.IP {
					t.Errorf("must target only one IP: %v", payload)
				}
				if r.Method == http.MethodPut && payload["changetype"] != tc.action {
					t.Errorf("wrong change: %v", payload)
				}
				if r.Method == http.MethodPost && payload["NTLMIdentity"] != forcepointID.Username {
					t.Errorf("wrong identity: %v", payload)
				}
				if r.Method == http.MethodPost && tc.conflict {
					w.WriteHeader(409)
					return
				}
				_, _ = io.WriteString(w, `{"objectGUID":"some-guid"}`)
			}))
			defer s.Close()
			err := (&App{httpc: s.Client()}).forcepointUpdate(Firewall{Address: s.URL, Secret: forcepointSecret, VerifyTLS: true}, tc.action, forcepointID)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(methods, ","); got != tc.wantMethods {
				t.Fatalf("methods %s, want %s", got, tc.wantMethods)
			}
		})
	}
}

func TestForcepointSafety(t *testing.T) {
	for _, tc := range []struct {
		name, action          string
		id                    Identity
		secret, address, want string
	}{
		{"unsupported username", "add", Identity{"alice", "192.0.2.12"}, forcepointSecret, "", "DOMAIN"},
		{"bad IP", "delete", Identity{`EXAMPLE\alice`, "not-an-ip"}, forcepointSecret, "", "IPv4"},
		{"bad credentials", "add", forcepointID, "api-user:p:a:ss", "", "JSON"},
		{"bad action", "modify", forcepointID, forcepointSecret, "", "action"},
		{"HTTP forbidden", "add", forcepointID, forcepointSecret, "http://example.com", "HTTPS"},
		{"embedded credentials", "add", forcepointID, forcepointSecret, "https://u:p@example.com", "HTTPS"},
		{"unexpected path", "add", forcepointID, forcepointSecret, "https://example.com/api", "HTTPS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.address
			if addr == "" {
				addr = "https://example.com"
			}
			err := (&App{}).forcepointUpdate(Firewall{Address: addr, Secret: tc.secret}, tc.action, tc.id)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
	if got, err := forcepointEndpoint("example.com"); err != nil || got != "https://example.com:5000/api/uid/v1.0/" {
		t.Fatalf("default port: %s %v", got, err)
	}
}

func TestForcepointRejectsUnexpectedReadOrWriteResponse(t *testing.T) {
	for _, tc := range []struct {
		name, read              string
		readStatus, writeStatus int
		write                   string
		want                    string
	}{
		{"mismatched user", `{"NTLMIdentity":"EXAMPLE\\mallory"}`, 200, 200, "", "mismatch"},
		{"invalid JSON", "<html>", 200, 200, "", "invalid JSON"},
		{"GET failure", "secret", 503, 200, "", "HTTP 503"},
		{"PUT failure", `{"NTLMIdentity":"EXAMPLE\\alice"}`, 200, 401, "secret", "HTTP 401"},
		{"missing GUID", `{"NTLMIdentity":"EXAMPLE\\alice"}`, 200, 200, `{}`, "objectGUID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(tc.readStatus)
					fmt.Fprint(w, tc.read)
					return
				}
				w.WriteHeader(tc.writeStatus)
				fmt.Fprint(w, tc.write)
			}))
			defer s.Close()
			err := (&App{httpc: s.Client()}).forcepointUpdate(Firewall{Address: s.URL, Secret: forcepointSecret, VerifyTLS: true}, "add", forcepointID)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "p:a:ss") {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestForcepointProbeReadOnly(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/api/uid/v1.0/status" || r.Header.Get("Authorization") != "" {
			t.Errorf("unsafe probe %s %s", r.Method, r.URL)
		}
		io.WriteString(w, `{"status":{"Total users count":19,"Total domains count":2}}`)
	}))
	defer s.Close()
	msg, err := (&App{httpc: s.Client()}).forcepointProbe(Firewall{Address: s.URL, VerifyTLS: true})
	if err != nil || calls != 1 || !strings.Contains(msg, "19 total users") || !strings.Contains(msg, "write credentials not tested") {
		t.Fatalf("probe: %q %v (%d calls)", msg, err, calls)
	}
}

func TestForcepointTLSRedirectAndSanitization(t *testing.T) {
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked = true }))
	defer destination.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(307)
	}))
	defer s.Close()
	f := Firewall{Address: s.URL, Secret: forcepointSecret, VerifyTLS: true}
	if err := (&App{httpc: s.Client()}).forcepointUpdate(f, "add", forcepointID); err == nil || leaked {
		t.Fatalf("redirect followed: %v %v", err, leaked)
	}
	if _, err := (&App{httpc: &http.Client{}}).forcepointProbe(f); err == nil || !strings.Contains(err.Error(), "transport failure") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	// The explicit opt-out only applies to the cloned client, never the shared transport.
	f.VerifyTLS = false
	if _, err := (&App{httpc: client}).forcepointProbe(f); err == nil {
		t.Fatal("redirect unexpectedly accepted as status")
	}
	if client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("shared client mutated")
	}
	leakClient := &http.Client{Transport: forcepointRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("p:a:ss") })}
	if _, err := (&App{httpc: leakClient}).forcepointProbe(Firewall{Address: "example.com", VerifyTLS: true}); err == nil || strings.Contains(err.Error(), "p:a:ss") {
		t.Fatalf("transport secret leaked: %v", err)
	}
}

type forcepointRoundTripper func(*http.Request) (*http.Response, error)

func (f forcepointRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
