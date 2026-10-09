package main

import (
	"database/sql"
	"fmt"
	"io"
	_ "modernc.org/sqlite"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ciscoTestApp(t *testing.T, client *http.Client) *App {
	t.Helper()
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return &App{db: db, httpc: client}
}

func TestCiscoAddDelete(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1, 3:
			if r.Method != "POST" || r.URL.Path != "/api/fmi_platform/v1/identityauth/generatetoken" {
				t.Errorf("token request %s %s", r.Method, r.URL)
			}
			u, p, ok := r.BasicAuth()
			if !ok || u != "api-user" || p != "p@ss" {
				t.Error("wrong BasicAuth")
			}
			w.Header().Set("X-auth-access-token", "temporary-token")
			w.WriteHeader(204)
		case 2:
			if r.Method != "POST" || r.URL.Path != "/api/identity/v1/identity/useridentity" || r.Header.Get("X-auth-access-token") != "temporary-token" || r.Header.Get("Content-Type") != "application/json" {
				t.Error("wrong add request")
			}
			data, _ := io.ReadAll(r.Body)
			s := string(data)
			for _, field := range []string{`"user":"domain\\bob"`, `"srcIpAddress":"10.1.2.3"`, `"agentInfo":"sync"`, `"domain":"example.com"`, `"timestamp":"`} {
				if !strings.Contains(s, field) {
					t.Errorf("missing %s in %s", field, s)
				}
			}
			if strings.Contains(s, "p@ss") {
				t.Error("credential leaked into payload")
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":"session-123"}`)
		case 4:
			if r.Method != "DELETE" || r.URL.Path != "/api/identity/v1/identity/useridentity/session-123" || r.Header.Get("X-auth-access-token") != "temporary-token" {
				t.Error("wrong delete request")
			}
			w.WriteHeader(200)
			fmt.Fprint(w, `{"id":"session-123"}`)
		default:
			t.Error("unexpected call")
		}
	}))
	defer server.Close()
	a := ciscoTestApp(t, server.Client())
	f := Firewall{ID: 1, Address: server.URL, Secret: `{"username":"api-user","password":"p@ss","domain":"example.com","agentInfo":"sync"}`, VerifyTLS: true}
	id := Identity{Username: `domain\bob`, IP: "10.1.2.3"}
	if e := a.ciscoUpdate(f, "add", id); e != nil {
		t.Fatal(e)
	}
	if e := a.ciscoUpdate(f, "add", id); e == nil {
		t.Fatal("duplicate add accepted")
	}
	if e := a.ciscoUpdate(f, "delete", id); e != nil {
		t.Fatal(e)
	}
	if e := a.ciscoUpdate(f, "delete", id); e == nil {
		t.Fatal("missing binding accepted")
	}
	if calls != 4 {
		t.Fatalf("got %d calls", calls)
	}
}

func TestCiscoFailures(t *testing.T) {
	for _, tc := range []struct{ name, secret, address, action, ip, want string }{
		{"plaintext secret", "password", "example.com", "add", "10.1.2.3", "Secret requires JSON"},
		{"credentials in address", `{"username":"u","password":"p","domain":"d","agentInfo":"a"}`, "https://u:p@example.com", "add", "10.1.2.3", "address must"},
		{"http rejected", `{"username":"u","password":"p","domain":"d","agentInfo":"a"}`, "http://example.com", "add", "10.1.2.3", "address must"},
		{"invalid ip", `{"username":"u","password":"p","domain":"d","agentInfo":"a"}`, "example.com", "add", "bad", "requires IPv4"},
		{"unknown action", `{"username":"u","password":"p","domain":"d","agentInfo":"a"}`, "example.com", "remove", "10.1.2.3", "action must"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ciscoTestApp(t, nil)
			e := a.ciscoUpdate(Firewall{Address: tc.address, Secret: tc.secret}, tc.action, Identity{"bob", tc.ip})
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("got %v; want %s", e, tc.want)
			}
		})
	}
}

func TestCiscoTokenAndIDFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tokenStatus int
		token       string
		addStatus   int
		body        string
		want        string
	}{
		{"missing token", 204, "", 201, `{"id":"x"}`, "token header missing"},
		{"failed auth", 401, "", 201, `{"id":"x"}`, "token HTTP 401"},
		{"missing id", 204, "t", 201, `{"self":"/x"}`, "no usable binding ID"},
		{"bad id", 204, "t", 201, `{"id":"../escape"}`, "no usable binding ID"},
		{"bad status", 204, "t", 200, `{"id":"x"}`, "identity HTTP 200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/api/fmi_platform/v1/identityauth/generatetoken" {
					w.Header().Set("X-auth-access-token", tc.token)
					w.WriteHeader(tc.tokenStatus)
					return
				}
				w.WriteHeader(tc.addStatus)
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			a := ciscoTestApp(t, s.Client())
			e := a.ciscoUpdate(Firewall{ID: 1, Address: s.URL, Secret: `{"username":"u","password":"p","domain":"d","agentInfo":"a"}`, VerifyTLS: true}, "add", Identity{"bob", "10.1.2.3"})
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("got %v; want %s", e, tc.want)
			}
			if tc.tokenStatus != 204 || tc.token == "" {
				if calls != 1 {
					t.Errorf("expected one request, got %d", calls)
				}
			}
		})
	}
}

func TestCiscoProbeNoWrite(t *testing.T) {
	a := &App{}
	s, e := a.ciscoProbe(Firewall{})
	if s != "" || e == nil {
		t.Fatalf("%q %v", s, e)
	}
}
