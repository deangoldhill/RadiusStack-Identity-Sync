package main

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPanUserID(t *testing.T) {
	const key = "api-key+%&secret"
	cases := []struct {
		name, action, response string
		status                 int
		identities             []Identity
		verifyTLS              bool
		wantErr, wantTag       string
	}{
		{"login escaped username", "login", `<response status="success"><result>ok</result></response>`, 200, []Identity{{Username: `domain\\a&"<b>`, IP: "10.0.0.1"}}, true, "", "login"},
		{"logout", "logout", `<response status="success"/>`, 200, []Identity{{Username: "bob", IP: "10.0.0.2"}}, true, "", "logout"},
		{"multiple", "login", `<response status="success"/>`, 200, []Identity{{Username: "a", IP: "10.0.0.1"}, {Username: "b", IP: "10.0.0.2"}}, true, "", "login"},
		{"api failure", "login", `<response status="error"><msg>api-key+%&amp;secret</msg></response>`, 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "did not report success", "login"},
		{"http failure", "login", `<response status="success"/>`, 403, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "HTTP 403", "login"},
		{"malformed XML", "login", `<response`, 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "invalid XML", "login"},
		{"wrong root", "login", `<wrong status="success"/>`, 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "invalid XML", "login"},
		{"trailing XML", "login", `<response status="success"/><response status="success"/>`, 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "trailing", "login"},
		{"oversize response", "login", strings.Repeat("x", 65537), 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "exceeds", "login"},
		{"invalid action", "query", "", 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, true, "action", ""},
		{"invalid IP", "login", "", 200, []Identity{{Username: "a", IP: "bad"}}, true, "valid IPv4", ""},
		{"empty user", "login", "", 200, []Identity{{Username: "", IP: "10.0.0.1"}}, true, "username", ""},
		{"empty batch", "login", "", 200, nil, true, "at least one", ""},
		{"explicit TLS opt-out", "login", `<response status="success"/>`, 200, []Identity{{Username: "a", IP: "10.0.0.1"}}, false, "", "login"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/api/" || r.URL.RawQuery != "" {
					t.Errorf("unexpected endpoint: %s %s", r.Method, r.URL)
				}
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Errorf("wrong content type: %s", r.Header.Get("Content-Type"))
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.PostForm.Get("type") != "user-id" || r.PostForm.Get("action") != "set" || r.Header.Get("X-PAN-KEY") != key || r.PostForm.Get("key") != "" {
					t.Errorf("invalid form parameters")
				}
				cmd := r.PostForm.Get("cmd")
				if !strings.Contains(cmd, "<uid-message>") || !strings.Contains(cmd, "<version>1.0</version>") || !strings.Contains(cmd, "<type>update</type>") || !strings.Contains(cmd, "<payload><"+tc.wantTag+">") {
					t.Errorf("invalid User-ID XML structure: %s", cmd)
				}
				for _, id := range tc.identities {
					if !strings.Contains(cmd, `ip="`+id.IP+`"`) {
						t.Errorf("IP missing: %s", cmd)
					}
				}
				if tc.name == "login escaped username" && (!strings.Contains(cmd, "&amp;") || !strings.Contains(cmd, "&#34;") || !strings.Contains(cmd, "&lt;")) {
					t.Errorf("username not XML escaped: %s", cmd)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}))
			defer s.Close()
			client := s.Client()
			if !tc.verifyTLS {
				client = &http.Client{}
			}
			a := &App{httpc: client}
			err := a.panUserID(Firewall{Address: s.URL, Secret: key, VerifyTLS: tc.verifyTLS}, tc.action, tc.identities)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("expected %q, got %v", tc.wantErr, err)
			}
			if err != nil && strings.Contains(err.Error(), key) {
				t.Fatal("API key leaked in error")
			}
			if tc.wantTag != "" && calls != 1 {
				t.Errorf("expected one request, got %d", calls)
			}
			if tc.wantTag == "" && calls != 0 {
				t.Errorf("unexpected request count: %d", calls)
			}
		})
	}
}

func TestPanTLSAndValidation(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<response status="success"/>`)
	}))
	defer s.Close()
	id := []Identity{{Username: "a", IP: "10.0.0.1"}}
	for _, tc := range []struct {
		name, address, key string
		verify             bool
		want               string
	}{
		{"untrusted certificate", s.URL, "key", true, "transport failure"},
		{"HTTP prohibited", strings.Replace(s.URL, "https:", "http:", 1), "key", true, "HTTPS host"},
		{"URL key injection prohibited", s.URL + "/?key=leak", "key", true, "HTTPS host"},
		{"credentials prohibited", "https://u:p@example.com", "key", true, "HTTPS host"},
		{"empty key", s.URL, "", true, "key is not configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (&App{httpc: &http.Client{}}).panUserID(Firewall{Address: tc.address, Secret: tc.key, VerifyTLS: tc.verify}, "login", id)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
	// The opt-out must not change a shared HTTP client's TLS settings.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if err := (&App{httpc: client}).panUserID(Firewall{Address: s.URL, Secret: "key", VerifyTLS: false}, "login", id); err != nil {
		t.Fatal(err)
	}
	if client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("shared TLS transport mutated")
	}
}

func TestPanProbeDoesNotWrite(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer s.Close()
	msg, err := (&App{httpc: s.Client()}).panProbe(Firewall{Address: s.URL, Secret: "key"})
	if msg != "" || err == nil || calls != 0 {
		t.Fatalf("probe made network request or claimed success: %q %v %d", msg, err, calls)
	}
}

func TestPanRedirectDoesNotLeakKey(t *testing.T) {
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer destination.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	err := (&App{httpc: s.Client()}).panUserID(Firewall{Address: s.URL, Secret: "key", VerifyTLS: true}, "login", []Identity{{Username: "u", IP: "10.0.0.1"}})
	if err == nil || leaked {
		t.Fatalf("redirect followed or accepted: %v leaked=%v", err, leaked)
	}
}

func TestPanTransportErrorSanitized(t *testing.T) {
	client := &http.Client{Transport: panRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("api-key+%&secret") })}
	err := (&App{httpc: client}).panUserID(Firewall{Address: "example.com", Secret: "api-key+%&secret", VerifyTLS: true}, "login", []Identity{{Username: "u", IP: "10.0.0.1"}})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("secret leaked: %v", err)
	}
}

type panRoundTripper func(*http.Request) (*http.Response, error)

func (f panRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
