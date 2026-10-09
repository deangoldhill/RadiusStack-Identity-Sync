package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SonicWall's SSO API is distinct from the administrative /api/sonicos API.
// Reference (pp. 5-12, 14-20):
// https://www.sonicwall.com/techdocs/pdf/sso-api-reference-guide.pdf
// Configure the firewall's 3rd Party SSO API client for shared-secret HIGH/SHA256.
// The client source host/IP must be allowed on the firewall. Certificate-only
// clients and SHA512-only clients are not supported by this adapter.
// CSRF sequence numbers are serialized per client/firewall in this process; the
// documented 401 Reset handshake re-synchronizes after process/firewall restart.
type sonicwallSequence struct {
	mu   sync.Mutex
	next uint32
}

var sonicwallSequences sync.Map // key: app, firewall ID, endpoint, secret digest

type sonicwallSequenceKey struct {
	app        *App
	id         int
	endpoint   string
	secretHash [32]byte
}

func sonicwallEndpoint(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("SonicWall address is not configured")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(u.Host, " \r\n") {
		return "", errors.New("SonicWall address must be an HTTPS host with optional port")
	}
	return "https://" + u.Host + "/api/sso/user", nil
}

// sonicwallUpdate performs one documented SSO login or logout operation. Secret
// is the SSO API client's shared key, not an admin username/password. For login
// we omit domain/type/groups: the firewall applies its documented LDAP/default
// resolution; the operator must configure that behavior on the firewall.
func (a *App) sonicwallUpdate(f Firewall, action string, i Identity) error {
	if action != "add" && action != "delete" {
		return errors.New("SonicWall action must be add or delete")
	}
	ip, err := netip.ParseAddr(i.IP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() {
		return errors.New("SonicWall requires a valid IPv4 user address")
	}
	if strings.TrimSpace(i.Username) == "" || strings.ContainsAny(i.Username, "\x00\r\n") {
		return errors.New("SonicWall requires a nonempty username without control characters")
	}
	endpoint, err := sonicwallEndpoint(f.Address)
	if err != nil {
		return err
	}
	if f.Secret == "" {
		return errors.New("SonicWall SSO shared key is not configured")
	}
	method := http.MethodDelete
	var body []byte
	if action == "add" {
		method = http.MethodPost
		body, err = json.Marshal(struct {
			IP   string `json:"ip"`
			Name string `json:"name"`
		}{ip.String(), i.Username})
		if err != nil {
			return errors.New("SonicWall request encoding failure")
		}
	} else {
		endpoint += "/" + ip.String()
	}
	return a.sonicwallRequest(f, endpoint, method, body)
}

// sonicwallProbe is read-only. OPTIONS advertises the API's supported methods;
// it never logs in/out a user. This is not a count of existing mappings.
func (a *App) sonicwallProbe(f Firewall) (string, error) {
	endpoint, err := sonicwallEndpoint(f.Address)
	if err != nil {
		return "", err
	}
	if f.Secret == "" {
		return "", errors.New("SonicWall SSO shared key is not configured")
	}
	if err := a.sonicwallRequest(f, endpoint, http.MethodOptions, nil); err != nil {
		return "", err
	}
	return "SonicWall SSO API OPTIONS reachable (no mappings changed)", nil
}

func (a *App) sonicwallRequest(f Firewall, endpoint, method string, body []byte) error {
	base, _ := sonicwallEndpoint(f.Address)
	key := sonicwallSequenceKey{a, f.ID, base, sha256.Sum256([]byte(f.Secret))}
	raw, _ := sonicwallSequences.LoadOrStore(key, &sonicwallSequence{next: 1})
	state := raw.(*sonicwallSequence)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.next == 0 {
		state.next = 1
	}
	client := http.Client{Timeout: 12 * time.Second}
	if a != nil && a.httpc != nil {
		client = *a.httpc
		client.Timeout = 12 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if !f.VerifyTLS {
		tr, ok := client.Transport.(*http.Transport)
		if !ok && client.Transport != nil {
			return errors.New("SonicWall TLS opt-out requires a standard HTTP transport")
		}
		if !ok {
			tr = http.DefaultTransport.(*http.Transport)
		}
		clone := tr.Clone()
		if clone.TLSClientConfig == nil {
			clone.TLSClientConfig = &tls.Config{}
		} else {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
		}
		clone.TLSClientConfig.InsecureSkipVerify = true // explicit per-firewall setting only
		client.Transport = clone
		defer clone.CloseIdleConnections()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		// SHA256 high: flags(4), sequence(4), fresh nonce(24), hash(32).
		// Hash input is prefix || shared-key || raw body (or URI when bodyless).
		auth := make([]byte, 64)
		binary.BigEndian.PutUint32(auth[4:8], state.next)
		if _, err := rand.Read(auth[8:32]); err != nil {
			return errors.New("SonicWall nonce generation failure")
		}
		h := sha256.New()
		h.Write(auth[:32])
		h.Write([]byte(f.Secret))
		if body != nil {
			h.Write(body)
		} else {
			h.Write([]byte(strings.TrimPrefix(endpoint, "https://"+mustHost(endpoint))))
		}
		copy(auth[32:], h.Sum(nil))
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("SonicWall request construction failure")
		}
		req.Header.Set("Authorization", "SNWL-API-Auth "+base64.StdEncoding.EncodeToString(auth))
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("SonicWall SSO transport failure")
		} // no secret or identity in errors
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024+1))
		resp.Body.Close()
		if readErr != nil {
			return errors.New("SonicWall SSO response read failure")
		}
		if resp.StatusCode == http.StatusUnauthorized {
			challenge := resp.Header.Get("WWW-Authenticate")
			const prefix = "SNWL-API-Auth Reset:"
			if attempt == 0 && strings.HasPrefix(challenge, prefix) {
				var n uint32
				text := strings.TrimSpace(strings.TrimPrefix(challenge, prefix))
				if text != "" {
					parsed, parseErr := parseSonicwallReset(text)
					if parseErr == nil {
						n = parsed
						if n != 0 {
							state.next = n
							continue
						}
					}
				}
			}
			return errors.New("SonicWall SSO authentication rejected (check shared key, SHA256 high security and CSRF sequence)")
		}
		state.next++
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("SonicWall SSO HTTP %d", resp.StatusCode)
		}
		if method == http.MethodOptions {
			allow := resp.Header.Get("Allow")
			if !strings.Contains(allow, "POST") || !strings.Contains(allow, "DELETE") || !strings.Contains(allow, "OPTIONS") {
				return errors.New("SonicWall SSO OPTIONS did not advertise required methods")
			}
		}
		return nil
	}
	return errors.New("SonicWall SSO sequence reset failed")
}

func mustHost(endpoint string) string { u, _ := url.Parse(endpoint); return u.Host }

func parseSonicwallReset(text string) (uint32, error) {
	if len(text) > 10 {
		return 0, errors.New("invalid sequence")
	}
	var n uint64
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid sequence")
		}
		n = n*10 + uint64(c-'0')
		if n > 0xffffffff {
			return 0, errors.New("invalid sequence")
		}
	}
	return uint32(n), nil
}
