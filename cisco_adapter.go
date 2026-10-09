package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Cisco ISE-PIC 3.4 API Providers documentation:
// https://www.cisco.com/c/en/us/td/docs/security/ise/3-4/pic_admin_guide/pic_admin34/pic_admin_providers.html
// Secret is JSON: {"username":"provider","password":"...","domain":"example.com","agentInfo":"RadiusStack Identity Sync"}.
// Never place credentials in Firewall.Address (HTTPS host, optional port).
type ciscoCredentials struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Domain    string `json:"domain"`
	AgentInfo string `json:"agentInfo"`
}

func parseCiscoSecret(secret string) (ciscoCredentials, error) {
	var c ciscoCredentials
	d := json.NewDecoder(strings.NewReader(secret))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Username == "" || c.Password == "" || c.Domain == "" || c.AgentInfo == "" {
		return ciscoCredentials{}, errors.New("ISE-PIC Secret requires JSON username, password, domain, and agentInfo")
	}
	return c, nil
}

func ciscoEndpoint(address string) (string, error) {
	address = strings.TrimSpace(address)
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(u.Hostname(), "\r\n") {
		return "", errors.New("ISE-PIC address must be an HTTPS host (optional port), without credentials or path")
	}
	if u.Port() == "" {
		return "https://" + net.JoinHostPort(u.Hostname(), "9094"), nil
	}
	return "https://" + u.Host, nil
}

// ciscoUpdate creates a PIC API-provider binding or deletes the exact ID
// returned by its add response. The ID is persisted per firewall/IP; a missing
// ID is an error, never a best-effort delete by IP or username.
func (a *App) ciscoUpdate(f Firewall, action string, i Identity) error {
	if action != "add" && action != "delete" {
		return errors.New("ISE-PIC action must be add or delete")
	}
	ip, err := netip.ParseAddr(i.IP)
	if err != nil || !ip.Is4() || ip.Is4In6() || strings.TrimSpace(i.Username) == "" {
		return errors.New("ISE-PIC requires IPv4 and a nonempty user")
	}
	base, err := ciscoEndpoint(f.Address)
	if err != nil {
		return err
	}
	creds, err := parseCiscoSecret(f.Secret)
	if err != nil {
		return err
	}
	if a == nil || a.db == nil {
		return errors.New("ISE-PIC binding storage is unavailable")
	}
	_, err = a.db.Exec(`CREATE TABLE IF NOT EXISTS cisco_bindings (firewall_id INTEGER NOT NULL, ip TEXT NOT NULL, username TEXT NOT NULL, binding_id TEXT NOT NULL, PRIMARY KEY(firewall_id,ip))`)
	if err != nil {
		return errors.New("ISE-PIC binding storage failed")
	}
	var priorUser, bindingID string
	err = a.db.QueryRow(`SELECT username,binding_id FROM cisco_bindings WHERE firewall_id=? AND ip=?`, f.ID, ip.String()).Scan(&priorUser, &bindingID)
	if err != nil && err != sql.ErrNoRows {
		return errors.New("ISE-PIC binding lookup failed")
	}
	if action == "add" && err == nil {
		return errors.New("ISE-PIC binding already exists; delete it before adding again")
	}
	if action == "delete" && (err == sql.ErrNoRows || priorUser != i.Username) {
		return errors.New("ISE-PIC matching binding ID not found")
	}
	client := http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if a.httpc != nil {
		client = *a.httpc
		client.Timeout = 12 * time.Second
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	if !f.VerifyTLS {
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			tr = http.DefaultTransport.(*http.Transport)
		}
		clone := tr.Clone()
		if clone.TLSClientConfig == nil {
			clone.TLSClientConfig = &tls.Config{}
		} else {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
		}
		clone.TLSClientConfig.InsecureSkipVerify = true // explicit per-integration opt-out only
		client.Transport = clone
		defer clone.CloseIdleConnections()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/fmi_platform/v1/identityauth/generatetoken", nil)
	if err != nil {
		return errors.New("ISE-PIC token request construction failed")
	}
	tokenReq.SetBasicAuth(creds.Username, creds.Password)
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return errors.New("ISE-PIC token transport failure")
	}
	io.Copy(io.Discard, io.LimitReader(tokenResp.Body, 4096))
	tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("ISE-PIC token HTTP %d", tokenResp.StatusCode)
	}
	accessToken := tokenResp.Header.Get("X-auth-access-token")
	if accessToken == "" {
		return errors.New("ISE-PIC token header missing")
	}
	endpoint := base + "/api/identity/v1/identity/useridentity"
	var body io.Reader
	method := http.MethodPost
	if action == "add" {
		payload, e := json.Marshal(struct {
			User      string `json:"user"`
			SrcIP     string `json:"srcIpAddress"`
			Agent     string `json:"agentInfo"`
			Timestamp string `json:"timestamp"`
			Domain    string `json:"domain"`
		}{i.Username, ip.String(), creds.AgentInfo, time.Now().UTC().Format(time.RFC3339), creds.Domain})
		if e != nil {
			return errors.New("ISE-PIC payload encoding failed")
		}
		body = bytes.NewReader(payload)
	} else {
		// PathEscape does not escape '.'; reject non-opaque/path-like IDs as defense in depth.
		if bindingID == "" || strings.ContainsAny(bindingID, "/\\?#\r\n") || bindingID == "." || bindingID == ".." {
			return errors.New("ISE-PIC invalid stored binding ID")
		}
		endpoint += "/" + url.PathEscape(bindingID)
		method = http.MethodDelete
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errors.New("ISE-PIC identity request construction failed")
	}
	req.Header.Set("X-auth-access-token", accessToken)
	if action == "add" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("ISE-PIC identity transport failure")
	}
	defer resp.Body.Close()
	response, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil {
		return errors.New("ISE-PIC response read failure")
	}
	if len(response) > 65536 {
		return errors.New("ISE-PIC response too large")
	}
	expected := http.StatusCreated
	if action == "delete" {
		expected = http.StatusOK
	}
	if resp.StatusCode != expected {
		return fmt.Errorf("ISE-PIC identity HTTP %d", resp.StatusCode)
	}
	if action == "add" {
		// Cisco documents an ID in the add response, but does not give a full
		// response schema. Require its top-level id; don't infer from self links.
		var result struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(response, &result) != nil || result.ID == "" || strings.ContainsAny(result.ID, "/\\?#\r\n") || result.ID == "." || result.ID == ".." {
			return errors.New("ISE-PIC add response has no usable binding ID")
		}
		_, e = a.db.Exec(`INSERT INTO cisco_bindings(firewall_id,ip,username,binding_id) VALUES(?,?,?,?)`, f.ID, ip.String(), i.Username, result.ID)
	} else {
		_, e = a.db.Exec(`DELETE FROM cisco_bindings WHERE firewall_id=? AND ip=? AND username=? AND binding_id=?`, f.ID, ip.String(), i.Username, bindingID)
	}
	if e != nil {
		return errors.New("ISE-PIC binding storage failed after remote update; reconcile manually before retry")
	}
	return nil
}

// Cisco documents no non-mutating API-provider test request in this section.
func (a *App) ciscoProbe(f Firewall) (string, error) {
	return "", errors.New("ISE-PIC read-only API-provider probe is not documented")
}
