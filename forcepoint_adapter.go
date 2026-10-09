package main

import (
	"bytes"
	"context"
	"crypto/tls"
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

// Forcepoint User ID Service API User Guide, revision A (28 October 2020):
// https://help.forcepoint.com/docs/uid/v20/rfrnce/fuid_ug_api_a_en-us.pdf
// This talks to the User ID Service, NOT directly to an NGFW engine. Configure
// NGFW to consume that service separately. Secret is JSON with username and
// password fields for the service API user; never put credentials in Address.
// Only DOMAIN\Username identities are supported by the documented NTLM URL.
func (a *App) forcepointUpdate(f Firewall, action string, id Identity) error {
	if action != "add" && action != "delete" {
		return errors.New("Forcepoint action must be add or delete")
	}
	base, err := forcepointEndpoint(f.Address)
	if err != nil {
		return err
	}
	var cred struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.Unmarshal([]byte(f.Secret), &cred) != nil || cred.Username == "" || cred.Password == "" {
		return errors.New("Forcepoint API credentials require JSON username and password")
	}
	if err := forcepointIdentity(id); err != nil {
		return err
	}
	client := a.forcepointClient(f.VerifyTLS)
	endpoint := base + "user/ntlm-identity/" + url.PathEscape(id.Username)
	var current struct {
		Identity string   `json:"NTLMIdentity"`
		IPs      []string `json:"ipv4_addresses"`
	}
	status, err := forcepointRequest(client, http.MethodGet, endpoint, "", "", nil, &current)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound && action == "delete" {
		return nil
	}
	if status == http.StatusNotFound {
		// A new user is only created after a confirmed 404. POST never overwrites
		// an existing user, including its groups or other source-owned addresses.
		payload := struct {
			Identity string   `json:"NTLMIdentity"`
			IPs      []string `json:"ipv4_addresses"`
		}{id.Username, []string{id.IP}}
		var created struct {
			GUID string `json:"objectGUID"`
		}
		status, err = forcepointRequest(client, http.MethodPost, endpoint, cred.Username, cred.Password, payload, &created)
		if err != nil {
			return err
		}
		if status == http.StatusOK {
			if created.GUID == "" {
				return errors.New("Forcepoint POST missing objectGUID")
			}
			return nil
		}
		if status != http.StatusConflict {
			return fmt.Errorf("Forcepoint POST user HTTP %d", status)
		}
		// Another producer won the create race; re-read before changing anything.
		status, err = forcepointRequest(client, http.MethodGet, endpoint, "", "", nil, &current)
		if err != nil {
			return err
		}
	}
	if status != http.StatusOK {
		return fmt.Errorf("Forcepoint GET user HTTP %d", status)
	}
	if current.Identity != id.Username {
		return errors.New("Forcepoint GET user identity mismatch")
	}
	if action == "delete" {
		present := false
		for _, ip := range current.IPs {
			if ip == id.IP {
				present = true
				break
			}
		}
		if !present {
			return nil
		}
	}
	change := action
	// Never use changetype=modify or DELETE /user: those replace/remove
	// unrelated IP addresses, group memberships, or the whole user object.
	payload := struct {
		Change string   `json:"changetype"`
		IPs    []string `json:"ipv4_addresses"`
	}{change, []string{id.IP}}
	var updated struct {
		GUID string `json:"objectGUID"`
	}
	status, err = forcepointRequest(client, http.MethodPut, endpoint, cred.Username, cred.Password, payload, &updated)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("Forcepoint PUT user HTTP %d", status)
	}
	if updated.GUID == "" {
		return errors.New("Forcepoint PUT missing objectGUID")
	}
	return nil
}

func forcepointIdentity(id Identity) error {
	ip, err := netip.ParseAddr(id.IP)
	if err != nil || !ip.Is4() || ip.String() != id.IP {
		return errors.New("Forcepoint requires canonical IPv4 address")
	}
	parts := strings.Split(id.Username, "\\")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.TrimSpace(id.Username) != id.Username || strings.ContainsAny(id.Username, "\x00\r\n") {
		return errors.New("Forcepoint requires DOMAIN\\Username identity")
	}
	return nil
}

func forcepointEndpoint(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("Forcepoint address is not configured")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.Contains(u.Host, "\\") {
		return "", errors.New("Forcepoint address must be an HTTPS host (optional port)")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "5000")
	}
	return "https://" + host + "/api/uid/v1.0/", nil
}

func (a *App) forcepointClient(verify bool) *http.Client {
	c := &http.Client{}
	if a != nil && a.httpc != nil {
		copyClient := *a.httpc
		c = &copyClient
	}
	c.Timeout = 12 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if !verify {
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			tr = http.DefaultTransport.(*http.Transport)
		}
		cloned := tr.Clone()
		if cloned.TLSClientConfig == nil {
			cloned.TLSClientConfig = &tls.Config{}
		} else {
			cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
		}
		cloned.TLSClientConfig.InsecureSkipVerify = true // explicit per-firewall opt-out
		c.Transport = cloned
	}
	return c
}

// No response body or underlying transport error is returned: both may carry
// credentials or user data. Each response has a strict bounded read.
func forcepointRequest(client *http.Client, method, endpoint, user, pass string, payload any, out any) (int, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, errors.New("Forcepoint JSON encoding failed")
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, errors.New("Forcepoint request construction failed")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodPut {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New("Forcepoint transport failure")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return 0, errors.New("Forcepoint response read failure")
	}
	if len(b) > 64*1024 {
		return 0, errors.New("Forcepoint response exceeds 64 KiB")
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	if out != nil {
		if err = json.Unmarshal(b, out); err != nil {
			return 0, errors.New("Forcepoint invalid JSON response")
		}
	}
	return resp.StatusCode, nil
}

// GET /status is documented as an anonymous, read-only health/inventory call.
// It does not validate write credentials or prove that the NGFW consumes data.
func (a *App) forcepointProbe(f Firewall) (string, error) {
	base, err := forcepointEndpoint(f.Address)
	if err != nil {
		return "", err
	}
	var result struct {
		Status struct {
			Users *int `json:"Total users count"`
		} `json:"status"`
	}
	code, err := forcepointRequest(a.forcepointClient(f.VerifyTLS), http.MethodGet, base+"status", "", "", nil, &result)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("Forcepoint GET status HTTP %d", code)
	}
	if result.Status.Users == nil || *result.Status.Users < 0 {
		return "", errors.New("Forcepoint status missing total users count")
	}
	return fmt.Sprintf("Forcepoint User ID Service reachable: %d total users (service-wide; write credentials not tested)", *result.Status.Users), nil
}
