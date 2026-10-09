package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// fortinetUpdate queues a FortiAuthenticator FSSO logon/logoff via its v1
// SSO web service. This is not a FortiGate API: configure FAC's SSO Web Service,
// directory/group enrichment, and an API administrator with Web service access
// and the Webservice Authentication permission. Secret is a JSON object:
// {"username":"api-admin","api_key":"emailed-web-service-access-key"}.
// Optionally set "user_groups":"groupA+groupB" for external users (FAC
// requires a group for their logon/logoff); these groups apply to all updates
// made with this firewall configuration.
// A 200 means the event was queued, NOT that FSSO has populated/removed the
// mapping; verify actual state in FAC Monitor > SSO > SSO Sessions.
// https://docs.fortinet.com/document/fortiauthenticator/8.0.3/rest-api-solution-guide/679748/sso-authentication-ssoauth
// https://docs.fortinet.com/document/fortiauthenticator/8.0.3/rest-api-solution-guide/870944/authorization-and-permissions
func (a *App) fortinetUpdate(f Firewall, action string, i Identity) error {
	var event string
	switch action {
	case "add":
		event = "1"
	case "delete":
		event = "0"
	default:
		return errors.New("FortiAuthenticator action must be add or delete")
	}
	endpoint, err := fortinetEndpoint(f.Address)
	if err != nil {
		return err
	}
	var credential struct {
		Username   string `json:"username"`
		APIKey     string `json:"api_key"`
		UserGroups string `json:"user_groups"`
	}
	if err := json.Unmarshal([]byte(f.Secret), &credential); err != nil || strings.TrimSpace(credential.Username) == "" || strings.TrimSpace(credential.APIKey) == "" || strings.ContainsAny(credential.Username, "\x00\r\n:") {
		return errors.New("FortiAuthenticator secret must be JSON with username and api_key")
	}
	if credential.UserGroups != "" {
		if len(credential.UserGroups) > 253 || strings.ContainsAny(credential.UserGroups, "\x00\r\n") {
			return errors.New("FortiAuthenticator user_groups must be at most 253 bytes")
		}
		for _, group := range strings.Split(credential.UserGroups, "+") {
			if strings.TrimSpace(group) == "" {
				return errors.New("FortiAuthenticator user_groups contains an empty group")
			}
		}
	}
	ip, err := netip.ParseAddr(i.IP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || strings.TrimSpace(i.Username) == "" || len(i.Username) > 253 || strings.ContainsAny(i.Username, "\x00\r\n") {
		return errors.New("FortiAuthenticator identity requires IPv4 and a valid nonempty username (max 253 bytes)")
	}
	body, _ := json.Marshal(struct {
		Event      string `json:"event"`
		Username   string `json:"username"`
		UserIP     string `json:"user_ip"`
		UserGroups string `json:"user_groups,omitempty"`
	}{event, i.Username, ip.String(), credential.UserGroups})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("FortiAuthenticator request construction failed")
	}
	req.SetBasicAuth(credential.Username, credential.APIKey)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{}
	if a != nil && a.httpc != nil {
		client = *a.httpc
	}
	client.Timeout = 12 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if !f.VerifyTLS {
		base, ok := client.Transport.(*http.Transport)
		if !ok {
			base = http.DefaultTransport.(*http.Transport)
		}
		tr := base.Clone()
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.InsecureSkipVerify = true // explicit per-firewall opt-out
		client.Transport = tr
		defer tr.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		// URL/transport errors can expose HTTP Basic credentials or payloads.
		return errors.New("FortiAuthenticator SSO transport failure")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FortiAuthenticator SSO HTTP %d", resp.StatusCode)
	}
	return nil
}

func fortinetEndpoint(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("FortiAuthenticator address is not configured")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("FortiAuthenticator address must be an HTTPS host (optional port)")
	}
	return "https://" + u.Host + "/api/v1/ssoauth/", nil
}

// No read-only ssoauth probe exists: a POST changes/queues identities. Do not
// masquerade as a connectivity test by generating a temporary login.
func (a *App) fortinetProbe(f Firewall) (string, error) {
	return "", errors.New("FortiAuthenticator SSO has no documented read-only mapping test; inspect SSO Sessions on the device")
}
