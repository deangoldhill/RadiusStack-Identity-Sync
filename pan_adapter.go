package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// panUserID sends PAN-OS XML API User-ID login or logout updates. Secret is a
// pre-generated API key, never an administrator password. A successful HTTP
// status alone is not sufficient: the XML response must report success.
// See https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-use-cases/apply-user-id-mapping-and-populate-dynamic-address-groups-api
func (a *App) panUserID(f Firewall, action string, identities []Identity) error {
	if action != "login" && action != "logout" {
		return errors.New("PAN-OS User-ID action must be login or logout")
	}
	if len(identities) == 0 {
		return errors.New("PAN-OS User-ID requires at least one identity")
	}
	if f.Secret == "" {
		return errors.New("PAN-OS API key is not configured")
	}
	endpoint, err := panEndpoint(f.Address)
	if err != nil {
		return err
	}
	type entry struct {
		Name string `xml:"name,attr"`
		IP   string `xml:"ip,attr"`
	}
	type payloadMapping struct {
		XMLName xml.Name `xml:"uid-message"`
		Version string   `xml:"version"`
		Type    string   `xml:"type"`
		Payload struct {
			Events struct {
				XMLName xml.Name
				Entries []entry `xml:"entry"`
			}
		} `xml:"payload"`
	}
	msg := payloadMapping{Version: "1.0", Type: "update"}
	msg.Payload.Events.XMLName = xml.Name{Local: action}
	for _, identity := range identities {
		ip, parseErr := netip.ParseAddr(identity.IP)
		if parseErr != nil || !ip.Is4() || strings.TrimSpace(identity.Username) == "" {
			return errors.New("PAN-OS User-ID requires valid IPv4 and nonempty username")
		}
		if strings.ContainsAny(identity.Username, "\x00\r\n") {
			return errors.New("PAN-OS User-ID username contains control characters")
		}
		e := entry{Name: identity.Username, IP: ip.String()}
		msg.Payload.Events.Entries = append(msg.Payload.Events.Entries, e)
	}
	payload, err := xml.Marshal(msg)
	if err != nil {
		return fmt.Errorf("PAN-OS User-ID XML encoding: %w", err)
	}
	// PAN-OS documents POST of type=user-id, key and cmd=<uid-message>.
	// action=set is included for the requested integration convention.
	form := url.Values{"type": {"user-id"}, "action": {"set"}, "cmd": {string(payload)}}
	if len(form.Encode()) > 5*1024*1024 {
		return errors.New("PAN-OS User-ID request exceeds 5 MiB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("PAN-OS User-ID request construction failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-PAN-KEY", f.Secret)
	client := http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if a != nil && a.httpc != nil {
		client = *a.httpc
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client.Timeout = 12 * time.Second
	}
	if !f.VerifyTLS {
		// Clone instead of mutating the shared client/transport; preserve proxy and
		// test transport settings when a standard *http.Transport was injected.
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
		tr.TLSClientConfig.InsecureSkipVerify = true // operator's explicit per-firewall opt-out
		client.Transport = tr
		defer tr.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		// Never return a transport error verbatim: custom transports may include
		// the request body or key in their error text.
		return errors.New("PAN-OS User-ID transport failure")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return errors.New("PAN-OS User-ID response read failure")
	}
	if len(body) > 64*1024 {
		return errors.New("PAN-OS User-ID response exceeds 64 KiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PAN-OS User-ID HTTP %d", resp.StatusCode)
	}
	var result struct {
		XMLName xml.Name `xml:"response"`
		Status  string   `xml:"status,attr"`
	}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&result); err != nil || result.XMLName.Local != "response" {
		return errors.New("PAN-OS User-ID invalid XML response")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("PAN-OS User-ID invalid trailing response")
	}
	if result.Status != "success" {
		return errors.New("PAN-OS User-ID API did not report success")
	}
	return nil
}

func panEndpoint(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("PAN-OS firewall address is not configured")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("PAN-OS firewall address must be an HTTPS host (optional port)")
	}
	return "https://" + u.Host + "/api/", nil
}

// panProbe deliberately makes no request. Key generation requires administrator
// credentials and User-ID action=set writes mappings; neither is a safe test.
func (a *App) panProbe(f Firewall) (string, error) {
	return "", errors.New("PAN-OS read-only connectivity test is not supported; use a documented read-only operation")
}
