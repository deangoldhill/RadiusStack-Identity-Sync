package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestVendorConfigurationUIAndPersistence(t *testing.T) {
	a := extrasTestApp(t)
	extrasLogin(t, a)
	view := httptest.NewRecorder()
	a.vendorFirewalls(view, extrasRequest(http.MethodGet, "/firewalls", ""))
	if view.Code != 200 {
		t.Fatalf("UI status %d: %s", view.Code, view.Body.String())
	}
	for _, v := range []string{"paloalto", "cisco", "watchguard", "sonicwall", "fortinet", "fortigate", "forcepoint"} {
		if !strings.Contains(view.Body.String(), `value="`+v+`"`) {
			t.Errorf("missing vendor %s", v)
		}
	}
	form := url.Values{"name": {"Lab PAN"}, "vendor": {"paloalto"}, "address": {"pan.example.com"}, "secret": {"test-key"}, "verify_tls": {"on"}}
	response := httptest.NewRecorder()
	a.vendorFirewalls(response, extrasRequest(http.MethodPost, "/firewalls", form.Encode()))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create status %d: %s", response.Code, response.Body.String())
	}
	var vendor string
	var verify int
	if err := a.db.QueryRow("SELECT vendor,verify_tls FROM firewalls WHERE name='Lab PAN'").Scan(&vendor, &verify); err != nil || vendor != "paloalto" || verify != 1 {
		t.Fatalf("created integration not persisted: %s %d %v", vendor, verify, err)
	}
}

func TestAllAdvertisedVendorsAreDispatchable(t *testing.T) {
	for _, vendor := range []string{"checkpoint", "paloalto", "cisco", "watchguard", "sonicwall", "fortinet", "fortigate", "forcepoint"} {
		if !supportedVendor(vendor) {
			t.Errorf("vendor not supported: %s", vendor)
		}
		if !strings.Contains(fwT, `value="`+vendor+`"`) {
			t.Errorf("vendor missing from UI: %s", vendor)
		}
	}
	if supportedVendor("unknown") {
		t.Fatal("unknown vendor accepted")
	}
}

func TestPanSyncReconciliationThroughProductionLoop(t *testing.T) {
	a := extrasTestApp(t)
	sessions := `[{"radacctid":1,"username":"alice","framedipaddress":"10.20.30.4"}]`
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sessions/active" || r.Header.Get("X-API-Key") != "test-api-key" {
			t.Errorf("wrong source request: %s", r.URL)
		}
		fmt.Fprint(w, sessions)
	}))
	defer source.Close()
	var actions []string
	pan := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/" || r.Header.Get("X-PAN-KEY") != "test-pan-key" {
			t.Errorf("wrong PAN request: %s", r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		cmd := form.Get("cmd")
		if strings.Contains(cmd, "<login>") {
			actions = append(actions, "login")
		} else if strings.Contains(cmd, "<logout>") {
			actions = append(actions, "logout")
		} else {
			t.Errorf("unknown XML action: %s", cmd)
		}
		fmt.Fprint(w, `<response status="success"/>`)
	}))
	defer pan.Close()
	for k, v := range map[string]string{"radius_url": source.URL, "radius_api_key": "test-api-key"} {
		if _, err := a.db.Exec("INSERT INTO config(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.db.Exec("INSERT INTO firewalls(name,vendor,address,secret,verify_tls,enabled) VALUES('pan','paloalto',?,?,0,1)", pan.URL, "test-pan-key"); err != nil {
		t.Fatal(err)
	}
	a.sync(false)
	var user string
	if err := a.db.QueryRow("SELECT username FROM identities WHERE ip='10.20.30.4'").Scan(&user); err != nil || user != "alice" {
		t.Fatalf("missing tracked login: %s %v", user, err)
	}
	a.sync(false)
	a.sync(true)
	sessions = `[]`
	a.sync(false)
	if got := strings.Join(actions, ","); got != "login,login,logout" {
		t.Fatalf("unexpected diff/full/logout sequence: %s", got)
	}
	var count int
	if err := a.db.QueryRow("SELECT count(*) FROM identities").Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale mappings: %d %v", count, err)
	}
}

func TestCiscoFullRefreshDoesNotCreateDuplicate(t *testing.T) {
	a := extrasTestApp(t)
	f := Firewall{ID: 17, Vendor: "cisco"}
	i := Identity{Username: "alice", IP: "10.0.0.1"}
	if _, err := a.db.Exec("INSERT INTO cisco_bindings(firewall_id,ip,username,binding_id) VALUES(?,?,?,?)", f.ID, i.IP, i.Username, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshOrAdd(f, true, map[string]Identity{i.IP: i}, i); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec("DELETE FROM cisco_bindings"); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshOrAdd(f, true, map[string]Identity{i.IP: i}, i); err == nil {
		t.Fatal("missing binding must not be silently treated as refreshed")
	}
}
