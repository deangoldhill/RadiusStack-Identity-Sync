package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Each integration has a specific product/protocol; a brand name alone is not
// sufficient to infer a generic identity API.
func supportedVendor(v string) bool {
	switch v {
	case "checkpoint", "paloalto", "cisco", "watchguard", "sonicwall", "fortinet", "fortigate", "forcepoint":
		return true
	}
	return false
}

func (a *App) updateFirewall(f Firewall, action string, identity Identity) error {
	if action != "add" && action != "delete" {
		return errors.New("invalid identity action")
	}
	switch f.Vendor {
	case "checkpoint":
		if action == "delete" {
			return a.cp(f, "delete-identity", map[string]any{"ip-address": identity.IP})
		}
		return a.cp(f, "add-identity", map[string]any{"ip-address": identity.IP, "user": identity.Username, "identity-source": "RadiusStack Identity Sync", "fetch-user-groups": 0, "fetch-machine-groups": 0, "calculate-roles": 0, "roles": []string{"API_Users"}, "session-timeout": max(300, a.cfg().PollSeconds*4)})
	case "paloalto":
		cmd := "login"
		if action == "delete" {
			cmd = "logout"
		}
		return a.panUserID(f, cmd, []Identity{identity})
	case "cisco":
		return a.ciscoUpdate(f, action, identity)
	case "watchguard":
		return a.watchguardUpdate(f, action, identity)
	case "sonicwall":
		return a.sonicwallUpdate(f, action, identity)
	case "fortinet":
		return a.fortinetUpdate(f, action, identity)
	case "fortigate":
		return a.fortigateUpdate(f, action, identity)
	case "forcepoint":
		return a.forcepointUpdate(f, action, identity)
	default:
		return fmt.Errorf("unsupported identity integration: %s", f.Vendor)
	}
}

func (a *App) refreshOrAdd(f Firewall, full bool, old map[string]Identity, i Identity) error {
	if previous, ok := old[i.IP]; full && ok && previous.Username == i.Username {
		switch f.Vendor {
		case "watchguard":
			return a.watchguardUpdate(f, "refresh", i)
		case "fortigate":
			return a.fortigateUpdate(f, "refresh", i)
		case "cisco":
			var user string
			if err := a.db.QueryRow("SELECT username FROM cisco_bindings WHERE firewall_id=? AND ip=?", f.ID, i.IP).Scan(&user); err != nil || user != i.Username {
				return errors.New("ISE-PIC binding state missing; manual reconciliation required")
			}
			return nil // persistent binding; re-POST would create a duplicate
		}
	}
	return a.updateFirewall(f, "add", i)
}

func (a *App) vendorFirewalls(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	if r.Method == http.MethodPost {
		if !sameOrigin(r) {
			http.Error(w, "invalid origin", 403)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		name, addr, secret, vendor := strings.TrimSpace(r.Form.Get("name")), strings.TrimSpace(r.Form.Get("address")), r.Form.Get("secret"), r.Form.Get("vendor")
		if !supportedVendor(vendor) || name == "" || len(name) > 200 || addr == "" || len(addr) > 500 || secret == "" || len(secret) > 16384 {
			http.Error(w, "valid integration, name, endpoint and credential are required", 400)
			return
		}
		// Fail closed on insecure or malformed HTTP endpoints. WatchGuard RSSO is
		// the sole UDP transport and intentionally accepts host[:port].
		if vendor != "watchguard" && vendor != "fortigate" && vendor != "checkpoint" {
			if _, err := panEndpoint(addr); err != nil {
				http.Error(w, "HTTPS host with optional port required", 400)
				return
			}
		}
		if vendor == "watchguard" || vendor == "fortigate" {
			host, port, err := net.SplitHostPort(addr)
			n, _ := strconv.Atoi(port)
			if err != nil || host == "" || n < 1 || n > 65535 {
				http.Error(w, "RADIUS accounting host:port required", 400)
				return
			}
		}
		if vendor == "cisco" {
			if _, err := parseCiscoSecret(secret); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		if vendor == "fortigate" {
			var cfg struct {
				SharedSecret string `json:"shared_secret"`
				Group        string `json:"group"`
			}
			if json.Unmarshal([]byte(secret), &cfg) != nil || cfg.SharedSecret == "" || cfg.Group == "" {
				http.Error(w, "FortiGate RSSO needs JSON shared_secret and group", 400)
				return
			}
		}
		verify := 1
		if r.Form.Get("verify_tls") != "on" {
			verify = 0
		}
		if _, err := a.db.Exec("INSERT INTO firewalls(name,vendor,address,secret,verify_tls,enabled,last_status) VALUES(?,?,?,?,?,1,'Not yet synchronized')", name, vendor, addr, secret, verify); err != nil {
			http.Error(w, "unable to add integration", 500)
			return
		}
		a.recordNotice("Integration added: " + name)
		http.Redirect(w, r, "/firewalls", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	render(w, fwT, map[string]any{"FW": a.listFW(), "Notice": a.latestNotice(), "Page": "firewalls"})
}

func (a *App) testVendorFirewall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "invalid origin", 403)
		return
	}
	if _, ok := a.require(w, r); !ok {
		return
	}
	id := atoi(r.FormValue("id"), 0)
	var f *Firewall
	for _, item := range a.listFW() {
		if item.ID == id {
			x := item
			f = &x
			break
		}
	}
	if f == nil {
		a.recordNotice("Integration test failed: not found")
		http.Redirect(w, r, "/firewalls", 303)
		return
	}
	var msg string
	var err error
	switch f.Vendor {
	case "checkpoint":
		err = a.cp(*f, "show-identity", map[string]any{"ip-address": "127.0.0.1"})
		msg = "Check Point Identity Web API responded"
	case "paloalto":
		msg, err = a.panProbe(*f)
	case "cisco":
		msg, err = a.ciscoProbe(*f)
	case "watchguard", "fortigate":
		err = errors.New("RADIUS RSSO has no documented read-only probe; verify on the firewall after a controlled sync")
	case "sonicwall":
		msg, err = a.sonicwallProbe(*f)
	case "fortinet":
		msg, err = a.fortinetProbe(*f)
	case "forcepoint":
		msg, err = a.forcepointProbe(*f)
	default:
		err = errors.New("unknown integration")
	}
	if err != nil {
		msg = "Read-only test unavailable or failed: " + err.Error()
	}
	a.recordNotice(msg)
	http.Redirect(w, r, "/firewalls", 303)
}

func (a *App) vendorDeleteFirewall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "invalid origin", 403)
		return
	}
	if _, ok := a.require(w, r); !ok {
		return
	}
	id := atoi(r.FormValue("id"), 0)
	a.mu.Lock()
	defer a.mu.Unlock()
	var name, vendor string
	if err := a.db.QueryRow("SELECT name,vendor FROM firewalls WHERE id=?", id).Scan(&name, &vendor); err != nil {
		a.recordNotice("Firewall not found")
		http.Redirect(w, r, "/firewalls", 303)
		return
	}
	if vendor == "cisco" {
		var count int
		if err := a.db.QueryRow("SELECT COUNT(*) FROM cisco_bindings WHERE firewall_id=?", id).Scan(&count); err != nil || count > 0 {
			a.recordNotice("Clear Cisco ISE-PIC mappings before removing this integration; binding IDs must be retained for logout")
			http.Redirect(w, r, "/firewalls", 303)
			return
		}
	}
	tx, err := a.db.Begin()
	if err != nil {
		http.Error(w, "database unavailable", 500)
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM identities WHERE firewall_id=?", id); err != nil {
		http.Error(w, "database error", 500)
		return
	}
	if _, err = tx.Exec("DELETE FROM cisco_bindings WHERE firewall_id=?", id); err != nil {
		http.Error(w, "database error", 500)
		return
	}
	if _, err = tx.Exec("DELETE FROM firewalls WHERE id=?", id); err != nil {
		http.Error(w, "database error", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "database error", 500)
		return
	}
	a.recordNotice("Removed integration: " + name + ". Previously submitted device mappings, if any, were not removed by this action")
	http.Redirect(w, r, "/firewalls", 303)
}

func (a *App) deleteVendorMappings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "invalid origin", 403)
		return
	}
	if _, ok := a.require(w, r); !ok {
		return
	}
	id := atoi(r.FormValue("id"), 0)
	var f *Firewall
	for _, item := range a.listFW() {
		if item.ID == id {
			x := item
			f = &x
			break
		}
	}
	if f == nil {
		a.recordNotice("Delete mappings failed: firewall not found")
		http.Redirect(w, r, "/firewalls", 303)
		return
	}
	rows, err := a.db.Query("SELECT ip,username FROM identities WHERE firewall_id=? ORDER BY ip", id)
	if err != nil {
		a.recordNotice("Delete mappings failed: local inventory unavailable")
		http.Redirect(w, r, "/firewalls", 303)
		return
	}
	var identities []Identity
	for rows.Next() {
		var i Identity
		if err = rows.Scan(&i.IP, &i.Username); err != nil {
			break
		}
		identities = append(identities, i)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		a.recordNotice("Delete mappings failed: local inventory error")
		http.Redirect(w, r, "/firewalls", 303)
		return
	}
	a.mu.Lock()
	count := 0
	for _, i := range identities {
		if err = a.updateFirewall(*f, "delete", i); err != nil {
			break
		}
		if _, err = a.db.Exec("DELETE FROM identities WHERE firewall_id=? AND ip=?", id, i.IP); err != nil {
			break
		}
		count++
	}
	a.mu.Unlock()
	if err != nil {
		a.recordNotice(fmt.Sprintf("Deleted %d mappings; stopped on error: %v", count, err))
	} else {
		a.recordNotice(fmt.Sprintf("Deleted %d tracked mappings from %s; active sessions will be restored by the next sync", count, f.Name))
	}
	http.Redirect(w, r, "/firewalls", 303)
}

// Only Check Point has a implemented per-IP device read API. All others show
// the application's last confirmed writes, explicitly not a firewall inventory.
func (a *App) vendorFirewallIdentities(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	id := atoi(r.FormValue("id"), 0)
	var f *Firewall
	for _, item := range a.listFW() {
		if item.ID == id {
			x := item
			f = &x
			break
		}
	}
	if f == nil {
		http.Error(w, "firewall not found", 404)
		return
	}
	if f.Vendor == "checkpoint" {
		a.firewallIdentities(w, r)
		return
	}
	rows, err := a.db.Query("SELECT ip,username FROM identities WHERE firewall_id=? ORDER BY ip", id)
	if err != nil {
		http.Error(w, "inventory unavailable", 500)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><title>Tracked mappings</title><style>body{font:16px system-ui;background:#0f172a;color:#e5e7eb;padding:24px}th,td{padding:10px;border-bottom:1px solid #334155}table{border-collapse:collapse}</style><a href='/firewalls'>← Firewalls</a><h1>%s — tracked mappings</h1><p>Last successfully submitted by Identity Sync; this is NOT a live device inventory.</p><table><tr><th>IP</th><th>User</th></tr>", html.EscapeString(f.Name))
	for rows.Next() {
		var ip, user string
		if rows.Scan(&ip, &user) != nil {
			break
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>", html.EscapeString(ip), html.EscapeString(user))
	}
	fmt.Fprint(w, "</table>")
}
