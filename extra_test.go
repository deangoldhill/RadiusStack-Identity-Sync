package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func extrasTestApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("DEFAULT_ADMIN_PASSWORD", "test-only-bootstrap-password")
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	a := &App{db: db, httpc: &http.Client{Timeout: time.Second}}
	if err = a.init(); err != nil {
		t.Fatal(err)
	}
	if err = a.initExtras(); err != nil {
		t.Fatal(err)
	}
	return a
}
func extrasRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.AddCookie(&http.Cookie{Name: "ia_session", Value: "test-token"})
	return r
}
func extrasLogin(t *testing.T, a *App) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := a.db.Exec(`INSERT INTO web_sessions(token,user_id,created,last_seen) VALUES('test-token',1,?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
}
func TestExtrasArchiveRoundTripAndInvalidRollback(t *testing.T) {
	a := extrasTestApp(t)
	extrasLogin(t, a)
	a.db.Exec(`INSERT INTO manual_identities(ip,username) VALUES('10.0.0.1','alice')`)
	a.db.Exec(`INSERT INTO firewalls(name,vendor,address,secret,enabled,verify_tls) VALUES('lab','checkpoint','gw.local','private',1,1)`)
	a.db.Exec(`INSERT INTO config(k,v) VALUES('radius_api_key','private-key')`)
	w := httptest.NewRecorder()
	a.configExport(w, extrasRequest("GET", "/config/export", ""))
	if w.Code != 200 {
		t.Fatalf("export: %d %s", w.Code, w.Body.String())
	}
	var v ConfigArchive
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Admins) != 1 || len(v.Firewalls) != 1 || len(v.ManualIdentities) != 1 || v.Firewalls[0].Secret != "private" {
		t.Fatal("incomplete export")
	}
	v.Admins = nil
	b, _ := json.Marshal(v)
	req := extrasRequest("POST", "/config/import", string(b))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	a.configImport(w, req)
	if w.Code != 400 {
		t.Fatalf("invalid import: %d", w.Code)
	}
	var count int
	a.db.QueryRow(`SELECT count(*) FROM manual_identities`).Scan(&count)
	if count != 1 {
		t.Fatal("invalid import changed database")
	}
	v.Admins = []ArchiveAdmin{{ID: 1, Username: "admin", Mode: "local", PasswordHash: func() string { var h string; a.db.QueryRow(`SELECT password FROM users WHERE id=1`).Scan(&h); return h }()}}
	b, _ = json.Marshal(v)
	req = extrasRequest("POST", "/config/import", string(b))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	a.configImport(w, req)
	if w.Code != 200 {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	a.db.QueryRow(`SELECT count(*) FROM web_sessions`).Scan(&count)
	if count != 0 {
		t.Fatal("import retained active sessions")
	}
	a.db.QueryRow(`SELECT count(*) FROM manual_identities`).Scan(&count)
	if count != 1 {
		t.Fatal("import did not restore manual identity")
	}
}
func TestExtrasAdminAndStats(t *testing.T) {
	a := extrasTestApp(t)
	extrasLogin(t, a)
	a.db.Exec(`INSERT INTO users(username,mode,password) VALUES('secondary','radius','')`)
	var id int
	a.db.QueryRow(`SELECT id FROM users WHERE username='secondary'`).Scan(&id)
	now := time.Now().UTC().Format(time.RFC3339)
	a.db.Exec(`INSERT INTO web_sessions(token,user_id,created,last_seen) VALUES('secondary-token',?,?,?)`, id, now, now)
	w := httptest.NewRecorder()
	a.adminEnd(w, extrasRequest("POST", "/admins/end", "id="+strconv.Itoa(id)))
	if w.Code != 303 {
		t.Fatalf("admin end: %d %s", w.Code, w.Body.String())
	}
	var count int
	a.db.QueryRow(`SELECT count(*) FROM web_sessions WHERE user_id=?`, id).Scan(&count)
	if count != 0 {
		t.Fatal("session not ended")
	}
	w = httptest.NewRecorder()
	a.adminDelete(w, extrasRequest("POST", "/admins/delete", "id=1"))
	if w.Code != 400 {
		t.Fatal("self deletion allowed")
	}
	w = httptest.NewRecorder()
	a.adminDelete(w, extrasRequest("POST", "/admins/delete", "id="+strconv.Itoa(id)))
	if w.Code != 303 {
		t.Fatalf("admin delete: %d", w.Code)
	}
	a.recordStat("firewall_update", "success", "")
	w = httptest.NewRecorder()
	a.stats(w, extrasRequest("GET", "/stats", ""))
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("Grouping: hour")) || !bytes.Contains(w.Body.Bytes(), []byte("firewall_update")) {
		t.Fatalf("stats: %d %s", w.Code, w.Body.String())
	}
	for _, unit := range []string{"second", "minute", "hour", "day", "week", "month", "year"} {
		w = httptest.NewRecorder()
		a.stats(w, extrasRequest("GET", "/stats?unit="+unit, ""))
		if w.Code != 200 {
			t.Fatalf("unit %s: %d %s", unit, w.Code, w.Body.String())
		}
	}
}
