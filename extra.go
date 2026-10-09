package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ConfigArchive contains configuration only. Runtime mappings, browser sessions,
// debug logs, notices and statistics are deliberately excluded.
type ConfigArchive struct {
	Version          int               `json:"version"`
	Config           []ConfigEntry     `json:"config"`
	Firewalls        []ArchiveFirewall `json:"firewalls"`
	Admins           []ArchiveAdmin    `json:"admins"`
	ManualIdentities []Identity        `json:"manual_identities"`
}
type ConfigEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type ArchiveFirewall struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Vendor    string `json:"vendor"`
	Address   string `json:"address"`
	Secret    string `json:"secret"`
	VerifyTLS bool   `json:"verify_tls"`
	Enabled   bool   `json:"enabled"`
}
type ArchiveAdmin struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Mode         string `json:"mode"`
	PasswordHash string `json:"password_hash"`
}

func (a *App) initExtras() error {
	_, err := a.db.Exec(`CREATE TABLE IF NOT EXISTS stat_events (
 id INTEGER PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL,
 outcome TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`CREATE TABLE IF NOT EXISTS radius_source_snapshot (ip TEXT PRIMARY KEY, username TEXT NOT NULL)`)
 if err != nil { return err }
 _, err = a.db.Exec(`CREATE INDEX IF NOT EXISTS stat_events_created ON stat_events(created)`)
	return err
}

// recordStat is a best-effort operational counter. Callers must supply a short,
// non-sensitive detail (never API errors, credentials, request bodies or usernames).
func (a *App) recordStat(kind, outcome, detail string) {
	if a.db == nil {
		return
	}
	if len(kind) > 64 || len(outcome) > 64 || len(detail) > 160 || kind == "" || outcome == "" {
		return
	}
	a.db.Exec(`INSERT INTO stat_events(created,kind,outcome,detail) VALUES(?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), kind, outcome, detail)
}

func extraMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if method == http.MethodPost {
		// Reject cross-origin form submissions. An absent Origin is allowed for older
		// same-site clients; modern browsers attach it to cross-origin POSTs.
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := r.URL.Parse(origin)
			if err != nil || u.Host != r.Host || u.Scheme != requestScheme(r) {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return false
			}
		}
	}
	return true
}
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

func (a *App) configExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	if !extraMethod(w, r, http.MethodGet) {
		return
	}
	out := ConfigArchive{Version: 1, Config: []ConfigEntry{}, Firewalls: []ArchiveFirewall{}, Admins: []ArchiveAdmin{}, ManualIdentities: []Identity{}}
	rows, err := a.db.Query(`SELECT k,v FROM config WHERE k!='last_notice' ORDER BY k`)
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	for rows.Next() {
		var c ConfigEntry
		if err = rows.Scan(&c.Key, &c.Value); err != nil {
			break
		}
		out.Config = append(out.Config, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	rows, err = a.db.Query(`SELECT id,name,vendor,address,secret,verify_tls,enabled FROM firewalls ORDER BY id`)
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	for rows.Next() {
		var f ArchiveFirewall
		var verify, enabled int
		if err = rows.Scan(&f.ID, &f.Name, &f.Vendor, &f.Address, &f.Secret, &verify, &enabled); err != nil {
			break
		}
		f.VerifyTLS = verify != 0
		f.Enabled = enabled != 0
		out.Firewalls = append(out.Firewalls, f)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	rows, err = a.db.Query(`SELECT id,username,mode,COALESCE(password,'') FROM users ORDER BY id`)
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	for rows.Next() {
		var u ArchiveAdmin
		if err = rows.Scan(&u.ID, &u.Username, &u.Mode, &u.PasswordHash); err != nil {
			break
		}
		out.Admins = append(out.Admins, u)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	rows, err = a.db.Query(`SELECT ip,username FROM manual_identities ORDER BY ip`)
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	for rows.Next() {
		var i Identity
		if err = rows.Scan(&i.IP, &i.Username); err != nil {
			break
		}
		out.ManualIdentities = append(out.ManualIdentities, i)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		http.Error(w, "export failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="identity-sync-config.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(append(b, '\n'))
}

func validateArchive(v *ConfigArchive) error {
	if v.Version != 1 {
		return errors.New("unsupported archive version")
	}
	if len(v.Config) > 256 || len(v.Firewalls) > 1000 || len(v.Admins) > 1000 || len(v.ManualIdentities) > 10000 {
		return errors.New("archive has too many entries")
	}
	if len(v.Admins) == 0 {
		return errors.New("at least one administrator is required")
	}
	keys := map[string]bool{}
	for _, c := range v.Config {
		if len(c.Key) == 0 || len(c.Key) > 100 || len(c.Value) > 16384 || strings.ContainsAny(c.Key, "\x00\r\n") || c.Key == "last_notice" || keys[c.Key] {
			return errors.New("invalid or duplicate configuration key")
		}
		keys[c.Key] = true
		switch c.Key {
		case "poll_seconds", "full_minutes", "interim_seconds", "radius_auth_port", "radius_acct_port":
			n, e := strconv.Atoi(c.Value)
			if e != nil || n < 1 || n > 86400 {
				return errors.New("invalid numeric configuration value")
			}
		case "radius_verify_tls", "debug_enabled":
			if c.Value != "true" && c.Value != "false" {
				return errors.New("invalid boolean configuration value")
			}
		}
	}
	ids := map[int]bool{}
	for _, f := range v.Firewalls {
		if f.ID <= 0 || ids[f.ID] || len(f.Name) == 0 || len(f.Name) > 200 || f.Vendor != "checkpoint" || len(f.Address) == 0 || len(f.Address) > 500 || len(f.Secret) == 0 || len(f.Secret) > 16384 {
			return errors.New("invalid or duplicate firewall")
		}
		ids[f.ID] = true
	}
	ids = map[int]bool{}
	names := map[string]bool{}
	for _, u := range v.Admins {
		if u.ID <= 0 || ids[u.ID] || u.Username == "" || len(u.Username) > 200 || names[u.Username] || (u.Mode != "local" && u.Mode != "radius") {
			return errors.New("invalid or duplicate administrator")
		}
		ids[u.ID] = true
		names[u.Username] = true
		if u.Mode == "local" {
			if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
				return errors.New("invalid administrator password hash")
			}
		} else if u.PasswordHash != "" {
			return errors.New("RADIUS administrator must not have a password hash")
		}
	}
	ips := map[string]bool{}
	for _, i := range v.ManualIdentities {
		ip, e := netip.ParseAddr(i.IP)
		if e != nil || !ip.Is4() || ip.String() != i.IP || ips[i.IP] || strings.TrimSpace(i.Username) == "" || len(i.Username) > 200 {
			return errors.New("invalid or duplicate manual identity")
		}
		ips[i.IP] = true
	}
	return nil
}

func (a *App) configImport(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	if !extraMethod(w, r, http.MethodPost) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var src io.Reader = r.Body
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			http.Error(w, "invalid or oversized import", 400)
			return
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", 400)
			return
		}
		defer f.Close()
		src = f
	}
	dec := json.NewDecoder(src)
	dec.DisallowUnknownFields()
	var v ConfigArchive
	if err := dec.Decode(&v); err != nil {
		http.Error(w, "invalid import JSON", 400)
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		http.Error(w, "unexpected trailing JSON", 400)
		return
	}
	if err := validateArchive(&v); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// End live sessions before replacing administrator records so RADIUS Stop
	// can read the session's final accounting counters. No network IO in tx.
	active, err := a.sessionTokens(0)
	if err != nil {
		http.Error(w, "failed to list sessions", 500)
		return
	}
	for _, sid := range active {
		a.endSession(a.cfg(), sid)
	}
	tx, err := a.db.Begin()
	if err != nil {
		http.Error(w, "import failed", 500)
		return
	}
	defer tx.Rollback()
	for _, table := range []string{"config", "identities", "radius_source_snapshot", "manual_identities", "firewalls", "web_sessions", "users"} {
		if _, err = tx.Exec("DELETE FROM " + table); err != nil {
			http.Error(w, "import failed", 500)
			return
		}
	}
	for _, c := range v.Config {
		if _, err = tx.Exec(`INSERT INTO config(k,v) VALUES(?,?)`, c.Key, c.Value); err != nil {
			break
		}
	}
	if err == nil {
		for _, u := range v.Admins {
			_, err = tx.Exec(`INSERT INTO users(id,username,mode,password) VALUES(?,?,?,?)`, u.ID, u.Username, u.Mode, u.PasswordHash)
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		for _, f := range v.Firewalls {
			_, err = tx.Exec(`INSERT INTO firewalls(id,name,vendor,address,secret,verify_tls,enabled,last_status,last_sync) VALUES(?,?,?,?,?,?,?,'Not yet synchronized','')`, f.ID, f.Name, f.Vendor, f.Address, f.Secret, f.VerifyTLS, f.Enabled)
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		for _, i := range v.ManualIdentities {
			_, err = tx.Exec(`INSERT INTO manual_identities(ip,username) VALUES(?,?)`, i.IP, i.Username)
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "import failed", 500)
		return
	}
	a.recordStat("config_import", "success", fmt.Sprintf("firewalls=%d admins=%d manual=%d", len(v.Firewalls), len(v.Admins), len(v.ManualIdentities)))
	http.SetCookie(w, &http.Cookie{Name: "ia_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "Import complete: %d settings, %d firewalls, %d administrators, %d manual identities. All browser sessions were ended; sign in again.\n", len(v.Config), len(v.Firewalls), len(v.Admins), len(v.ManualIdentities))
}

func extraID(r *http.Request) (int, error) {
	if err := r.ParseForm(); err != nil {
		return 0, err
	}
	id, e := strconv.Atoi(r.Form.Get("id"))
	if e != nil || id <= 0 {
		return 0, errors.New("valid id required")
	}
	return id, nil
}

// sessionTokens snapshots tokens before endSession performs network IO and deletion.
// userID=0 selects every session (configuration replacement).
func (a *App) sessionTokens(userID int) ([]string, error) {
	query := `SELECT token FROM web_sessions`
	var args []any
	if userID > 0 {
		query += ` WHERE user_id=?`
		args = append(args, userID)
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var sid string
		if err = rows.Scan(&sid); err != nil {
			return nil, err
		}
		tokens = append(tokens, sid)
	}
	return tokens, rows.Err()
}

func (a *App) adminEnd(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	if !extraMethod(w, r, http.MethodPost) {
		return
	}
	id, err := extraID(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var exists int
	if err = a.db.QueryRow(`SELECT id FROM users WHERE id=?`, id).Scan(&exists); err != nil {
		http.Error(w, "administrator not found", 404)
		return
	}
	tokens, err := a.sessionTokens(id)
	if err != nil {
		http.Error(w, "failed to list sessions", 500)
		return
	}
	c := a.cfg()
	for _, sid := range tokens {
		a.endSession(c, sid)
	}
	a.recordStat("admin_sessions_end", "success", fmt.Sprintf("count=%d", len(tokens)))
	http.Redirect(w, r, "/admins", http.StatusSeeOther)
}

func (a *App) adminDelete(w http.ResponseWriter, r *http.Request) {
	current, ok := a.require(w, r)
	if !ok {
		return
	}
	if !extraMethod(w, r, http.MethodPost) {
		return
	}
	id, err := extraID(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if id == current.ID {
		http.Error(w, "cannot delete your own administrator account", 400)
		return
	}
	var name string
	if err = a.db.QueryRow(`SELECT username FROM users WHERE id=?`, id).Scan(&name); err != nil {
		http.Error(w, "administrator not found", 404)
		return
	}
	tokens, err := a.sessionTokens(id)
	if err != nil {
		http.Error(w, "failed to list sessions", 500)
		return
	}
	c := a.cfg()
	for _, sid := range tokens {
		a.endSession(c, sid)
	}
	tx, err := a.db.Begin()
	if err != nil {
		http.Error(w, "delete failed", 500)
		return
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil || count <= 1 {
		http.Error(w, "cannot delete the last administrator", 400)
		return
	}
	// End sessions before deleting the user; no orphaned browser session remains.
	if _, err = tx.Exec(`DELETE FROM web_sessions WHERE user_id=?`, id); err == nil {
		_, err = tx.Exec(`DELETE FROM users WHERE id=?`, id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "delete failed", 500)
		return
	}
	a.recordStat("admin_delete", "success", "")
	http.Redirect(w, r, "/admins", http.StatusSeeOther)
}

func (a *App) manualDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	if !extraMethod(w, r, http.MethodPost) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	ip := r.Form.Get("ip")
	parsed, err := netip.ParseAddr(ip)
	if err != nil || !parsed.Is4() {
		http.Error(w, "valid IPv4 address required", 400)
		return
	}
	res, err := a.db.Exec(`DELETE FROM manual_identities WHERE ip=?`, ip)
	if err != nil {
		http.Error(w, "delete failed", 500)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "manual identity not found", 404)
		return
	}
	a.recordStat("manual_delete", "success", "")
	http.Redirect(w, r, "/manual", http.StatusSeeOther)
}

type statRow struct {
	Kind, Outcome string
	Count         int
}
type statBucket struct {
	Label, Kind, Outcome string
	Count                int
}
type statEvent struct{ Created, Kind, Outcome, Detail string }

func statsBucket(t time.Time, unit string) time.Time {
	t = t.UTC()
	switch unit {
	case "second":
		return t.Truncate(time.Second)
	case "minute":
		return t.Truncate(time.Minute)
	case "hour":
		return t.Truncate(time.Hour)
	case "day":
		return t.Truncate(24 * time.Hour)
	case "week":
		return t.Truncate(24*time.Hour).AddDate(0, 0, -(int(t.Weekday())+6)%7)
	case "month":
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	default:
		return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	}
}
func statsWindow(unit string, now time.Time) (time.Time, string, error) {
	switch unit {
	case "second":
		return statsBucket(now.Add(-59*time.Second), unit), "%Y-%m-%dT%H:%M:%S", nil
	case "minute":
		return statsBucket(now.Add(-59*time.Minute), unit), "%Y-%m-%dT%H:%M", nil
	case "hour":
		return statsBucket(now.Add(-23*time.Hour), unit), "%Y-%m-%dT%H", nil
	case "day":
		return statsBucket(now.AddDate(0, 0, -29), unit), "%Y-%m-%d", nil
	case "week":
		return statsBucket(now.AddDate(0, 0, -77), unit), "", nil
	case "month":
		return statsBucket(now.AddDate(0, -11, 0), unit), "%Y-%m", nil
	case "year":
		return statsBucket(now.AddDate(-4, 0, 0), unit), "%Y", nil
	default:
		return time.Time{}, "", errors.New("invalid unit")
	}
}
func (a *App) stats(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.require(w, r); !ok {
		return
	}
	if !extraMethod(w, r, http.MethodGet) {
		return
	}
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "hour"
	}
	since, format, err := statsWindow(unit, time.Now().UTC())
	if err != nil {
		http.Error(w, "invalid unit", 400)
		return
	}
	// SQL aggregates per metric, outcome and time bucket; individual events are
	// never loaded to construct the graph. Units are a fixed allowlist above.
	bucketExpr := `strftime('` + format + `',created)`
	if unit == "week" {
		bucketExpr = `date(created, '-' || ((cast(strftime('%w',created) as integer)+6)%7) || ' days')`
	}
	query := `SELECT ` + bucketExpr + `,kind,outcome,count(*) FROM stat_events WHERE created>=? GROUP BY 1,2,3 ORDER BY 1,2,3`
	rows, err := a.db.Query(query, since.Format(time.RFC3339))
	if err != nil {
		http.Error(w, "statistics unavailable", 500)
		return
	}
	var buckets []statBucket
	groupedMap := map[string]*statRow{}
	maxCount := 1
	for rows.Next() {
		var b statBucket
		if err = rows.Scan(&b.Label, &b.Kind, &b.Outcome, &b.Count); err != nil {
			break
		}
		buckets = append(buckets, b)
		key := b.Kind + "\x00" + b.Outcome
		if groupedMap[key] == nil {
			groupedMap[key] = &statRow{Kind: b.Kind, Outcome: b.Outcome}
		}
		groupedMap[key].Count += b.Count
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "statistics unavailable", 500)
		return
	}
	var grouped []statRow
	for _, v := range groupedMap {
		grouped = append(grouped, *v)
	}
	sort.Slice(grouped, func(i, j int) bool {
		if grouped[i].Kind == grouped[j].Kind {
			return grouped[i].Outcome < grouped[j].Outcome
		}
		return grouped[i].Kind < grouped[j].Kind
	})
	rows, err = a.db.Query(`SELECT created,kind,outcome,detail FROM stat_events WHERE created>=? ORDER BY id DESC LIMIT 100`, since.Format(time.RFC3339))
	if err != nil {
		http.Error(w, "statistics unavailable", 500)
		return
	}
	var recent []statEvent
	for rows.Next() {
		var v statEvent
		if err = rows.Scan(&v.Created, &v.Kind, &v.Outcome, &v.Detail); err != nil {
			break
		}
		recent = append(recent, v)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "statistics unavailable", 500)
		return
	}
	var fwCount, manualCount, trackedCount int
	a.db.QueryRow(`SELECT count(*) FROM firewalls`).Scan(&fwCount)
	a.db.QueryRow(`SELECT count(*) FROM manual_identities`).Scan(&manualCount)
	a.db.QueryRow(`SELECT count(*) FROM identities`).Scan(&trackedCount)
	w.Header().Set("Cache-Control", "no-store")
	render(w, extrasStatsT, map[string]any{"Unit": unit, "Units": []string{"second","minute","hour","day","week","month","year"}, "Grouped": grouped, "Buckets": buckets, "Max": maxCount, "Recent": recent, "Firewalls": fwCount, "Manual": manualCount, "Tracked": trackedCount})
}

const extrasStatsT = `{{define "body"}}<div class="app">{{template "nav" "stats"}}<main class="main">{{template "top" "Statistics"}}<header class="pagehead"><p class="eyebrow">Operational insights</p><h1>Statistics</h1><p>Firewall updates, RadiusStack API activity, synchronization outcomes and unchanged lookups. UTC buckets; data starts from this release.</p></header>
<section class="card"><div class="card-head"><div><h2>Granularity</h2><p>Grouping: {{.Unit}} (UTC). Default view groups events by hour.</p></div><span class="badge">{{.Unit}}</span></div><div class="actions">{{range $v := .Units}}<a class="button secondary small" href="/stats?unit={{$v}}">{{$v}}</a>{{end}}</div></section>
<div class="grid three"><section class="card"><span class="stat-label">Tracked mappings</span><div class="stat">{{.Tracked}}</div></section><section class="card"><span class="stat-label">Firewalls</span><div class="stat">{{.Firewalls}}</div></section><section class="card"><span class="stat-label">Manual identities</span><div class="stat">{{.Manual}}</div></section></div>
<section class="card"><div class="card-head"><div><h2>Metrics by outcome</h2><p>Counts in the selected window.</p></div></div><div class="table-wrap"><table><thead><tr><th>Metric</th><th>Outcome</th><th>Count</th></tr></thead><tbody>{{range .Grouped}}<tr><td>{{.Kind}}</td><td>{{.Outcome}}</td><td><strong>{{.Count}}</strong></td></tr>{{else}}<tr><td colspan="3">No events in this window yet.</td></tr>{{end}}</tbody></table></div></section>
<section class="card"><div class="card-head"><div><h2>Activity by {{.Unit}}</h2><p>Per-bucket graph and detailed metric table (UTC).</p></div></div><div class="table-wrap"><table><thead><tr><th>Bucket</th><th>Metric</th><th>Outcome</th><th>Graph</th><th>Count</th></tr></thead><tbody>{{range .Buckets}}<tr><td><code>{{.Label}}</code></td><td>{{.Kind}}</td><td>{{.Outcome}}</td><td><progress value="{{.Count}}" max="{{$.Max}}" style="width:clamp(70px,16vw,200px)"></progress></td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="5">No recorded activity.</td></tr>{{end}}</tbody></table></div></section>
<section class="card"><div class="card-head"><div><h2>Recent events</h2><p>Last 100 events in the selected window.</p></div></div><div class="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Metric</th><th>Outcome</th><th>Detail</th></tr></thead><tbody>{{range .Recent}}<tr><td>{{.Created}}</td><td>{{.Kind}}</td><td>{{.Outcome}}</td><td>{{.Detail}}</td></tr>{{else}}<tr><td colspan="4">No recent events.</td></tr>{{end}}</tbody></table></div></section></main></div>{{end}}` + base
