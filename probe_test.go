package main

import (
 "database/sql"
 "net/http"
 "net/http/httptest"
 "testing"
 _ "modernc.org/sqlite"
)

func TestRadiusProbeReportsActiveSessionCount(t *testing.T) {
 s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.Header.Get("X-API-Key") != "key" { http.Error(w, "missing key", 401); return }
  w.Header().Set("Content-Type", "application/json")
  w.Write([]byte(`[{"radacctid":1,"username":"alice","framedipaddress":"10.0.0.2"},{"radacctid":2,"username":"bad","framedipaddress":""}]`))
 }))
 defer s.Close()
 a := &App{httpc: s.Client()}
 got, err := a.radiusProbe(Config{RadiusURL:s.URL, RadiusAPIKey:"key"})
 if err != nil { t.Fatal(err) }
 if got != "RadiusStack API reachable: 2 active sessions, 1 valid IPv4 identity" { t.Fatalf("%q", got) }
}

func TestSyncNowPersistsVisibleResult(t *testing.T) {
 db, err := sql.Open("sqlite", ":memory:"); if err != nil { t.Fatal(err) }
 a := &App{db:db, httpc:&http.Client{}}
 if err=a.init();err!=nil {t.Fatal(err)}
 a.recordNotice("Manual synchronization requested")
 if a.latestNotice() != "Manual synchronization requested" { t.Fatal("notice was not persisted") }
}
