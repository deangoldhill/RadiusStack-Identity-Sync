package main
import "testing"
func TestSourceChangesCountOnlyObservedDeltas(t *testing.T){
 a:=extrasTestApp(t)
 a.trackSource([]RadiusSession{{Username:"alice",IP:"10.0.0.1"}})
 a.trackSource([]RadiusSession{{Username:"alice",IP:"10.0.0.1"}})
 a.trackSource([]RadiusSession{{Username:"bob",IP:"10.0.0.1"},{Username:"carol",IP:"10.0.0.2"}})
 var n int
 if e:=a.db.QueryRow("SELECT count(*) FROM stat_events WHERE kind='radiusstack_updates'").Scan(&n);e!=nil||n!=4{t.Fatalf("expected initial add and later two adds/one removal, got %d: %v",n,e)}
}
