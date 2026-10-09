package main

import "testing"

func TestDesiredSkipsIncompleteAndDeduplicates(t *testing.T) {
 in := []RadiusSession{{ID:"1", Username:"alice", IP:"10.0.0.2"}, {ID:"2", Username:"alice", IP:"10.0.0.2"}, {ID:"3", Username:"", IP:"10.0.0.3"}, {ID:"4", Username:"bob", IP:"bad"}}
 got := desired(in)
 if len(got) != 1 || got["10.0.0.2"].Username != "alice" { t.Fatalf("unexpected desired state: %#v", got) }
}
func TestDiffProducesAddUpdateDelete(t *testing.T) {
 old := map[string]Identity{"10.0.0.1": {Username:"old", IP:"10.0.0.1"}, "10.0.0.3": {Username:"gone", IP:"10.0.0.3"}}
 now := map[string]Identity{"10.0.0.1": {Username:"new", IP:"10.0.0.1"}, "10.0.0.2": {Username:"added", IP:"10.0.0.2"}}
 add, del := diff(old, now)
 if len(add)!=2 || len(del)!=2 { t.Fatalf("add=%#v del=%#v",add,del) }
}
func TestIntervalsAreBounded(t *testing.T) {
 if validateSeconds(1)!=5 || validateSeconds(30)!=30 || validateMinutes(0)!=1 { t.Fatal("interval bounds incorrect") }
}
