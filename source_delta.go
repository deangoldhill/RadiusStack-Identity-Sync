package main

// Source changes are observed between successful RadiusStack snapshots, not
// inferred from firewall writes. Failed upstream requests leave the baseline.
func (a *App)trackSource(rows []RadiusSession){
 if a.db==nil{return}
 a.sourceMu.Lock();defer a.sourceMu.Unlock()
 now:=desired(rows);old:=map[string]Identity{}
 rs,e:=a.db.Query("SELECT ip,username FROM radius_source_snapshot");if e!=nil{return}
 for rs.Next(){var i Identity;if rs.Scan(&i.IP,&i.Username)==nil{old[i.IP]=i}};rs.Close()
 add,del:=diff(old,now)
 tx,e:=a.db.Begin();if e!=nil{return};defer tx.Rollback()
 if _,e=tx.Exec("DELETE FROM radius_source_snapshot");e!=nil{return}
 for _,i:=range now {if _,e=tx.Exec("INSERT INTO radius_source_snapshot(ip,username) VALUES(?,?)",i.IP,i.Username);e!=nil{return}}
 if tx.Commit()!=nil{return}
 for range add{a.recordStat("radiusstack_updates","added_or_changed","")}
 for range del{a.recordStat("radiusstack_updates","removed_or_changed","")}
}
