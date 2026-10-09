package main

import (
 "encoding/json"
 "fmt"
 "net/http"
 "strconv"
 "strings"
 "time"
)
func bSafeIdentity(body map[string]any)[]byte{safe:=map[string]any{};for k,v:=range body{if k!="shared-secret"{safe[k]=v}};b,_:=json.Marshal(safe);return b}
func (a *App)configPage(w http.ResponseWriter,r *http.Request){if _,ok:=a.require(w,r);!ok{return};if r.Method!="GET"{http.Error(w,"method not allowed",405);return};render(w,configT,map[string]any{"Page":"config"})}
func redactResponse(s,secret string)string{if secret!=""{s=strings.ReplaceAll(s,secret,"[redacted]")};if len(s)>4096{s=s[:4096]+"…"};return s}
func (a *App)debugTail(w http.ResponseWriter,r *http.Request){
 if _,ok:=a.require(w,r);!ok{return}
 limit:=atoi(r.URL.Query().Get("limit"),200);if limit<10{limit=10};if limit>2000{limit=2000}
 after:=atoi(r.URL.Query().Get("after"),0)
 rows,e:=a.db.Query("SELECT id,created,message FROM debug_log WHERE id>? ORDER BY id DESC LIMIT ?",after,limit)
 if e!=nil{http.Error(w,"log unavailable",500);return};defer rows.Close()
 type line struct {ID int `json:"id"`;Created string `json:"created"`;Message string `json:"message"`}
 var result []line;for rows.Next(){var l line;if rows.Scan(&l.ID,&l.Created,&l.Message)==nil{result=append(result,l)}}
 for i,j:=0,len(result)-1;i<j;i,j=i+1,j-1{result[i],result[j]=result[j],result[i]}
 if result==nil{result=[]line{}}
 w.Header().Set("Content-Type","application/json");w.Header().Set("Cache-Control","no-store");json.NewEncoder(w).Encode(result)
}
func (a *App)debugState()(bool,int){if a.db==nil{return false,200};var enabled,limit string;a.db.QueryRow("SELECT v FROM config WHERE k='debug_enabled'").Scan(&enabled);a.db.QueryRow("SELECT v FROM config WHERE k='debug_lines'").Scan(&limit);n,_:=strconv.Atoi(limit);if n<10||n>2000{n=200};return enabled=="true",n}
func (a *App)trimDebug(){a.db.Exec("DELETE FROM debug_log WHERE id < (SELECT COALESCE(MAX(id),0)-50000 FROM debug_log)")}
func (a *App)debugRequest(kind,method,path string,status int,duration time.Duration){a.debugLog(fmt.Sprintf("%s %s %s -> %d (%s)",kind,method,path,status,duration.Round(time.Millisecond)))}
