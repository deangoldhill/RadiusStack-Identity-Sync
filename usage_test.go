package main
import (
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)
func TestMeasuredTrafficRemainsPrivateInSession(t *testing.T){
 a:=extrasTestApp(t);now:=time.Now().UTC().Format(time.RFC3339)
 if _,e:=a.db.Exec("INSERT INTO web_sessions(token,user_id,created,last_seen) VALUES('usage-test',1,?,?)",now,now);e!=nil{t.Fatal(e)}
 h:=a.measured(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){io.Copy(io.Discard,r.Body);w.Write([]byte("response"))}))
 req:=httptest.NewRequest("POST","/private",strings.NewReader("request"));req.AddCookie(&http.Cookie{Name:"ia_session",Value:"usage-test"})
 w:=httptest.NewRecorder();h.ServeHTTP(w,req)
 input,output:=a.sessionUsage("usage-test")
 if input!=7||output!=8{t.Fatalf("usage mismatch %d/%d",input,output)}
 if strings.Contains(w.Body.String(),"7")||strings.Contains(w.Body.String(),"8"){t.Fatal("usage leaked in response")}
}
