package main

import (
 "crypto/md5"
 "crypto/subtle"
 "encoding/binary"
 "io"
 "net/http"
 "strings"
 "time"
)

// usageWriter measures bytes sent by this web service, not NAS traffic.
type usageWriter struct { http.ResponseWriter; bytes uint64 }
func (w *usageWriter) Write(p []byte)(int,error){n,e:=w.ResponseWriter.Write(p);w.bytes+=uint64(n);return n,e}
type usageReader struct { io.ReadCloser; bytes uint64 }
func (r *usageReader) Read(p []byte)(int,error){n,e:=r.ReadCloser.Read(p);r.bytes+=uint64(n);return n,e}
func (a *App) measured(next http.Handler) http.Handler {return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
 var sid string
 if ck,e:=r.Cookie("ia_session");e==nil {sid=ck.Value}
 uw:=&usageWriter{ResponseWriter:w};ur:=&usageReader{ReadCloser:r.Body};r.Body=ur
 next.ServeHTTP(uw,r)
 if sid!="" {a.db.Exec("UPDATE web_sessions SET input_octets=input_octets+?,output_octets=output_octets+? WHERE token=?",ur.bytes,uw.bytes,sid)}
 })}
func (a *App) sessionUsage(sid string)(uint64,uint64){var in,out uint64;a.db.QueryRow("SELECT input_octets,output_octets FROM web_sessions WHERE token=?",sid).Scan(&in,&out);return in,out}
func uintAttr(t byte,n uint32)[]byte{v:=make([]byte,4);binary.BigEndian.PutUint32(v,n);return attr(t,v)}
func accountingAttrs(user,sid string,status,sessionTime int,input,output uint64)[]byte{
 attrs:=append(attr(1,[]byte(user)),uintAttr(40,uint32(status))...)
 attrs=append(attrs,attr(44,[]byte(sid))...)
 if status!=1 {attrs=append(attrs,uintAttr(46,uint32(max(0,sessionTime)))...)}
 attrs=append(attrs,uintAttr(42,uint32(input))...)
 attrs=append(attrs,uintAttr(43,uint32(output))...)
 attrs=append(attrs,uintAttr(52,uint32(input>>32))...)
 attrs=append(attrs,uintAttr(53,uint32(output>>32))...)
 return attrs
}
func validAccountingResponse(req,resp,secret []byte)bool{
 if len(req)<20||len(resp)<20||resp[0]!=5||resp[1]!=req[1]||int(binary.BigEndian.Uint16(resp[2:4]))!=len(resp){return false}
 h:=md5.New();h.Write(resp[:4]);h.Write(req[4:20]);h.Write(resp[20:]);h.Write(secret)
 return subtle.ConstantTimeCompare(h.Sum(nil),resp[4:20])==1
}
func (a *App) endSession(c Config,sid string){
 var username,created string
 if e:=a.db.QueryRow("SELECT u.username,s.created FROM web_sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",sid).Scan(&username,&created);e!=nil{return}
 ct,_:=time.Parse(time.RFC3339,created)
 // Stop before removal so measured octets remain available to the accounting sender.
 a.account(c,username,sid,2,int(time.Since(ct).Seconds()))
 a.db.Exec("DELETE FROM web_sessions WHERE token=?",sid)
}
func sameOrigin(r *http.Request)bool {origin:=r.Header.Get("Origin");if origin==""{return true};return strings.EqualFold(origin,"http://"+r.Host)||strings.EqualFold(origin,"https://"+r.Host)}
