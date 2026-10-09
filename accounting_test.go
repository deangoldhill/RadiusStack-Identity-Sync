package main

import (
 "bytes"
 "crypto/md5"
 "testing"
)

func TestAccountingRequestAuthenticatorUsesZeroedAuthenticator(t *testing.T) {
 secret := []byte("shared")
 attrs := attr(1, []byte("dean"))
 p := packet(4, 7, bytes.Repeat([]byte{9}, 16), attrs, secret)
 wantInput := append([]byte{4, 7, 0, byte(20+len(attrs))}, make([]byte, 16)...)
 wantInput = append(wantInput, attrs...)
 wantInput = append(wantInput, secret...)
 want := md5.Sum(wantInput)
 if !bytes.Equal(p[4:20], want[:]) { t.Fatalf("invalid Accounting-Request authenticator: got %x want %x", p[4:20], want) }
}
