package main

import (
 "encoding/binary"
 "testing"
)
func TestInterimAttributesIncludePrivateWebUsageAndSessionTime(t *testing.T){
 attrs:=accountingAttrs("dean","session",3,125,4294967301,42)
 values:=map[byte]uint32{}
 for i:=0;i<len(attrs); {if i+2>len(attrs)||int(attrs[i+1])<2||i+int(attrs[i+1])>len(attrs){t.Fatal("invalid attribute")};if attrs[i+1]==6 {values[attrs[i]]=binary.BigEndian.Uint32(attrs[i+2:i+6])};i+=int(attrs[i+1])}
 for typ,want:=range map[byte]uint32{40:3,46:125,42:5,43:42,52:1,53:0}{if values[typ]!=want{t.Errorf("attribute %d got %d want %d",typ,values[typ],want)}}
}
