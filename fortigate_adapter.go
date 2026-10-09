package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// fortigateUpdate forwards RADIUS Accounting to a FortiGate RSSO agent.
// FortiOS 8.0.1 RSSO: https://docs.fortinet.com/document/fortigate/8.0.1/administration-guide/85730/radius-single-sign-on-agent
// Secret JSON: {"shared_secret":"...","group":"RSSO-Users"}. The group
// must match the FortiGate RSSO agent's configured RADIUS group attribute
// (Class, 25). The device accepts only the configured source IP/interface.
func (a *App) fortigateUpdate(f Firewall, action string, i Identity) error {
	var status uint32
	switch action {
	case "add":
		status = 1
	case "delete":
		status = 2
	case "refresh":
		status = 3
	default:
		return errors.New("FortiGate RSSO action must be add, delete, or refresh")
	}
	var secret struct {
		SharedSecret string `json:"shared_secret"`
		Group        string `json:"group"`
	}
	if json.Unmarshal([]byte(f.Secret), &secret) != nil || secret.SharedSecret == "" || secret.Group == "" || len(secret.Group) > 253 || strings.ContainsAny(secret.Group, "\x00\r\n") {
		return errors.New("FortiGate RSSO requires JSON shared_secret and group")
	}
	host, portText, err := net.SplitHostPort(f.Address)
	if err != nil || host == "" {
		return errors.New("FortiGate RSSO address must be RADIUS accounting host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("FortiGate RSSO port invalid")
	}
	ip, err := netip.ParseAddr(i.IP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || i.Username == "" || len(i.Username) > 253 || strings.ContainsAny(i.Username, "\x00\r\n") {
		return errors.New("FortiGate RSSO requires valid IPv4 and username")
	}
	if f.ID <= 0 {
		return errors.New("FortiGate RSSO firewall ID required")
	}
	hash := sha256.Sum256([]byte(strconv.Itoa(f.ID) + "/" + i.IP + "/" + i.Username))
	attrs := attr(1, []byte(i.Username))
	ip4 := ip.As4()
	attrs = append(attrs, attr(8, ip4[:])...)
	attrs = append(attrs, uintAttr(40, status)...)
	attrs = append(attrs, attr(44, []byte(hex.EncodeToString(hash[:])))...)
	attrs = append(attrs, attr(25, []byte(secret.Group))...)
	request := packet(4, byte(time.Now().UnixNano()), make([]byte, 16), attrs, []byte(secret.SharedSecret))
	reply, err := udp(host, port, request)
	if err != nil {
		return errors.New("FortiGate RSSO accounting transport failed")
	}
	if !validAccountingResponse(request, reply, []byte(secret.SharedSecret)) {
		return errors.New("FortiGate RSSO response authenticator invalid")
	}
	return nil
}
