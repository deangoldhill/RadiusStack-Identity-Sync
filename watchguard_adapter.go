package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// watchguardSessionID is stable across process restarts and full refreshes,
// and is unrelated to the web administrator's RADIUS accounting session ID.
// A username change on one client IP denotes a different mapping/session.
func watchguardSessionID(firewallID int, i Identity) string {
	h := sha256.New()
	fmt.Fprintf(h, "identity-sync/watchguard/v1:%d:%d:%s:%d:%s", firewallID, len(i.IP), i.IP, len(i.Username), i.Username)
	return hex.EncodeToString(h.Sum(nil))
}

// watchguardUpdate delivers RSSO Accounting-Start (add), Stop (delete), or
// Interim-Update (refresh) directly to a Firebox configured to accept RADIUS
// accounting from this service's source IP with the configured shared secret.
// See https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/authentication/rsso_about.html
// A valid Accounting-Response acknowledges packet receipt, not proof that a
// mapping exists on the Firebox; RSSO has no documented read-only identity API.
func (a *App) watchguardUpdate(f Firewall, action string, i Identity) error {
	var status uint32
	switch action {
	case "add":
		status = 1 // RFC 2866 Acct-Status-Type: Start
	case "delete":
		status = 2 // Stop
	case "refresh":
		status = 3 // Interim-Update
	default:
		return errors.New("WatchGuard action must be add, delete, or refresh")
	}
	if f.ID <= 0 || f.Secret == "" {
		return errors.New("WatchGuard firewall ID and RADIUS shared secret are required")
	}
	// Require an explicit accounting port; do not confuse the Fireware web
	// management address/port with its RADIUS accounting listener.
	host, portText, err := net.SplitHostPort(f.Address)
	if err != nil || host == "" {
		return errors.New("WatchGuard address must be a RADIUS accounting host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("WatchGuard RADIUS accounting port is invalid")
	}
	ip, err := netip.ParseAddr(i.IP)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() {
		return errors.New("WatchGuard RSSO requires a valid client IPv4 address")
	}
	if strings.TrimSpace(i.Username) == "" || len(i.Username) > 253 || strings.ContainsAny(i.Username, "\x00\r\n") {
		return errors.New("WatchGuard RSSO requires a nonempty User-Name of at most 253 bytes without NUL/CR/LF")
	}
	// RFC 2866 attributes: User-Name (1), Framed-IP-Address (8),
	// Acct-Status-Type (40), and Acct-Session-Id (44).
	attrs := attr(1, []byte(i.Username))
	ip4 := ip.As4()
	attrs = append(attrs, attr(8, ip4[:])...)
	attrs = append(attrs, uintAttr(40, status)...)
	attrs = append(attrs, attr(44, []byte(watchguardSessionID(f.ID, i)))...)
	// packet computes the Accounting-Request authenticator using a zeroed
	// authenticator and the shared secret (RFC 2866 section 3).
	id := byte(time.Now().UnixNano())
	request := packet(4, id, make([]byte, 16), attrs, []byte(f.Secret))
	response, err := udp(host, port, request)
	if err != nil {
		return errors.New("WatchGuard RADIUS accounting transport failed") // no secret in errors
	}
	if !validAccountingResponse(request, response, []byte(f.Secret)) {
		return errors.New("WatchGuard RADIUS accounting response failed authentication")
	}
	return nil
}
