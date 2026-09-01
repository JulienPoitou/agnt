package web

// Updated oracle snapshot of the web-side scope guard (isBlockedTarget)
// matching the smart scope guard rewrite. The smart guard only blocks:
//   - Loopback (127.0.0.0/8, ::1) — always self
//   - Unspecified (0.0.0.0, ::) — always self
//   - "localhost" — always self
//   - IPs matching local network interfaces — operator's machine
//   - Self-listener textual match (bind addr + port)
//
// It does NOT blanket-block RFC1918, link-local, or ULA ranges.
// Those are legitimate SSRF targets (e.g. 169.254.169.254 cloud
// metadata, internal IPs on the target's network).

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// oracleLookupHost is the web oracle's resolver indirection.
var oracleLookupHost = net.LookupHost

// oracleIsBlockedTarget mirrors the smart scope guard behavior.
func oracleIsBlockedTarget(s *Server, target string) bool {
	host := target
	hostPort := ""
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
		hostPort = u.Port()
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if hostPort == "" {
			hostPort = p
		}
	}

	// Self-listener textual fast-path.
	if s != nil && hostPort != "" {
		if portNum, err := strconv.Atoi(hostPort); err == nil && portNum == s.port {
			bind := strings.ToLower(strings.TrimSpace(s.cfg.BindAddr))
			if bind == "" {
				bind = "127.0.0.1"
			}
			lowerHost := strings.ToLower(strings.TrimSpace(host))
			if lowerHost == bind || lowerHost == "0.0.0.0" || lowerHost == "::" {
				return true
			}
		}
	}

	// Always-self textual fast-path.
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "[::1]" || lower == "::1" {
		return true
	}

	// Resolve IPs.
	var resolvedIPs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		resolvedIPs = []net.IP{ip}
	} else {
		addrs, err := oracleLookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		for _, a := range addrs {
			if parsed := net.ParseIP(a); parsed != nil {
				resolvedIPs = append(resolvedIPs, parsed)
			}
		}
		if len(resolvedIPs) == 0 {
			return false
		}
	}

	// Only block loopback and unspecified — NOT link-local or RFC1918.
	for _, ip := range resolvedIPs {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
	}

	// Block IPs matching local interfaces (operator's own machine).
	if oracleIPsMatchLocalInterface(resolvedIPs) {
		return true
	}

	return false
}

// oracleIPsMatchLocalInterface checks if any IP matches a local interface.
func oracleIPsMatchLocalInterface(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		for _, a := range addrs {
			var aIP net.IP
			switch v := a.(type) {
			case *net.IPNet:
				aIP = v.IP
			case *net.IPAddr:
				aIP = v.IP
			}
			if aIP == nil {
				continue
			}
			if aIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
