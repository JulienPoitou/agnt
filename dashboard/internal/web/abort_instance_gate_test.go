package web

import "testing"

// Only a top-level single/DAST session may fail the whole instance on an
// LLM-abort. Wildcard discovery + subdomain sub-sessions share the parent
// instance ID, so failing the instance from them marks a still-running scan
// as failed (issue: "scan is running but marked as failed" on att.com, where
// Phase 1 discovery aborted after finding 3026 subdomains and Phase 2 kept
// scanning).
func TestShouldFailInstanceOnAbort(t *testing.T) {
	cases := []struct {
		name         string
		scanMode     string
		parentTarget string
		discovery    bool
		want         bool
	}{
		{name: "single scan", scanMode: "single", want: true},
		{name: "dast scan", scanMode: "dast", want: true},
		{name: "empty mode top-level", scanMode: "", want: true},
		{name: "wildcard discovery session", scanMode: "wildcard", discovery: true, want: false},
		{name: "wildcard subdomain session", scanMode: "wildcard", parentTarget: "att.com", want: false},
		{name: "wildcard mixed case", scanMode: "Wildcard", want: false},
		{name: "subdomain session without explicit mode", scanMode: "", parentTarget: "att.com", want: false},
		{name: "discovery flag without wildcard mode", scanMode: "", discovery: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFailInstanceOnAbort(tc.scanMode, tc.parentTarget, tc.discovery); got != tc.want {
				t.Errorf("shouldFailInstanceOnAbort(%q,%q,%v) = %v, want %v",
					tc.scanMode, tc.parentTarget, tc.discovery, got, tc.want)
			}
		})
	}
}
