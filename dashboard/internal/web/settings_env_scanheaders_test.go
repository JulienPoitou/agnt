package web

import (
	"strings"
	"testing"
)

// TestScanHeaderEnvSettingsExposed verifies the WebUI settings surface exposes
// the scan/attribution headers introduced in PR #289 (XALGORIX_SCAN_HEADERS and
// XALGORIX_SCAN_HEADERS_FILE) so an operator can configure them from the
// dashboard, not only via the CLI -H flag or the raw environment. A key absent
// from the definition map is rejected by applyEnvironmentUpdates, so this also
// guards the POST accept-list.
func TestScanHeaderEnvSettingsExposed(t *testing.T) {
	defs := envDefinitionByKey()
	for _, key := range []string{"XALGORIX_SCAN_HEADERS", "XALGORIX_SCAN_HEADERS_FILE"} {
		def, ok := defs[key]
		if !ok {
			t.Fatalf("%s missing from env setting definitions; the WebUI would 400 when saving it", key)
		}
		if def.Category != "Runtime" {
			t.Errorf("%s category = %q, want Runtime (grouped with Target auth)", key, def.Category)
		}
		if !def.RequiresRestart {
			t.Errorf("%s must require restart: config.load() reads it only at startup", key)
		}
		// Attribution headers are a visible identifier (e.g. X-Bug-Bounty),
		// never a credential, so they must not be masked in the UI.
		if def.Sensitive {
			t.Errorf("%s should not be Sensitive; it is a visible attribution identifier", key)
		}
	}
}

// TestScanHeadersValueSurvivesNormalization guards the WebUI POST path: a
// ';'-separated, colon-containing header value must pass through
// normalizeEnvSettingValue unchanged and newline-free so it round-trips to the
// environment exactly as config.loadScanHeaders() expects to parse it.
func TestScanHeadersValueSurvivesNormalization(t *testing.T) {
	def := envDefinitionByKey()["XALGORIX_SCAN_HEADERS"]
	in := "X-Bug-Bounty: ulises2k; Authorization: Bearer a:b:c"
	got, err := normalizeEnvSettingValue(def, in)
	if err != nil {
		t.Fatalf("normalizeEnvSettingValue(%q) error: %v", in, err)
	}
	if got != in {
		t.Fatalf("normalized = %q, want unchanged %q", got, in)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("normalized value contains a newline; applyEnvironmentUpdates would reject it")
	}
}
