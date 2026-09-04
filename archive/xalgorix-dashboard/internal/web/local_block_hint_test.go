package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestHandleScan_LocalTargetBlockedHint verifies that an all-local scan request
// is rejected with a helpful message: when local scanning is off, it tells a
// self-hosted operator exactly how to enable it (#228 follow-up); when it's
// already on, it explains the dashboard/unspecified addresses are never
// scannable.
func TestHandleScan_LocalTargetBlockedHint(t *testing.T) {
	post := func(s *Server, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
		s.handleScan(rr, req)
		return rr
	}

	t.Run("off → how-to-enable hint", func(t *testing.T) {
		s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
		rr := post(s, `{"targets":["http://127.0.0.1:3000/"],"scan_mode":"single"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "XALGORIX_ALLOW_LOCAL_TARGETS") {
			t.Fatalf("expected the enable hint, got: %s", body)
		}
	})

	t.Run("on → still blocks dashboard/unspecified with explanation", func(t *testing.T) {
		s := newTestServer(t, &config.Config{
			RateLimitRequests: 60,
			RateLimitWindow:   60,
			AllowLocalTargets: true,
		})
		// Unspecified is always blocked, even with local targets enabled.
		rr := post(s, `{"targets":["http://0.0.0.0/"],"scan_mode":"single"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, "XALGORIX_ALLOW_LOCAL_TARGETS") {
			t.Fatalf("should not suggest enabling when it's already on: %s", body)
		}
		if !strings.Contains(body, "even with local targets enabled") {
			t.Fatalf("expected the already-enabled explanation, got: %s", body)
		}
	})
}
