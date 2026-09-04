package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProviderKeyRoutesRegistered locks in the lockstep invariant for
// the two provider-key wiring routes: both patterns must appear in
// dashboardRoutes so they pass through the same auth + rate-limit
// middleware as the rest of the /api/* surface.
//
// Validates: Requirements 2.9, 9.4
func TestRouterWiringRoutesRegistered(t *testing.T) {
	want := []string{
		"/api/settings/llm/keys",
		"/api/settings/llm/test-route",
	}
	for _, pattern := range want {
		found := false
		for _, route := range dashboardRoutes {
			if route == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("dashboardRoutes missing %q", pattern)
		}
	}
}

// TestProviderKeyHandlersNilDependency confirms the wiring preserves
// the handlers' nil-guard contract: with no key store / router on the
// Server (construction failed at startup), the handlers surface HTTP
// 503 rather than panicking.
//
// Validates: Requirements 1.7, 1.8
func TestRouterWiringHandlersNilDependency(t *testing.T) {
	t.Run("handleProviderKeys 503 when key store nil", func(t *testing.T) {
		s := &Server{} // llmKeyStore == nil
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/settings/llm/keys", nil)

		s.handleProviderKeys(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
		}
	})

	t.Run("handleProviderKeys 503 when key store nil (POST)", func(t *testing.T) {
		s := &Server{} // llmKeyStore == nil
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/llm/keys", strings.NewReader(`{"keys":[]}`))

		s.handleProviderKeys(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
		}
	})

	t.Run("handleProviderKeys 503 when key store nil (DELETE)", func(t *testing.T) {
		s := &Server{} // llmKeyStore == nil
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/settings/llm/keys", strings.NewReader(`{"provider_id":"openai"}`))

		s.handleProviderKeys(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
		}
	})

	t.Run("handleTestRoute 503 when router nil", func(t *testing.T) {
		s := &Server{} // llmRouter == nil
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/llm/test-route", strings.NewReader(`{"model":"gpt-4o"}`))

		s.handleTestRoute(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
		}
	})
}

// TestRouterWiringConstruction confirms that NewServer, given a valid
// temp DataDir, builds both the key store and the router. The router
// is only constructed on the key-store success branch, so a non-nil
// router also proves the key store is live.
//
// Validates: Requirements 1.3, 1.4
func TestRouterWiringConstruction(t *testing.T) {
	srv := newTestServer(t, nil)

	if srv.llmKeyStore == nil {
		t.Error("srv.llmKeyStore == nil, want non-nil after NewServer with valid DataDir")
	}
	if srv.llmRouter == nil {
		t.Error("srv.llmRouter == nil, want non-nil after NewServer with valid DataDir")
	}
}

// TestRouterWiringRouteListInvariants asserts the two provider-key
// patterns appear in dashboardRoutes exactly once each, and that no
// pre-existing route entry was removed when the wiring entries were
// added.
//
// Validates: Requirements 2.9, 9.4
func TestRouterWiringRouteListInvariants(t *testing.T) {
	counts := make(map[string]int, len(dashboardRoutes))
	for _, route := range dashboardRoutes {
		counts[route]++
	}

	// Each new entry appears exactly once.
	for _, pattern := range []string{
		"/api/settings/llm/keys",
		"/api/settings/llm/test-route",
	} {
		if counts[pattern] != 1 {
			t.Errorf("dashboardRoutes contains %q %d time(s), want exactly 1", pattern, counts[pattern])
		}
	}

	// No pre-existing entry was removed. This is a representative
	// baseline of routes that existed before the wiring change,
	// spanning static roots, the scan/report surface, the existing
	// single-provider /api/settings/llm endpoint, and the provider /
	// auth-profile namespace.
	preExisting := []string{
		"/",
		"/ws",
		"/api/scan",
		"/api/stop",
		"/api/status",
		"/api/scans",
		"/api/schedules",
		"/api/report/",
		"/api/settings/rate-limit",
		"/api/settings/llm",
		"/api/settings/environment",
		"/api/version",
		"/api/chat",
		"/api/auth/login",
		"/api/auth/logout",
		"/api/auth/status",
		"/api/providers",
		"/api/auth/profiles",
	}
	for _, pattern := range preExisting {
		if counts[pattern] < 1 {
			t.Errorf("dashboardRoutes missing pre-existing entry %q (was it removed?)", pattern)
		}
	}
}

// TestRouterWiringMethodGuards confirms the handlers enforce their
// method contracts: /keys rejects methods other than GET/POST/DELETE
// with 405, and /test-route rejects non-POST with 405. These run
// against a fully constructed Server so the method guard (not the
// nil-dependency guard) is what produces the 405.
//
// Validates: Requirements 2.5, 2.6
func TestRouterWiringMethodGuards(t *testing.T) {
	srv := newTestServer(t, nil)

	t.Run("PUT /keys → 405", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/settings/llm/keys", nil)
		srv.handleProviderKeys(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
		}
	})

	t.Run("PATCH /keys → 405", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/api/settings/llm/keys", nil)
		srv.handleProviderKeys(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
		}
	})

	t.Run("GET /test-route → 405", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/settings/llm/test-route", nil)
		srv.handleTestRoute(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
		}
	})
}

// TestRouterWiringHappyPath exercises the success contracts the wired
// handlers preserve: the GET /keys envelope shape, the masked-key
// POST short-circuit (saved: 0), and resolvable / unresolvable
// test-route resolution (both 200, differing only by the resolved
// flag and without any outbound provider request).
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10
func TestRouterWiringHappyPath(t *testing.T) {
	srv := newTestServer(t, nil)

	t.Run("GET /keys → 200 with envelope fields", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/settings/llm/keys", nil)
		srv.handleProviderKeys(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v; body=%s", err, rr.Body.String())
		}
		for _, field := range []string{"providers", "configured_count", "router_enabled", "known_model_patterns"} {
			if _, ok := body[field]; !ok {
				t.Errorf("GET /keys response missing field %q; body=%s", field, rr.Body.String())
			}
		}
	})

	t.Run("POST masked key → 200 saved:0", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/llm/keys",
			strings.NewReader(`{"keys":[{"provider_id":"openai","api_key":"****1234"}]}`))
		srv.handleProviderKeys(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body struct {
			Saved int `json:"saved"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v; body=%s", err, rr.Body.String())
		}
		if body.Saved != 0 {
			t.Errorf("saved = %d, want 0 (masked key should be skipped)", body.Saved)
		}
	})

	t.Run("POST /test-route resolvable model → 200 resolved:true", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/llm/test-route",
			strings.NewReader(`{"model":"gpt-4o"}`))
		srv.handleTestRoute(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body struct {
			Resolved bool `json:"resolved"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v; body=%s", err, rr.Body.String())
		}
		if !body.Resolved {
			t.Errorf("resolved = false, want true for model %q; body=%s", "gpt-4o", rr.Body.String())
		}
	})

	t.Run("POST /test-route unresolvable model → 200 resolved:false", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/llm/test-route",
			strings.NewReader(`{"model":"zzz-unknown-model-9000"}`))
		srv.handleTestRoute(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body struct {
			Resolved bool `json:"resolved"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v; body=%s", err, rr.Body.String())
		}
		if body.Resolved {
			t.Errorf("resolved = true, want false for unknown model; body=%s", rr.Body.String())
		}
	})

	t.Run("POST /test-route empty model → 400", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings/llm/test-route",
			strings.NewReader(`{"model":"   "}`))
		srv.handleTestRoute(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
		}
	})

	t.Run("DELETE /keys empty provider_id → 400", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/settings/llm/keys",
			strings.NewReader(`{"provider_id":"  "}`))
		srv.handleProviderKeys(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want %d; body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
		}
	})
}
