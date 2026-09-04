// Package web — small JSON helpers shared by /api/auth/profiles
// and the LLM settings handlers (v4.4.22).
//
// These were previously declared in handlers_providers.go (deleted
// in v4.4.22 along with the operator-facing Providers tab). They
// live here now because they're still consumed by
// handlers_profiles.go and any new write-shaped LLM settings code.
package web

import (
	"encoding/json"
	"net/http"
)

// jsonWriteBodyLimit caps the request body size every JSON write
// handler will read. 1 MiB is generous — the largest legitimate
// payload is a profile create with embedded credentials. Capping
// protects the dashboard from a misbehaving (or malicious) client
// sending a multi-gigabyte body that would otherwise be buffered
// into memory.
const jsonWriteBodyLimit = 1 << 20 // 1 MiB

// limitJSONBody installs an http.MaxBytesReader on r.Body so any
// downstream json.Decoder fails cleanly with an error referencing
// the limit instead of buffering arbitrarily large payloads. The
// MaxBytesReader's Close method is no-op-safe so existing
// defer r.Body.Close() lines continue to work.
func limitJSONBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, jsonWriteBodyLimit)
}

// writeJSONStatus is a small helper that sets the JSON content
// type, writes the status code, and JSON-encodes body.
//
// Errors from json.Encode are intentionally not surfaced — at this
// point we have already committed the status code, and the only
// realistic failure is a closed connection which the caller already
// sees through r.Context().Err().
func writeJSONStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// handleListProviders serves GET /api/providers, returning the
// compiled-in catalog for the LLM Settings tab dropdown to
// enumerate providers. v4.4.22 dropped the runtime-editable
// catalog, so this is now strictly read-only — there is no POST,
// PUT, or DELETE counterpart.
//
// A nil catalog is treated as a startup failure and surfaced as
// HTTP 503; the dashboard renders a "catalog not initialized"
// message so the operator can see the underlying problem rather
// than an empty dropdown.
func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	if s.catalog == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "catalog not initialized",
		})
		return
	}
	entries, err := s.catalog.List(r.Context())
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, entries)
}

// writeCatalogError writes err to w as a generic catalog-lookup
// error envelope. v4.4.22 collapsed the catalog to a read-only
// compiled-in list, so the only remaining error path is "not
// found" / "ctx canceled" — both surfaced as 500 here. The shape
// matches the v4.4.21 envelope so the dashboard's error renderer
// continues to consume {"error": <message>} unchanged.
func writeCatalogError(w http.ResponseWriter, err error) {
	writeJSONStatus(w, http.StatusInternalServerError, map[string]string{
		"error": err.Error(),
	})
}
