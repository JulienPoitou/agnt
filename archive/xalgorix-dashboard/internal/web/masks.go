// Package web — credential masking helpers for the provider catalog
// and OAuth profile HTTP surface.
//
// This file is the single home for the redaction policy applied to
// any credential field returned to the dashboard. Centralizing the
// helper here lets handlers_providers.go and (in Wave E task 5.2)
// handlers_profiles.go share the exact same masking semantics, and
// it lets the test suite assert one canonical algorithm rather than
// duplicate string-shape checks per handler.
//
// The shape mirrors maskAgentMailKey in server.go (~6303–6311) so
// operators see consistent redaction across the dashboard:
//
//   - empty input          → "" (so the UI can render
//     `hasApiKey === false` without juggling a
//     "****" placeholder)
//   - short input (≤8 chr) → "****"
//   - long input  (>8 chr) → "****" + last 8 characters
//
// The "last 8" tail is wide enough for an operator to recognize
// which key they pasted while still hiding the entropy a leak would
// need to be exploitable. Validates: Requirements 5.1, 5.2, 5.4.
package web

import (
	"github.com/xalgord/xalgorix/v4/internal/auth"
)

// maskAuthCredential redacts a credential string for outbound JSON
// responses. The contract intentionally matches maskAgentMailKey so
// the existing webui mask-detection logic (isMaskedAgentMailKey)
// keeps working unchanged for the new /api/auth/profiles surface.
//
// Validates: Requirements 5.1, 5.2, 5.4.
func maskAuthCredential(v string) string {
	if len(v) > 8 {
		return "****" + v[len(v)-8:]
	}
	if v != "" {
		return "****"
	}
	return ""
}

// maskProfile returns a copy of p with the three credential-bearing
// fields (apiKey, accessToken, refreshToken) replaced by their
// maskAuthCredential output. Every other field — provider,
// profileId, type, expiresAt, scopes, tokenType, requiresReauth,
// apiBaseOverride, updatedAt — is copied through untouched.
//
// Centralizing the redaction in one helper keeps the mask policy
// consistent across every handler in handlers_profiles.go (Wave E
// task 5.2) and gives the test suite a single function to assert
// against. The Profile value type means callers receive a defensive
// copy and cannot accidentally mutate the original through the
// returned value.
//
// Validates: Requirements 5.1, 5.2, 5.4.
func maskProfile(p auth.Profile) auth.Profile {
	out := p
	out.APIKey = maskAuthCredential(p.APIKey)
	out.AccessToken = maskAuthCredential(p.AccessToken)
	out.RefreshToken = maskAuthCredential(p.RefreshToken)
	return out
}
