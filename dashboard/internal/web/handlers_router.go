package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// handleProviderKeys handles multi-provider API key management.
//
//	GET  /api/settings/llm/keys       → list configured providers + key status
//	POST /api/settings/llm/keys       → save one or more provider keys
//	DELETE /api/settings/llm/keys     → remove a provider key
func (s *Server) handleProviderKeys(w http.ResponseWriter, r *http.Request) {
	if s.llmKeyStore == nil {
		http.Error(w, "provider key store not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetProviderKeys(w, r)
	case http.MethodPost:
		s.handleSaveProviderKeys(w, r)
	case http.MethodDelete:
		s.handleDeleteProviderKey(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// providerKeyStatus represents a provider's key configuration status
// for the settings UI.
type providerKeyStatus struct {
	ProviderID  string `json:"provider_id"`
	DisplayName string `json:"display_name"`
	HasKey      bool   `json:"has_key"`
	MaskedKey   string `json:"masked_key,omitempty"`
	BaseURL     string `json:"base_url"`
	HeaderStyle string `json:"header_style"`
}

func (s *Server) handleGetProviderKeys(w http.ResponseWriter, _ *http.Request) {
	// Build status for all providers in the catalog
	catalog := providers.Builtin()
	configured := s.llmKeyStore.List()

	// Index configured keys by provider ID
	configuredMap := make(map[string]llm.ProviderKey)
	for _, k := range configured {
		configuredMap[k.ProviderID] = k
	}

	result := make([]providerKeyStatus, 0, len(catalog))
	for _, entry := range catalog {
		if entry.ID == "custom" || entry.BaseURL == "" {
			continue // skip providers without a known base URL
		}

		status := providerKeyStatus{
			ProviderID:  entry.ID,
			DisplayName: entry.DisplayName,
			BaseURL:     entry.BaseURL,
			HeaderStyle: entry.HeaderStyle,
		}

		if pk, ok := configuredMap[entry.ID]; ok {
			status.HasKey = true
			status.MaskedKey = pk.APIKey // already masked by List()
		}

		result = append(result, status)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"providers":            result,
		"configured_count":     len(configured),
		"router_enabled":       s.llmRouter != nil && s.llmRouter.CanRoute(),
		"known_model_patterns": llm.KnownProviderIDs(),
	})
}

// saveProviderKeysRequest is the POST body for saving keys.
type saveProviderKeysRequest struct {
	Keys []saveKeyEntry `json:"keys"`
}

type saveKeyEntry struct {
	ProviderID  string `json:"provider_id"`
	APIKey      string `json:"api_key"`
	BaseURL     string `json:"base_url,omitempty"`
	HeaderStyle string `json:"header_style,omitempty"`
}

func (s *Server) handleSaveProviderKeys(w http.ResponseWriter, r *http.Request) {
	var req saveProviderKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Keys) == 0 {
		http.Error(w, "no keys provided", http.StatusBadRequest)
		return
	}

	// Validate and convert
	keys := make([]llm.ProviderKey, 0, len(req.Keys))
	for _, k := range req.Keys {
		pid := strings.TrimSpace(k.ProviderID)
		apiKey := strings.TrimSpace(k.APIKey)

		if pid == "" {
			http.Error(w, "provider_id is required", http.StatusBadRequest)
			return
		}

		// If the key looks masked (starts with ****), skip it —
		// the user didn't change it
		if strings.HasPrefix(apiKey, "****") {
			continue
		}

		// Look up header style from catalog if not provided
		headerStyle := k.HeaderStyle
		baseURL := k.BaseURL
		if headerStyle == "" || baseURL == "" {
			for _, entry := range providers.Builtin() {
				if entry.ID == pid {
					if headerStyle == "" {
						headerStyle = entry.HeaderStyle
					}
					if baseURL == "" {
						baseURL = entry.BaseURL
					}
					break
				}
			}
		}

		keys = append(keys, llm.ProviderKey{
			ProviderID:  pid,
			APIKey:      apiKey,
			HeaderStyle: headerStyle,
			BaseURL:     baseURL,
		})
	}

	if len(keys) == 0 {
		// All keys were masked (unchanged) — just return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"saved":   0,
			"message": "no keys changed",
		})
		return
	}

	if err := s.llmKeyStore.SetMultiple(r.Context(), keys); err != nil {
		log.Printf("Failed to save provider keys: %v", err)
		http.Error(w, "failed to save keys", http.StatusInternalServerError)
		return
	}

	log.Printf("Saved %d provider key(s): %v", len(keys), providerIDsFromKeys(keys))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"saved":   len(keys),
		"message": "provider keys saved successfully",
	})
}

func (s *Server) handleDeleteProviderKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID string `json:"provider_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	pid := strings.TrimSpace(req.ProviderID)
	if pid == "" {
		http.Error(w, "provider_id is required", http.StatusBadRequest)
		return
	}

	if err := s.llmKeyStore.Delete(r.Context(), pid); err != nil {
		log.Printf("Failed to delete provider key for %s: %v", pid, err)
		http.Error(w, "failed to delete key", http.StatusInternalServerError)
		return
	}

	log.Printf("Deleted provider key for: %s", pid)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "key deleted",
	})
}

// handleTestRoute tests model→provider resolution without making
// an actual LLM request. Returns the routing details.
//
//	POST /api/settings/llm/test-route  body: {"model": "gpt-4o"}
func (s *Server) handleTestRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Model string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	model := strings.TrimSpace(req.Model)
	if model == "" {
		http.Error(w, "model is required", http.StatusBadRequest)
		return
	}

	if s.llmRouter == nil {
		http.Error(w, "model router not initialized", http.StatusServiceUnavailable)
		return
	}

	result, err := s.llmRouter.TestRoute(model)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // not an HTTP error, just routing info
		json.NewEncoder(w).Encode(map[string]any{
			"resolved": false,
			"error":    err.Error(),
			"model":    model,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"resolved":     true,
		"provider_id":  result.ProviderID,
		"display_name": result.DisplayName,
		"bare_model":   result.BareModel,
		"base_url":     result.BaseURL,
		"header_style": result.HeaderStyle,
		"has_key":      result.HasKey,
		"model":        model,
	})
}

func providerIDsFromKeys(keys []llm.ProviderKey) []string {
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ProviderID
	}
	return ids
}
