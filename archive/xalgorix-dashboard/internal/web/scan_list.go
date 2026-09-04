package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// parsePageParams parses the `page` and `size` query parameters into a
// 1-indexed page number and a bounded page size. Invalid or missing values
// fall back to page 1 / size 50, and size is capped at 500 to protect the
// server from absurd page sizes.
func parsePageParams(pageStr, sizeStr string) (page, size int) {
	page, size = 1, 50
	if v, err := strconv.Atoi(strings.TrimSpace(pageStr)); err == nil && v >= 1 {
		page = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(sizeStr)); err == nil && v >= 1 {
		size = v
		if size > 500 {
			size = 500
		}
	}
	return page, size
}

// handleListScans returns a list of all saved scans (sorted newest first).
// scanListItem is the lightweight per-scan row returned by GET /api/scans.
type scanListItem struct {
	ID               string `json:"id"`
	Target           string `json:"target"`
	StartedAt        string `json:"started_at"`
	Status           string `json:"status"`
	ScanMode         string `json:"scan_mode,omitempty"`
	VulnCount        int    `json:"vuln_count"`
	TotalTokens      int    `json:"total_tokens"`
	SubScanTotal     int    `json:"sub_scan_total,omitempty"`
	SubScanCompleted int    `json:"sub_scan_completed,omitempty"`
	SubScanRunning   int    `json:"sub_scan_running,omitempty"`
	SubScanRemaining int    `json:"sub_scan_remaining,omitempty"`
}

// scanListCacheTTL bounds how long a built scan list is reused. Building the
// list walks the entire data dir and JSON-parses every scan.json, so without
// this cache each page/filter/poll request repeated that full-disk scan. The
// list view tolerates a few seconds of status lag (the instances page and the
// WebSocket feed are the live surfaces); deletes invalidate the cache for
// immediate effect.
const scanListCacheTTL = 5 * time.Second

// cachedScanList returns the sorted (newest-first) scan list, rebuilding it
// from disk at most once per scanListCacheTTL. The returned slice is shared
// read-only across callers — never mutate its elements; filtering/paginating
// must build new slices.
func (s *Server) cachedScanList() []scanListItem {
	s.scanListCacheMu.Lock()
	defer s.scanListCacheMu.Unlock()
	if s.scanListCache != nil && time.Since(s.scanListCacheAt) < scanListCacheTTL {
		return s.scanListCache
	}
	var scans []scanListItem
	// Walk the data dir ONCE (events-free + per-file cached) and reuse the
	// entry slice for child resolution. Previously each top-level scan
	// triggered its own findAllScans() walk via attachWildcardSubScans, making
	// list rebuilds O(parents × allScans) in full disk reads + JSON parses
	// (events included). Sharing one events-free walk makes it linear and skips
	// the per-event decode entirely.
	entries := s.findAllScanSummaries()
	for _, entry := range entries {
		if entry.rec.ParentTarget != "" {
			continue
		}
		rec := entry.rec
		// rec is a shallow copy of a cached, shared record. Detach the slices
		// that the snapshot/sub-scan logic appends to so we never mutate the
		// backing array held by scanSummaryCache (which other readers, e.g. the
		// findings handlers, access concurrently).
		rec.Vulns = append([]VulnSummary(nil), rec.Vulns...)
		s.applyInstanceSnapshot(&rec, false)
		// Only wildcard parents derive sub-scan progress from their own event
		// stream, so restore just that one record's events (cheap: one file)
		// rather than carrying events for every scan in the list.
		if strings.EqualFold(rec.ScanMode, "wildcard") {
			if full, ok := loadScanRecordFromDir(entry.dir); ok && full != nil {
				rec.Events = full.Events
			}
		}
		s.attachWildcardSubScansFrom(&rec, entries)
		scans = append(scans, scanListItem{
			ID:               rec.ID,
			Target:           rec.Target,
			StartedAt:        rec.StartedAt,
			Status:           rec.Status,
			ScanMode:         rec.ScanMode,
			VulnCount:        len(rec.Vulns),
			TotalTokens:      rec.TotalTokens,
			SubScanTotal:     rec.SubScanTotal,
			SubScanCompleted: rec.SubScanCompleted,
			SubScanRunning:   rec.SubScanRunning,
			SubScanRemaining: rec.SubScanRemaining,
		})
	}
	// Sort newest first.
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt > scans[j].StartedAt
	})
	s.scanListCache = scans
	s.scanListCacheAt = time.Now()
	return scans
}

// invalidateScanListCache forces the next GET /api/scans to rebuild from disk.
// Called after mutations (e.g. scan deletion) so the change is reflected
// immediately rather than after the TTL.
func (s *Server) invalidateScanListCache() {
	s.scanListCacheMu.Lock()
	s.scanListCache = nil
	s.scanListCacheMu.Unlock()
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans := s.cachedScanList()

	// Optional server-side filtering. These are no-ops when the query params
	// are absent, so the default GET /api/scans response is unchanged. Build
	// new slices so the shared cache is never mutated.
	if q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q"))); q != "" {
		filtered := make([]scanListItem, 0, len(scans))
		for _, sc := range scans {
			if strings.Contains(strings.ToLower(sc.Target), q) ||
				strings.Contains(strings.ToLower(sc.ID), q) {
				filtered = append(filtered, sc)
			}
		}
		scans = filtered
	}
	if st := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status"))); st != "" && st != "all" {
		filtered := make([]scanListItem, 0, len(scans))
		for _, sc := range scans {
			if strings.ToLower(sc.Status) == st {
				filtered = append(filtered, sc)
			}
		}
		scans = filtered
	}

	w.Header().Set("Content-Type", "application/json")

	// Pagination is opt-in. Without a page/size query param we preserve the
	// historical bare-array response for backward compatibility (public API
	// consumers and existing callers). With it, we return a paginated
	// envelope { items, total, page, size }.
	pageStr := r.URL.Query().Get("page")
	sizeStr := r.URL.Query().Get("size")
	if pageStr == "" && sizeStr == "" {
		_ = json.NewEncoder(w).Encode(scans)
		return
	}
	page, size := parsePageParams(pageStr, sizeStr)
	total := len(scans)
	start := (page - 1) * size
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	items := scans[start:end]
	if items == nil {
		items = []scanListItem{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items": items,
		"total": total,
		"page":  page,
		"size":  size,
	})
}

// handleDownloadReport serves the PDF report for a scan.
