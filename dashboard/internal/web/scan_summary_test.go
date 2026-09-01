package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestScanRecordLiteSkipsEventsKeepsRest verifies the json.RawMessage shadow
// field intercepts the "events" key (so it is not decoded into []WSEvent)
// while every other ScanRecord field still parses normally.
func TestScanRecordLiteSkipsEventsKeepsRest(t *testing.T) {
	raw := []byte(`{
		"id": "scan-123",
		"instance_id": "inst-9",
		"target": "example.com",
		"started_at": "2026-06-01T10:00:00Z",
		"status": "finished",
		"scan_mode": "single",
		"total_tokens": 4242,
		"iterations": 7,
		"tool_calls": 13,
		"sub_scan_total": 3,
		"sub_scan_completed": 2,
		"vulns": [
			{"id": "v1", "title": "SQLi", "severity": "critical", "endpoint": "/login"},
			{"id": "v2", "title": "XSS", "severity": "medium", "endpoint": "/search"}
		],
		"events": [
			{"type": "tool_call", "tool_name": "nuclei", "output": "lots of data"},
			{"type": "agent_message", "content": "thinking..."}
		]
	}`)

	var lite scanRecordLite
	if err := json.Unmarshal(raw, &lite); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec := lite.ScanRecord

	if len(rec.Events) != 0 {
		t.Fatalf("expected events to be skipped, got %d events", len(rec.Events))
	}
	if rec.ID != "scan-123" {
		t.Errorf("id = %q, want scan-123", rec.ID)
	}
	if rec.InstanceID != "inst-9" {
		t.Errorf("instance_id = %q, want inst-9", rec.InstanceID)
	}
	if rec.Target != "example.com" {
		t.Errorf("target = %q, want example.com", rec.Target)
	}
	if rec.Status != "finished" {
		t.Errorf("status = %q, want finished", rec.Status)
	}
	if rec.TotalTokens != 4242 {
		t.Errorf("total_tokens = %d, want 4242", rec.TotalTokens)
	}
	if rec.Iterations != 7 || rec.ToolCalls != 13 {
		t.Errorf("iterations/tool_calls = %d/%d, want 7/13", rec.Iterations, rec.ToolCalls)
	}
	if rec.SubScanTotal != 3 || rec.SubScanCompleted != 2 {
		t.Errorf("sub_scan_total/completed = %d/%d, want 3/2", rec.SubScanTotal, rec.SubScanCompleted)
	}
	if len(rec.Vulns) != 2 {
		t.Fatalf("vulns = %d, want 2", len(rec.Vulns))
	}
	if rec.Vulns[0].Title != "SQLi" || rec.Vulns[1].Severity != "medium" {
		t.Errorf("vulns parsed incorrectly: %+v", rec.Vulns)
	}
}

// TestFindAllScanSummariesCachesByModtime verifies the per-file cache reuses a
// parsed record until the underlying file changes.
func TestFindAllScanSummariesCachesByModtime(t *testing.T) {
	s := newTestServer(t, nil)

	dir := filepath.Join(s.dataDir, "example.com", "2026-06-01", "scan-abc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "scan.json")
	writeScan := func(target string) {
		body := `{"id":"scan-abc","target":"` + target + `","status":"finished","vulns":[]}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeScan("example.com")
	first := s.findAllScanSummaries()
	if len(first) != 1 || first[0].rec.Target != "example.com" {
		t.Fatalf("first walk = %+v", first)
	}

	// Cache entry exists keyed by path.
	s.scanSummaryCacheMu.Lock()
	_, cached := s.scanSummaryCache[path]
	s.scanSummaryCacheMu.Unlock()
	if !cached {
		t.Fatal("expected a cache entry after first walk")
	}

	// Delete the file: next walk must drop it from results and prune cache.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second := s.findAllScanSummaries()
	if len(second) != 0 {
		t.Fatalf("after delete walk = %d entries, want 0", len(second))
	}
	s.scanSummaryCacheMu.Lock()
	_, stillCached := s.scanSummaryCache[path]
	s.scanSummaryCacheMu.Unlock()
	if stillCached {
		t.Fatal("expected cache entry pruned after file removal")
	}
}
