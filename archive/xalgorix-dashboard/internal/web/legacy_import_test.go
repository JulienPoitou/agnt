package web

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestImportLegacyDataDir_Idempotent validates Property 6: running
// importLegacyDataDir twice produces the same destination state as
// running it once. The second call must return 0 and must NOT
// re-walk or re-copy.
func TestImportLegacyDataDir_Idempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Set up a server with a fresh active dataDir distinct from legacy.
	s := newTestServer(t, nil)
	s.dataDir = t.TempDir()

	// Seed the legacy directory with one scan record at a realistic
	// nested path: ~/xalgorix-data/<target>/<date>/<scan-id>/scan.json
	legacy := filepath.Join(home, "xalgorix-data", "example.com", "2026-05-01", "legacy-scan-1")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	rec := ScanRecord{
		ID:        "legacy-scan-1",
		Target:    "https://example.com",
		StartedAt: time.Now().Format(time.RFC3339),
		Status:    "finished",
		Vulns:     []VulnSummary{{ID: "v1", Severity: "high"}},
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "scan.json"), data, 0o644); err != nil {
		t.Fatalf("write legacy scan.json: %v", err)
	}

	// First run: should import the legacy record.
	count, err := s.importLegacyDataDir()
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if count != 1 {
		t.Fatalf("first run imported %d, want 1", count)
	}

	// Sentinel file should now exist.
	if _, err := os.Stat(filepath.Join(s.dataDir, ".legacy-imported")); err != nil {
		t.Fatalf("sentinel missing after first run: %v", err)
	}

	// Snapshot the dataDir tree for equality check after the second run.
	before := snapshotTree(t, s.dataDir)

	// Second run: should be a no-op (sentinel gates further work).
	count2, err := s.importLegacyDataDir()
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if count2 != 0 {
		t.Fatalf("second run imported %d, want 0 (idempotence)", count2)
	}

	after := snapshotTree(t, s.dataDir)
	if !equalSnapshots(before, after) {
		t.Fatalf("dataDir contents changed between runs:\nbefore=%v\nafter=%v", before, after)
	}
}

// TestImportLegacyDataDir_NoLegacyDir validates that when the legacy
// directory does not exist, the function writes the sentinel and
// returns (0, nil) without error. Subsequent calls must also return 0.
func TestImportLegacyDataDir_NoLegacyDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	s := newTestServer(t, nil)
	s.dataDir = t.TempDir()

	count, err := s.importLegacyDataDir()
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if count != 0 {
		t.Fatalf("import without legacy dir returned %d, want 0", count)
	}
	if _, err := os.Stat(filepath.Join(s.dataDir, ".legacy-imported")); err != nil {
		t.Fatalf("sentinel missing: %v", err)
	}

	// Second run is a no-op.
	count2, err := s.importLegacyDataDir()
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if count2 != 0 {
		t.Fatalf("second run returned %d, want 0", count2)
	}
}

// TestImportLegacyDataDir_LegacyEqualsActive validates the early
// return path when cfg.DataDir IS the legacy directory. No sentinel
// is written and no work is done.
func TestImportLegacyDataDir_LegacyEqualsActive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	s := newTestServer(t, nil)
	legacy := filepath.Join(home, "xalgorix-data")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	s.dataDir = legacy

	count, err := s.importLegacyDataDir()
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if count != 0 {
		t.Fatalf("legacy==active should not import anything, got %d", count)
	}
	// Sentinel should NOT be written when dirs are the same — we
	// would be polluting the legacy dir.
	if _, err := os.Stat(filepath.Join(legacy, ".legacy-imported")); err == nil {
		t.Fatalf("sentinel should not be written when legacy is active dir")
	}
}

// TestCopyDirRecursive validates that copyDirRecursive duplicates the
// source tree (files + nested dirs) into the destination, preserving
// content. It is the inner primitive used by importLegacyDataDir.
func TestCopyDirRecursive(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")

	// src/a/b/c.txt with content "hello"
	nested := filepath.Join(src, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "c.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := copyDirRecursive(src, dst); err != nil {
		t.Fatalf("copyDirRecursive: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dst, "a", "b", "c.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("copied content = %q, want %q", got, "hello")
	}
}

type fileSnap struct {
	rel  string
	size int64
}

func snapshotTree(t *testing.T, root string) []fileSnap {
	t.Helper()
	var out []fileSnap
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out = append(out, fileSnap{rel: rel, size: info.Size()})
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return out
}

func equalSnapshots(a, b []fileSnap) bool {
	if len(a) != len(b) {
		return false
	}
	idx := map[string]int64{}
	for _, f := range a {
		idx[f.rel] = f.size
	}
	for _, f := range b {
		size, ok := idx[f.rel]
		if !ok || size != f.size {
			return false
		}
	}
	return true
}

// TestHandleLegacyImportStatus_GetReportsCount verifies the GET path
// returns the in-memory count cached on the Server struct.
func TestHandleLegacyImportStatus_GetReportsCount(t *testing.T) {
	s := newTestServer(t, nil)
	s.legacyImportCount = 7
	s.legacyImportDismissed = false

	req := httptest.NewRequest("GET", "/api/legacy-import/status", nil)
	rr := httptest.NewRecorder()
	s.handleLegacyImportStatus(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Count     int  `json:"count"`
		Dismissed bool `json:"dismissed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != 7 {
		t.Fatalf("count = %d, want 7", body.Count)
	}
	if body.Dismissed {
		t.Fatalf("dismissed = true, want false")
	}
}

// TestHandleLegacyImportStatus_PostFlipsDismissed verifies POST flips
// dismissed=true for the remainder of the process and that subsequent
// GETs reflect the new value.
func TestHandleLegacyImportStatus_PostFlipsDismissed(t *testing.T) {
	s := newTestServer(t, nil)
	s.legacyImportCount = 3
	s.legacyImportDismissed = false

	postReq := httptest.NewRequest("POST", "/api/legacy-import/status", nil)
	postRR := httptest.NewRecorder()
	s.handleLegacyImportStatus(postRR, postReq)

	if postRR.Code != 200 {
		t.Fatalf("post status = %d, want 200", postRR.Code)
	}
	var postBody struct {
		Count     int  `json:"count"`
		Dismissed bool `json:"dismissed"`
	}
	if err := json.Unmarshal(postRR.Body.Bytes(), &postBody); err != nil {
		t.Fatalf("decode post: %v", err)
	}
	if postBody.Count != 3 || !postBody.Dismissed {
		t.Fatalf("post body = %+v, want count=3 dismissed=true", postBody)
	}

	// Subsequent GET must report the dismissed flag.
	getReq := httptest.NewRequest("GET", "/api/legacy-import/status", nil)
	getRR := httptest.NewRecorder()
	s.handleLegacyImportStatus(getRR, getReq)
	if getRR.Code != 200 {
		t.Fatalf("get status = %d, want 200", getRR.Code)
	}
	var getBody struct {
		Count     int  `json:"count"`
		Dismissed bool `json:"dismissed"`
	}
	if err := json.Unmarshal(getRR.Body.Bytes(), &getBody); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if !getBody.Dismissed {
		t.Fatalf("after POST, GET dismissed=false, want true")
	}
}

// TestHandleLegacyImportStatus_RejectsOtherMethods verifies methods
// other than GET/POST are rejected with 405.
func TestHandleLegacyImportStatus_RejectsOtherMethods(t *testing.T) {
	s := newTestServer(t, nil)
	req := httptest.NewRequest("DELETE", "/api/legacy-import/status", nil)
	rr := httptest.NewRecorder()
	s.handleLegacyImportStatus(rr, req)
	if rr.Code != 405 {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}
