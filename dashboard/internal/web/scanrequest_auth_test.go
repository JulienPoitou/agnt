package web

import (
	"encoding/json"
	"testing"
)

// The per-scan authenticated-scanning + whitebox-source fields must be
// settable from the wire via their JSON tags (FIX 3 wiring).
func TestScanRequest_TargetAuthSourceRepoDeserialize(t *testing.T) {
	body := `{
		"targets": ["https://app.example.com"],
		"target_auth": "Cookie: session=abc; Authorization: Bearer xyz",
		"source_repo": "https://github.com/example/app.git"
	}`
	var req ScanRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.TargetAuth != "Cookie: session=abc; Authorization: Bearer xyz" {
		t.Fatalf("TargetAuth = %q", req.TargetAuth)
	}
	if req.SourceRepo != "https://github.com/example/app.git" {
		t.Fatalf("SourceRepo = %q", req.SourceRepo)
	}
}

// Internal resume/instance fields are tagged json:"-" and must NOT be
// settable from a client payload (prevents broadcast spoofing / resume bypass).
func TestScanRequest_InternalFieldsNotSettableFromWire(t *testing.T) {
	body := `{
		"targets": ["https://x"],
		"InstanceID": "attacker-instance",
		"IsResume": true,
		"ResumeScanID": "spoofed"
	}`
	var req ScanRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.InstanceID != "" {
		t.Fatalf("InstanceID must not be settable from wire, got %q", req.InstanceID)
	}
	if req.IsResume {
		t.Fatal("IsResume must not be settable from wire")
	}
	if req.ResumeScanID != "" {
		t.Fatalf("ResumeScanID must not be settable from wire, got %q", req.ResumeScanID)
	}
}
