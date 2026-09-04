package web

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func writeZip(t *testing.T, entries map[string]string) (string, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	info, _ := os.Stat(path)
	return path, info.Size()
}

func TestUnzipInto_HappyPath(t *testing.T) {
	arc, size := writeZip(t, map[string]string{
		"app/main.py":     "print('hi')",
		"app/routes/x.py": "x = 1",
		"README.md":       "# app",
	})
	dest := t.TempDir()
	n, err := unzipInto(arc, size, dest)
	if err != nil {
		t.Fatalf("unzipInto: %v", err)
	}
	if n != 3 {
		t.Fatalf("files written = %d, want 3", n)
	}
	if _, err := os.Stat(filepath.Join(dest, "app", "main.py")); err != nil {
		t.Fatalf("expected extracted file: %v", err)
	}
}

func TestUnzipInto_RejectsZipSlip(t *testing.T) {
	arc, size := writeZip(t, map[string]string{
		"../../etc/evil": "pwned",
	})
	dest := t.TempDir()
	if _, err := unzipInto(arc, size, dest); err == nil {
		t.Fatal("expected zip-slip entry to be rejected, got nil error")
	}
	// The traversal target must NOT exist outside dest.
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(dest)), "etc", "evil")); err == nil {
		t.Fatal("zip-slip wrote a file outside the destination")
	}
}

func TestCollapseSingleDir(t *testing.T) {
	dest := t.TempDir()
	inner := filepath.Join(dest, "repo-main")
	if err := os.MkdirAll(inner, 0700); err != nil {
		t.Fatal(err)
	}
	if got := collapseSingleDir(dest); got != inner {
		t.Fatalf("collapseSingleDir = %q, want %q", got, inner)
	}
	// Two entries → no collapse.
	if err := os.WriteFile(filepath.Join(dest, "loose.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := collapseSingleDir(dest); got != dest {
		t.Fatalf("collapseSingleDir with 2 entries = %q, want %q", got, dest)
	}
}
