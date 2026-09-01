package web

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

// importLegacyDataDir copies scan records from the pre-migration data
// directory ~/xalgorix-data/ into the active s.dataDir, idempotently
// and non-destructively. Each scan ID already present under dataDir is
// skipped. On completion (or no-op early return), a sentinel file
// .legacy-imported is written so subsequent starts skip the walk.
//
// Returns the number of scans imported.
//
// Validates: Property 6 (legacy-import idempotence) of the
// findings-consistency-and-pagination spec.
func (s *Server) importLegacyDataDir() (int, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("home dir: %w", err)
	}
	legacyPath := filepath.Join(home, "xalgorix-data")
	sentinelPath := filepath.Join(s.dataDir, ".legacy-imported")

	// Early return: legacy IS the active dir — nothing to migrate.
	if filepath.Clean(legacyPath) == filepath.Clean(s.dataDir) {
		return 0, nil
	}
	// Early return: already imported once.
	if _, err := os.Stat(sentinelPath); err == nil {
		return 0, nil
	}
	// Early return: legacy dir doesn't exist or is empty.
	if info, err := os.Stat(legacyPath); err != nil || !info.IsDir() {
		// Still write the sentinel to skip future stat() calls.
		_ = os.MkdirAll(s.dataDir, 0o700)
		_ = os.WriteFile(sentinelPath, []byte("nothing-to-import\n"), 0o600)
		return 0, nil
	}

	existing := map[string]bool{}
	for _, entry := range s.findAllScans() {
		if entry.rec.ID != "" {
			existing[entry.rec.ID] = true
		}
	}

	imported := 0
	skipped := 0
	walkErr := filepath.WalkDir(legacyPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("[legacy-import] walk %s: %v", path, err)
			skipped++
			return nil // best effort; skip unreadable entries
		}
		if d.IsDir() || d.Name() != "scan.json" {
			return nil
		}
		// Read the scan.json to extract the id and target.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			log.Printf("[legacy-import] skipped %s: read error: %v", path, readErr)
			skipped++
			return nil
		}
		var rec ScanRecord
		if jerr := json.Unmarshal(data, &rec); jerr != nil {
			log.Printf("[legacy-import] skipped %s: malformed json: %v", path, jerr)
			skipped++
			return nil
		}
		if rec.ID == "" {
			log.Printf("[legacy-import] skipped %s: missing scan id", path)
			skipped++
			return nil
		}
		if existing[rec.ID] {
			// Already present in active dataDir — not an error, no log spam.
			return nil
		}

		// Determine destination directory using the same date-stamped
		// shape as createScanDirFor: dataDir/<target>/<date>/<scan-id>/
		srcDir := filepath.Dir(path)
		target := sanitizeTarget(rec.Target)
		if target == "" {
			target = "unknown"
		}
		date := ""
		if t, perr := time.Parse(time.RFC3339, rec.StartedAt); perr == nil {
			date = t.Format("2006-01-02")
		} else if t, perr := time.Parse(time.RFC3339Nano, rec.StartedAt); perr == nil {
			date = t.Format("2006-01-02")
		} else {
			date = time.Now().Format("2006-01-02")
		}
		dstDir := filepath.Join(s.dataDir, target, date, rec.ID)

		if err := copyDirRecursive(srcDir, dstDir); err != nil {
			log.Printf("[legacy-import] copy %s -> %s: %v", srcDir, dstDir, err)
			skipped++
			return nil
		}
		imported++
		existing[rec.ID] = true
		return nil
	})
	if walkErr != nil {
		return imported, walkErr
	}

	// Write sentinel even on partial success — failed copies are logged
	// and the user can retry by removing the sentinel.
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		log.Printf("[legacy-import] mkdir dataDir: %v", err)
	}
	if err := os.WriteFile(sentinelPath, []byte(fmt.Sprintf("imported=%d skipped=%d at=%s\n", imported, skipped, time.Now().Format(time.RFC3339))), 0o600); err != nil {
		log.Printf("[legacy-import] write sentinel: %v", err)
	}
	if skipped > 0 {
		log.Printf("[legacy-import] imported %d scans, skipped %d (see log lines above) from %s", imported, skipped, legacyPath)
	} else {
		log.Printf("[legacy-import] imported %d scans from %s", imported, legacyPath)
	}
	return imported, nil
}

// copyDirRecursive copies src directory tree to dst, creating dst if
// needed. Existing files at dst are overwritten. Used by
// importLegacyDataDir for non-destructive copy semantics (legacy dir
// preserved untouched).
func copyDirRecursive(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}
