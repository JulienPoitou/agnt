package web

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Source-upload limits. These bound both the compressed request body and the
// decompressed output so a malicious archive (zip bomb / path traversal)
// cannot exhaust disk or escape the sandbox directory.
const (
	maxSourceUpload       = 200 << 20 // 200MB compressed request body
	maxSourceUncompressed = 800 << 20 // 800MB total decompressed
	maxSourceFiles        = 20000     // max entries extracted
)

// handleUploadSource accepts a .zip archive of a codebase, extracts it safely
// under <dataDir>/sources/<slug>/, and returns the ABSOLUTE path of the
// extracted root. The caller passes that path back as ScanRequest.source_repo
// (with code_scan=review|provision) so the engine can scan uploaded code with
// no git URL and no live target — the frictionless "scan my code" entry point.
func (s *Server) handleUploadSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSourceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "failed to parse multipart form (max 200MB): "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required (a .zip of your codebase)", http.StatusBadRequest)
		return
	}
	defer file.Close()

	originalName := filepath.Base(header.Filename)
	if strings.ToLower(filepath.Ext(originalName)) != ".zip" {
		http.Error(w, "unsupported format: upload a .zip archive of the codebase", http.StatusBadRequest)
		return
	}

	// Spool the upload to a temp file so we can open it as a zip.ReaderAt.
	tmp, err := os.CreateTemp("", "xalgorix-src-*.zip")
	if err != nil {
		log.Printf("[ERROR] source upload: temp create: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	size, err := io.Copy(tmp, file)
	if err != nil {
		tmp.Close()
		log.Printf("[ERROR] source upload: spool: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	tmp.Close()

	// Destination: <dataDir>/sources/<ts>_<safeName>/
	nameOnly := strings.TrimSuffix(originalName, filepath.Ext(originalName))
	safeName := regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(nameOnly, "_")
	safeName = strings.Trim(safeName, "._-")
	if safeName == "" {
		safeName = "source"
	}
	destRoot := filepath.Join(s.dataDir, "sources", fmt.Sprintf("%d_%s", time.Now().UnixMilli(), safeName))
	if err := os.MkdirAll(destRoot, 0700); err != nil {
		log.Printf("[ERROR] source upload: mkdir: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	fileCount, err := unzipInto(tmpPath, size, destRoot)
	if err != nil {
		_ = os.RemoveAll(destRoot)
		http.Error(w, "could not extract archive: "+err.Error(), http.StatusBadRequest)
		return
	}

	// If the archive had a single top-level directory (the common
	// "repo-main/…" GitHub shape), use it as the source root so code_search
	// starts at the project root rather than a wrapper directory.
	root := collapseSingleDir(destRoot)

	log.Printf("Source uploaded: %s → %s (%d files)", header.Filename, root, fileCount)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"source_repo": root,
		"files":       fileCount,
		"name":        safeName,
	})
}

// unzipInto extracts the zip at archivePath into destRoot with zip-slip,
// file-count, and total-size protection. Symlinks are skipped. Returns the
// number of regular files written.
func unzipInto(archivePath string, archiveSize int64, destRoot string) (int, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, fmt.Errorf("not a valid zip: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// Resolve destRoot to an absolute, cleaned prefix for containment checks.
	absDest, err := filepath.Abs(destRoot)
	if err != nil {
		return 0, err
	}
	prefix := absDest + string(os.PathSeparator)

	var written int
	var totalOut int64
	for _, f := range zr.File {
		if len(zr.File) > maxSourceFiles || written > maxSourceFiles {
			return written, fmt.Errorf("archive has too many entries (max %d)", maxSourceFiles)
		}
		// Reject absolute paths and directory traversal outright (zip-slip).
		name := f.Name
		if strings.Contains(name, "\x00") {
			return written, fmt.Errorf("archive entry has an invalid name")
		}
		rel := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return written, fmt.Errorf("archive entry escapes destination: %q", name)
		}
		target := filepath.Join(absDest, rel)
		if target != absDest && !strings.HasPrefix(target, prefix) {
			return written, fmt.Errorf("archive entry escapes destination: %q", name)
		}

		info := f.FileInfo()
		if info.IsDir() {
			if err := os.MkdirAll(target, 0700); err != nil {
				return written, err
			}
			continue
		}
		// Skip symlinks and other non-regular files — never follow links out.
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return written, err
		}
		rc, err := f.Open()
		if err != nil {
			return written, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			rc.Close()
			return written, err
		}
		// Bound each copy against the remaining total-size budget to defuse
		// zip bombs (a small archive that inflates to gigabytes).
		remaining := maxSourceUncompressed - totalOut
		if remaining <= 0 {
			out.Close()
			rc.Close()
			return written, fmt.Errorf("archive exceeds max uncompressed size (%d bytes)", maxSourceUncompressed)
		}
		n, cErr := io.Copy(out, io.LimitReader(rc, remaining+1))
		out.Close()
		rc.Close()
		if cErr != nil {
			return written, cErr
		}
		if n > remaining {
			return written, fmt.Errorf("archive exceeds max uncompressed size (%d bytes)", maxSourceUncompressed)
		}
		totalOut += n
		written++
	}
	if written == 0 {
		return 0, fmt.Errorf("archive contained no files")
	}
	return written, nil
}

// collapseSingleDir returns the child directory when destRoot contains exactly
// one entry and that entry is a directory (the "repo-main/" wrapper GitHub zip
// exports produce). Otherwise it returns destRoot unchanged.
func collapseSingleDir(destRoot string) string {
	entries, err := os.ReadDir(destRoot)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return destRoot
	}
	return filepath.Join(destRoot, entries[0].Name())
}
