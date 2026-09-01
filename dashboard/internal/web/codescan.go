package web

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// resolveCodeScan interprets a code-first scan request (req.CodeScan set). The
// subject of a code scan is the source (req.SourceRepo), not a live target URL:
//
//   - "review"    → source review / SAST, NO running target (Option 1). The
//     agent audits the code and reports source-verified findings.
//   - "provision" → build & run the source locally on an allowlisted loopback
//     port, then DAST the running instance (Option 2).
//
// On success it mutates req (Targets, codeScanMode, allowLoopbackPorts) and
// returns isCodeScan=true. When req.CodeScan is empty it is a no-op returning
// (false, ""). errMsg is a client-facing 400 message when the request is
// malformed.
func (s *Server) resolveCodeScan(req *ScanRequest) (isCodeScan bool, errMsg string) {
	mode := strings.ToLower(strings.TrimSpace(req.CodeScan))
	if mode == "" {
		return false, ""
	}
	if strings.TrimSpace(req.SourceRepo) == "" {
		return false, "code_scan requires source_repo (a git URL or local path to the codebase)"
	}

	switch mode {
	case "review", "sast", "source":
		req.codeScanMode = agent.CodeScanReview
		// No live target — synthesize a stable, non-routable label so scan
		// naming/records work. The agent is told (in-prompt) not to make
		// network requests in review mode.
		req.Targets = []string{"code://" + codeTargetLabel(req.SourceRepo)}
		return true, ""

	case "provision", "run", "dast":
		port, err := pickLoopbackPort()
		if err != nil {
			return true, "could not allocate a local port for provisioning: " + err.Error()
		}
		req.codeScanMode = agent.CodeScanProvision
		req.allowLoopbackPorts = []int{port}
		// The agent builds the app from source and binds it here; the scope
		// guard allowlists exactly this loopback port for this scan.
		req.Targets = []string{fmt.Sprintf("http://127.0.0.1:%d", port)}
		return true, ""

	default:
		return false, "code_scan must be 'review' or 'provision'"
	}
}

// isBlockedTargetForScan is isBlockedTarget with a per-scan loopback allowlist.
// When allowLoopbackPorts is empty it is byte-identical to isBlockedTarget;
// with a port set, a loopback target on that exact port is permitted (used by
// provision code scans). The dashboard's own listener port is never allowed.
func (s *Server) isBlockedTargetForScan(target string, allowLoopbackPorts []int) bool {
	return scopeguard.IsLocalOrListener(scopeguard.Config{
		BindAddr:           s.cfg.BindAddr,
		Port:               s.port,
		AllowLoopbackPorts: allowLoopbackPorts,
		AllowLocalTargets:  s.cfg.AllowLocalTargets,
	}, target)
}

// pickLoopbackPort asks the OS for a free TCP port on 127.0.0.1 and returns it.
// There is an inherent TOCTOU window between closing the probe listener and the
// agent re-binding the port, but the provisioned app comes up moments later on
// the same machine, so collisions are vanishingly rare in practice.
func pickLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	if !ok {
		return 0, fmt.Errorf("unexpected listener address type %T", addr)
	}
	return addr.Port, nil
}

// codeTargetLabel derives a short, human-readable label from a repo URL or
// local path for use in the synthesized "code://<label>" review target.
func codeTargetLabel(repo string) string {
	r := strings.TrimSpace(repo)
	r = strings.TrimSuffix(r, "/")
	r = strings.TrimSuffix(r, ".git")
	// Strip any credentials in a URL (user:pass@host) before taking the base.
	if i := strings.LastIndex(r, "@"); i >= 0 && strings.Contains(r[:i], "://") {
		r = r[i+1:]
	}
	base := filepath.Base(r)
	if base == "" || base == "." || base == "/" {
		return "source"
	}
	return base
}
