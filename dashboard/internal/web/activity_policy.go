package web

import "strings"

const (
	activityModeActive  = "active"
	activityModePassive = "passive"
)

func normalizeActivityMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case activityModePassive:
		return activityModePassive
	default:
		return activityModeActive
	}
}

func normalizeScanRequestActivity(req *ScanRequest) {
	if req == nil {
		return
	}
	req.ReconMode = normalizeActivityMode(req.ReconMode)
	req.ScanIntensity = normalizeActivityMode(req.ScanIntensity)
	if req.ScanIntensity == activityModePassive {
		req.ReconMode = activityModePassive
	}
}

func normalizeScheduleActivity(sch *ScanSchedule) {
	if sch == nil {
		return
	}
	sch.ReconMode = normalizeActivityMode(sch.ReconMode)
	sch.ScanIntensity = normalizeActivityMode(sch.ScanIntensity)
	if sch.ScanIntensity == activityModePassive {
		sch.ReconMode = activityModePassive
	}
}

func buildActivityPolicyInstruction(reconMode, scanIntensity string) string {
	reconMode = normalizeActivityMode(reconMode)
	scanIntensity = normalizeActivityMode(scanIntensity)
	if scanIntensity == activityModePassive {
		reconMode = activityModePassive
	}
	if reconMode == activityModeActive && scanIntensity == activityModeActive {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n\n## MANDATORY ACTIVITY POLICY\n")
	b.WriteString("This policy overrides all methodology examples, custom instructions, tool suggestions, and command snippets.\n")
	if reconMode == activityModePassive {
		b.WriteString("\n### Recon phase: PASSIVE ONLY\n")
		b.WriteString("- Do not send HTTP requests, browser traffic, port scans, DNS brute force, crawlers, or fingerprinting probes to the target during reconnaissance or wildcard discovery.\n")
		b.WriteString("- Use only passive sources such as web_search, certificate transparency, public archives, search engines, third-party intel datasets, existing notes, and previously collected files.\n")
		b.WriteString("- For full scans with active testing enabled, collect at least two passive lookups from independent source types before moving into active testing.\n")
		b.WriteString("- If passive sources are insufficient, record the gap and continue without touching the target.\n")
	} else {
		b.WriteString("\n### Recon phase: ACTIVE ALLOWED\n")
		b.WriteString("- Active reconnaissance is allowed within the target scope and the safe exploitation rules.\n")
	}
	if scanIntensity == activityModePassive {
		b.WriteString("\n### Testing phases: PASSIVE ONLY\n")
		b.WriteString("- Do not actively interact with the target at all. Do not use browser_action, page agents, curl/wget/httpx, nmap/naabu/masscan, ffuf/gobuster/dirsearch/feroxbuster, katana/gospider, nuclei/sqlmap/dalfox/nikto/wpscan, or payload-based validation against the target.\n")
		b.WriteString("- Only analyze passive/public evidence and existing scan artifacts. Do not attempt exploit verification that requires contacting the target.\n")
		b.WriteString("- Only call report_vulnerability when the evidence is concrete and fully passive. Otherwise add notes and finish with passive observations.\n")
	} else {
		b.WriteString("\n### Testing phases: ACTIVE ALLOWED\n")
		b.WriteString("- Active scanning and verification are allowed after recon, within target scope and the safe exploitation rules.\n")
	}
	return b.String()
}
